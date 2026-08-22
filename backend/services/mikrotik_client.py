"""
Mikrotik device client — tries multiple access methods in order:

  1. REST API (RouterOS v7+, requires www service)
  2. Binary API (port 8728/8729, requires api service — RouterOS v3+)
  3. SNMP v2c (port 161, read-only, requires snmp + community)

Each high-level method tries REST first, falls back to API, then SNMP.
If all three fail (or aren't configured), raises with the last error.
"""
import asyncio
import aiohttp
import re
import ssl
import time
from typing import Any, Optional
import librouteros
from services.snmp_client import SnmpClient

# WireGuard peer considered "up" if it handshook within this many seconds —
# RouterOS/community convention: persistent-keepalive (when configured)
# re-handshakes on roughly this cadence, so a peer that's gone quiet this
# long is treated as dead rather than merely idle.
WG_HANDSHAKE_STALE_SEC = 180


def _parse_duration_to_sec(value) -> Optional[int]:
    """RouterOS's last-handshake sometimes comes back as a plain integer of
    seconds, sometimes as a human duration string like '2m30s' or '1h2m3s'
    (CLI-style) depending on API path/version — handle both rather than
    assuming one. Returns None for missing/never-handshaked/unparseable."""
    if value is None or value == "" or value == "never":
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        if value.isdigit():
            return int(value)
        m = re.match(r'^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?$', value.strip())
        if m and any(m.groups()):
            d, h, mi, s, _ms = (int(g) if g else 0 for g in m.groups())
            return d * 86400 + h * 3600 + mi * 60 + s
    return None


def _wireguard_peer_status(peer: dict) -> str:
    if str(peer.get("disabled", "false")).lower() in ("true", "yes"):
        return "down"
    age = _parse_duration_to_sec(peer.get("last-handshake"))
    if age is None:
        return "down"
    return "up" if age <= WG_HANDSHAKE_STALE_SEC else "down"


# Remembers, per (device IP, REST path), whether REST is known to fail on
# that device — so repeated polling doesn't keep paying for a doomed REST
# auth roundtrip (each one is a login+logout in the device's own system
# log) before falling back to the binary API every single time. Keyed by
# IP rather than held on the client instance since a fresh MikrotikClient
# is constructed for nearly every call site. Re-probed after
# _REST_BROKEN_TTL in case the underlying cause (cert, disabled www
# service, RouterOS upgrade) gets fixed.
_rest_broken: dict = {}
_REST_BROKEN_TTL = 3600


def _rest_is_broken(key: tuple) -> bool:
    ts = _rest_broken.get(key)
    return ts is not None and (time.time() - ts) < _REST_BROKEN_TTL


def _mark_rest_broken(key: tuple) -> None:
    _rest_broken[key] = time.time()


def _mark_rest_ok(key: tuple) -> None:
    _rest_broken.pop(key, None)


class MikrotikClient:
    def __init__(self, ip: str, username: str, password: str,
                 api_port: int = 8728, web_port: int = 80,
                 snmp_community: Optional[str] = None, snmp_port: int = 161):
        self.ip = ip
        self.username = username
        self.password = password
        self.api_port = api_port
        self.web_port = web_port
        self.snmp_community = snmp_community
        self.snmp_port = snmp_port
        self._rest_base = f"http://{ip}:{web_port}/rest"
        self._snmp = SnmpClient(ip, snmp_community, port=snmp_port) if snmp_community else None

    # ── REST API (RouterOS v7) ────────────────────────────────────────────────

    async def _rest_request(self, method: str, path: str, data: Optional[dict] = None) -> Any:
        url = f"{self._rest_base}/{path.lstrip('/')}"
        auth = aiohttp.BasicAuth(self.username, self.password)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, json=data, auth=auth,
                                       ssl=ssl_ctx, timeout=timeout) as resp:
                resp.raise_for_status()
                if resp.content_length == 0:
                    return {}
                return await resp.json()

    async def rest_get(self, path: str) -> Any:
        return await self._rest_request("GET", path)

    async def rest_patch(self, path: str, data: dict) -> Any:
        return await self._rest_request("PATCH", path, data)

    async def rest_put(self, path: str, data: dict) -> Any:
        return await self._rest_request("PUT", path, data)

    async def rest_delete(self, path: str) -> Any:
        return await self._rest_request("DELETE", path)

    # ── Binary API protocol (RouterOS v3+, port 8728) ─────────────────────────

    async def api_command(self, command: str) -> list:
        """Execute /command/print via binary API on port 8728. Runs in thread
        because librouteros is sync. Used as fallback when REST is not available."""
        loop = asyncio.get_event_loop()

        def _run():
            api = librouteros.connect(
                self.ip, username=self.username, password=self.password,
                port=self.api_port, timeout=8,
            )
            try:
                # librouteros expects paths like "/system/resource/print"
                cmd = command if command.startswith("/") else f"/{command}"
                if not cmd.endswith("/print"):
                    cmd = f"{cmd}/print"
                return list(api(cmd))
            finally:
                api.close()

        return await loop.run_in_executor(None, _run)

    # ── Fallback orchestrator ─────────────────────────────────────────────────

    async def _rest_or_api(self, rest_path: str, api_path: str, single_object: bool = False):
        """Try REST, falling back to binary API — but skip the REST attempt
        entirely once it's known to be broken for this device+path (see
        _rest_broken above), instead of re-paying for a doomed auth
        roundtrip (and the login/logout log line it costs on the device)
        on every single poll."""
        key = (self.ip, rest_path)
        if not _rest_is_broken(key):
            try:
                result = await self.rest_get(rest_path)
                _mark_rest_ok(key)
                return result
            except Exception:
                _mark_rest_broken(key)

        result = await self.api_command(api_path)
        if single_object and isinstance(result, list):
            return result[0] if result else {}
        return result

    async def _try_methods(self, rest_path: str, api_path: str,
                           snmp_fn=None, single_object: bool = False):
        """Try REST → API → SNMP in order. Returns first successful result."""
        errors = []
        key = (self.ip, rest_path)

        # 1. REST (skipped if known broken for this device+path)
        if not _rest_is_broken(key):
            try:
                result = await self.rest_get(rest_path)
                _mark_rest_ok(key)
                return result
            except Exception as e:
                _mark_rest_broken(key)
                errors.append(f"REST: {type(e).__name__}: {e}")

        # 2. Binary API
        try:
            result = await self.api_command(api_path)
            if single_object and isinstance(result, list):
                return result[0] if result else {}
            return result
        except Exception as e:
            errors.append(f"API: {type(e).__name__}: {e}")

        # 3. SNMP (only if community configured and helper given)
        if self._snmp and snmp_fn:
            try:
                return await snmp_fn()
            except Exception as e:
                errors.append(f"SNMP: {type(e).__name__}: {e}")

        # All failed — raise summarized error
        raise ConnectionError("Wszystkie metody dostępu zawiodły. " + " | ".join(errors))

    # ── High-level helpers (with fallback) ────────────────────────────────────

    async def get_identity(self) -> dict:
        snmp_fn = self._snmp.get_identity if self._snmp else None
        return await self._try_methods(
            "system/identity", "/system/identity",
            snmp_fn=snmp_fn, single_object=True,
        )

    async def get_resource(self) -> dict:
        snmp_fn = self._snmp.get_resource if self._snmp else None
        return await self._try_methods(
            "system/resource", "/system/resource",
            snmp_fn=snmp_fn, single_object=True,
        )

    async def get_routerboard(self) -> dict:
        try:
            return await self._rest_or_api("system/routerboard", "/system/routerboard", single_object=True)
        except Exception:
            return {}

    async def get_package_update_status(self) -> dict:
        """Trigger a live 'check for updates' and read the result — this
        asks the DEVICE ITSELF (aware of its own architecture and update
        channel), not a single global "latest" version guessed from a
        static file, so it's the only way to know accurately whether THIS
        specific model actually has a newer RouterOS available to it (some
        older/smaller boards stop receiving new major versions).

        RouterOS runs the check asynchronously — /system/package/update/
        check-for-updates returns immediately while the device contacts
        Mikrotik's servers in the background, so reading the result right
        away risks racing an unfinished check (community scripts commonly
        insert a ~3s delay for exactly this reason). Returns {} on any
        failure — caller treats that as "unknown", not "up to date"."""
        try:
            try:
                await self.rest_get("system/package/update/check-for-updates")
            except Exception:
                await self.api_command("/system/package/update/check-for-updates")
        except Exception:
            return {}

        await asyncio.sleep(3)

        try:
            info = await self._rest_or_api(
                "system/package/update", "/system/package/update", single_object=True)
        except Exception:
            return {}
        if not info:
            return {}
        return {
            "installed": info.get("installed-version"),
            "latest": info.get("latest-version"),
            "status": info.get("status"),
            "channel": info.get("channel", "stable"),
        }

    async def get_interfaces(self) -> list:
        snmp_fn = self._snmp.get_interfaces if self._snmp else None
        return await self._try_methods("interface", "/interface", snmp_fn=snmp_fn)

    async def get_ip_addresses(self) -> list:
        snmp_fn = self._snmp.get_ip_addresses if self._snmp else None
        return await self._try_methods("ip/address", "/ip/address", snmp_fn=snmp_fn)

    async def get_routes(self) -> list:
        return await self._try_methods("ip/route", "/ip/route")

    async def get_neighbors(self) -> list:
        try:
            return await self._rest_or_api("ip/neighbor", "/ip/neighbor")
        except Exception:
            return []

    async def get_logs(self, limit: int = 100) -> list:
        """System log — REST or API only (not exposed via SNMP)."""
        return await self._rest_or_api("log", "/log")

    async def get_firewall_rules(self) -> dict:
        async def _get_one(rest_path, api_path):
            try:
                return await self._rest_or_api(rest_path, api_path)
            except Exception:
                return []
        return {
            "filter": await _get_one("ip/firewall/filter", "/ip/firewall/filter"),
            "nat": await _get_one("ip/firewall/nat", "/ip/firewall/nat"),
        }

    async def get_wireless(self) -> list:
        try:
            return await self._rest_or_api("interface/wireless", "/interface/wireless")
        except Exception:
            return []

    async def get_dhcp_leases(self) -> list:
        try:
            return await self._rest_or_api("ip/dhcp-server/lease", "/ip/dhcp-server/lease")
        except Exception:
            return []

    async def get_wireguard_status(self) -> dict:
        """WireGuard interfaces + per-peer status. See _wireguard_peer_status
        for the up/down rule (last-handshake recency, disabled flag).
        Returns an "error" key (None if both queries succeeded) — a query
        failure (unsupported RouterOS version, REST/API path unreachable,
        etc.) must be visible, not indistinguishable from "genuinely no
        WireGuard configured" the way silently-returned empty lists were."""
        errors = []
        try:
            interfaces = await self._rest_or_api("interface/wireguard", "/interface/wireguard")
        except Exception as e:
            interfaces = []
            errors.append(f"interfaces: {type(e).__name__}: {e}")
        try:
            peers = await self._rest_or_api("interface/wireguard/peers", "/interface/wireguard/peers")
        except Exception as e:
            peers = []
            errors.append(f"peers: {type(e).__name__}: {e}")
        if isinstance(peers, list):
            for p in peers:
                if isinstance(p, dict):
                    p["status"] = _wireguard_peer_status(p)
        return {"interfaces": interfaces, "peers": peers, "error": "; ".join(errors) or None}

    async def get_ipsec_status(self) -> dict:
        """IPsec active peers (phase 1) with a computed "up"/"down" status
        — "up" only when RouterOS itself reports state=="established".
        Returns {"peers": [...], "error": str|None} — same reasoning as
        get_wireguard_status() above, a query failure must be visible."""
        try:
            peers = await self._rest_or_api("ip/ipsec/active-peers", "/ip/ipsec/active-peers")
        except Exception as e:
            return {"peers": [], "error": f"{type(e).__name__}: {e}"}
        if isinstance(peers, list):
            for p in peers:
                if isinstance(p, dict):
                    p["status"] = "up" if str(p.get("state", "")).lower() == "established" else "down"
        return {"peers": peers, "error": None}

    async def get_vpn_tunnels(self) -> dict:
        result = {}
        for rest_path, api_path, key in [
            ("interface/eoip", "/interface/eoip", "eoip"),
            ("interface/vxlan", "/interface/vxlan", "vxlan"),
            ("interface/gre", "/interface/gre", "gre"),
            ("interface/ipip", "/interface/ipip", "ipip"),
        ]:
            try:
                result[key] = await self._rest_or_api(rest_path, api_path)
            except Exception:
                result[key] = []
        try:
            result["wireguard"] = await self.get_wireguard_status()
        except Exception as e:
            result["wireguard"] = {"interfaces": [], "peers": [], "error": f"{type(e).__name__}: {e}"}
        try:
            result["ipsec"] = await self.get_ipsec_status()
        except Exception as e:
            result["ipsec"] = {"peers": [], "error": f"{type(e).__name__}: {e}"}
        return result

    async def set_identity(self, name: str) -> None:
        """Write op — only REST or API. SNMP would need RW community + sysName.0 SET."""
        try:
            await self.rest_patch("system/identity", {"name": name})
        except Exception:
            loop = asyncio.get_event_loop()
            def _run():
                api = librouteros.connect(self.ip, username=self.username,
                                          password=self.password,
                                          port=self.api_port, timeout=8)
                try:
                    api("/system/identity/set", **{"name": name})
                finally:
                    api.close()
            await loop.run_in_executor(None, _run)
