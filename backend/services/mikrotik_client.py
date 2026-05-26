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
import ssl
from typing import Any, Optional
import librouteros
from services.snmp_client import SnmpClient


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

    async def _try_methods(self, rest_path: str, api_path: str,
                           snmp_fn=None, single_object: bool = False):
        """Try REST → API → SNMP in order. Returns first successful result."""
        errors = []

        # 1. REST
        try:
            result = await self.rest_get(rest_path)
            return result
        except Exception as e:
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
            return await self.rest_get("system/routerboard")
        except Exception:
            pass
        try:
            res = await self.api_command("/system/routerboard")
            return res[0] if res else {}
        except Exception:
            return {}

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
            return await self.rest_get("ip/neighbor")
        except Exception:
            pass
        try:
            return await self.api_command("/ip/neighbor")
        except Exception:
            return []

    async def get_logs(self, limit: int = 100) -> list:
        """System log — REST or API only (not exposed via SNMP)."""
        try:
            return await self.rest_get("log")
        except Exception:
            pass
        return await self.api_command("/log")

    async def get_firewall_rules(self) -> dict:
        async def _get_one(rest_path, api_path):
            try:
                return await self.rest_get(rest_path)
            except Exception:
                try:
                    return await self.api_command(api_path)
                except Exception:
                    return []
        return {
            "filter": await _get_one("ip/firewall/filter", "/ip/firewall/filter"),
            "nat": await _get_one("ip/firewall/nat", "/ip/firewall/nat"),
        }

    async def get_wireless(self) -> list:
        try:
            return await self.rest_get("interface/wireless")
        except Exception:
            pass
        try:
            return await self.api_command("/interface/wireless")
        except Exception:
            return []

    async def get_dhcp_leases(self) -> list:
        try:
            return await self.rest_get("ip/dhcp-server/lease")
        except Exception:
            pass
        try:
            return await self.api_command("/ip/dhcp-server/lease")
        except Exception:
            return []

    async def get_vpn_tunnels(self) -> dict:
        result = {}
        for rest_path, api_path, key in [
            ("interface/eoip", "/interface/eoip", "eoip"),
            ("interface/vxlan", "/interface/vxlan", "vxlan"),
            ("interface/gre", "/interface/gre", "gre"),
            ("interface/ipip", "/interface/ipip", "ipip"),
        ]:
            try:
                result[key] = await self.rest_get(rest_path)
            except Exception:
                try:
                    result[key] = await self.api_command(api_path)
                except Exception:
                    result[key] = []
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
