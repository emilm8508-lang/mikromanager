"""
SNMP v2c read-only client for Mikrotik devices.

Used as a fallback when REST API (v7+) and binary API (port 8728) are
unavailable — typically RouterOS v6 with disabled API/www services.

Pure-Python (puresnmp) — no C extensions, works on Python 3.14.
"""
from typing import Optional
import asyncio
from puresnmp import Client, V2C, PyWrapper

# ── Standard MIB-2 OIDs ──────────────────────────────────────────────────────
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# Interfaces table (IF-MIB)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_MTU = "1.3.6.1.2.1.2.2.1.4"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"

# IP address table
OID_IP_AD_ENT_ADDR = "1.3.6.1.2.1.4.20.1.1"
OID_IP_AD_ENT_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
OID_IP_AD_ENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"

# Mikrotik-specific (enterprise 14988)
OID_MTXR_LIC_SOFTWARE_ID = "1.3.6.1.4.1.14988.1.1.4.1.0"
OID_MTXR_LIC_UPGR_LEVEL = "1.3.6.1.4.1.14988.1.1.4.3.0"
OID_MTXR_LIC_VERSION = "1.3.6.1.4.1.14988.1.1.4.4.0"
OID_MTXR_SYSTEM_BOARD_NAME = "1.3.6.1.4.1.14988.1.1.7.8.0"
OID_MTXR_SYSTEM_SERIAL = "1.3.6.1.4.1.14988.1.1.7.3.0"
OID_MTXR_SYSTEM_FW_VERSION = "1.3.6.1.4.1.14988.1.1.7.4.0"
OID_MTXR_CPU_LOAD = "1.3.6.1.4.1.14988.1.1.3.14.0"

IF_TYPE_NAMES = {
    1: "other", 6: "ethernet", 24: "loopback", 53: "propVirtual",
    71: "wireless", 131: "tunnel", 135: "l2vlan", 150: "mplsTunnel",
    161: "ieee8023adLag", 209: "bridge",
}
OPER_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


def _decode(val) -> str:
    """Best-effort decode of puresnmp return values."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return val.hex()
    return str(val)


class SnmpClient:
    def __init__(self, ip: str, community: str, port: int = 161, timeout: float = 3.0):
        self.ip = ip
        self.community = community
        self.port = port
        self.timeout = timeout
        self._client = PyWrapper(Client(ip, V2C(community), port=port))

    async def _get(self, oid: str):
        return await asyncio.wait_for(self._client.get(oid), timeout=self.timeout)

    async def _walk(self, oid: str) -> list:
        """Walk an OID subtree and return list of (oid, value) tuples."""
        results = []
        async def _do():
            async for binding in self._client.walk(oid):
                results.append((str(binding.oid), binding.value))
        await asyncio.wait_for(_do(), timeout=self.timeout * 3)
        return results

    async def probe(self) -> bool:
        """Quick check whether device responds to SNMP with this community."""
        try:
            await self._get(OID_SYS_NAME)
            return True
        except Exception:
            return False

    async def get_identity(self) -> dict:
        name = _decode(await self._get(OID_SYS_NAME))
        return {"name": name}

    async def get_resource(self) -> dict:
        """Return dict mimicking REST /system/resource shape. Tries multiple OIDs
        and parses sysDescr as fallback — useful for older RouterOS / restricted
        SNMP views that may not expose enterprise OIDs."""
        out = {}
        # Get sysDescr first — used as parsing fallback
        sys_descr = ""
        try:
            sys_descr = _decode(await self._get(OID_SYS_DESCR))
            out["sys-descr"] = sys_descr
        except Exception:
            pass
        try:
            out["uptime"] = _decode(await self._get(OID_SYS_UPTIME))
        except Exception:
            pass
        # board-name — try enterprise OID, then parse sysDescr
        try:
            board = _decode(await self._get(OID_MTXR_SYSTEM_BOARD_NAME))
            if board:
                out["board-name"] = board
        except Exception:
            pass
        # sysDescr is standard MIB-2 (1.3.6.1.2.1.1.1.0) — EVERY SNMP-capable
        # device answers it, not just Mikrotik ones, so anything parsed out
        # of it (unlike the enterprise-14988 OIDs above, which simply don't
        # exist on non-Mikrotik hardware and fail cleanly) must be gated on
        # sysDescr actually claiming to be RouterOS/Mikrotik. Without this,
        # a printer/switch answering basic SNMP (common when a shared
        # community string is configured broadly) had its own model number
        # or firmware string misread as a RouterOS version by the old blind
        # "any digit.digit substring" regex below — which then fed
        # Device.ros_version and silently passed as "this is RouterOS v7" in
        # every feature that trusts that field (tunnel monitoring, firmware
        # update checks), for a device that was never RouterOS at all.
        looks_like_routeros = any(tok in sys_descr.lower() for tok in ("routeros", "mikrotik"))
        if not out.get("board-name") and sys_descr and looks_like_routeros:
            # sysDescr is often "RouterOS RB951G-2HnD" — extract board name
            parts = sys_descr.split()
            for p in parts:
                if p.upper() not in ("ROUTEROS", "MIKROTIK") and any(c.isdigit() for c in p):
                    out["board-name"] = p
                    break
        # version — try enterprise OID, then parse sysDescr / firmware
        try:
            ver = _decode(await self._get(OID_MTXR_LIC_VERSION))
            if ver:
                out["version"] = ver
        except Exception:
            pass
        if not out.get("version"):
            # Try also fw-version which on some devices = ROS version
            try:
                fw = _decode(await self._get(OID_MTXR_SYSTEM_FW_VERSION))
                if fw and any(c.isdigit() for c in fw) and "." in fw:
                    out["version"] = fw
            except Exception:
                pass
        if not out.get("version") and sys_descr and looks_like_routeros:
            # RouterOS sysDescr sometimes contains version: "RouterOS v6.49.6"
            import re
            m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", sys_descr)
            if m:
                out["version"] = m.group(1)
        try:
            out["serial-number"] = _decode(await self._get(OID_MTXR_SYSTEM_SERIAL))
        except Exception:
            pass
        try:
            out["firmware"] = _decode(await self._get(OID_MTXR_SYSTEM_FW_VERSION))
        except Exception:
            pass
        try:
            out["cpu-load"] = _decode(await self._get(OID_MTXR_CPU_LOAD))
        except Exception:
            pass
        return out

    async def get_interfaces(self) -> list:
        """Build interface list from IF-MIB walks."""
        descr = {oid.rsplit(".", 1)[-1]: _decode(v) for oid, v in await self._walk(OID_IF_DESCR)}
        if not descr:
            return []
        ifindexes = list(descr.keys())

        def safe_walk_map(oid_base, ifindexes, default=""):
            return {}

        try:
            types = {oid.rsplit(".", 1)[-1]: int(v) if v is not None else 0
                     for oid, v in await self._walk(OID_IF_TYPE)}
        except Exception:
            types = {}
        try:
            oper = {oid.rsplit(".", 1)[-1]: int(v) if v is not None else 4
                    for oid, v in await self._walk(OID_IF_OPER_STATUS)}
        except Exception:
            oper = {}
        try:
            mac = {oid.rsplit(".", 1)[-1]: (_decode(v) if isinstance(v, str) else
                                             (v.hex(":") if isinstance(v, bytes) else ""))
                   for oid, v in await self._walk(OID_IF_PHYS_ADDRESS)}
        except Exception:
            mac = {}
        try:
            mtu = {oid.rsplit(".", 1)[-1]: _decode(v) for oid, v in await self._walk(OID_IF_MTU)}
        except Exception:
            mtu = {}

        result = []
        for idx in ifindexes:
            result.append({
                "name": descr.get(idx, ""),
                "type": IF_TYPE_NAMES.get(types.get(idx, 0), str(types.get(idx, ""))),
                "running": OPER_STATUS.get(oper.get(idx, 4), "unknown") == "up",
                "mac-address": mac.get(idx, ""),
                "mtu": mtu.get(idx, ""),
            })
        return result

    async def get_ip_addresses(self) -> list:
        """Build IP address list from ipAddrTable."""
        try:
            addrs = await self._walk(OID_IP_AD_ENT_ADDR)
            masks = {oid.split(OID_IP_AD_ENT_NETMASK + ".")[-1]: _decode(v)
                     for oid, v in await self._walk(OID_IP_AD_ENT_NETMASK)}
        except Exception:
            return []

        result = []
        for oid, val in addrs:
            ip = _decode(val)
            mask = masks.get(ip, "")
            result.append({"address": f"{ip}/{mask}" if mask else ip, "interface": ""})
        return result
