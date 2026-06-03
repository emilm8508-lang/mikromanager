"""
Cisco Small Business switch client (SG200/SG250/SG300/SG350 series).

These switches do NOT have a clean REST API like enterprise Cisco gear.
We rely on SNMP v2c with standard MIB-2 (IF-MIB, IP-MIB, BRIDGE-MIB,
LLDP-MIB) plus parsing sysDescr for model/firmware. Optionally SSH for
log/config retrieval (not implemented in this minimal version).

Auth model: same Credential rows as Mikrotik — username/password used
for SSH (future), snmp_community used for SNMP polling.
"""
import re
from typing import Optional
from services.snmp_client import (
    SnmpClient,
    OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME, OID_SYS_OBJECT_ID,
    OID_IF_DESCR, OID_IF_TYPE, OID_IF_OPER_STATUS, OID_IF_PHYS_ADDRESS, OID_IF_MTU,
    OID_IP_AD_ENT_ADDR, OID_IP_AD_ENT_NETMASK,
    IF_TYPE_NAMES, OPER_STATUS, _decode,
)

# Cisco enterprise OID space
CISCO_ENTERPRISE_OID = "1.3.6.1.4.1.9"
CISCO_SB_PREFIX = "1.3.6.1.4.1.9.6.1"   # Cisco Small Business family

# ENTITY-MIB OIDs — universal for hardware enumeration
OID_ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
OID_ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
OID_ENT_PHYSICAL_SOFTWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.10"
OID_ENT_PHYSICAL_FIRMWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.9"
OID_ENT_PHYSICAL_SERIAL_NUM = "1.3.6.1.2.1.47.1.1.1.1.11"
OID_ENT_PHYSICAL_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"

# LLDP-MIB — neighbors discovered via LLDP
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_MGMT_ADDR = "1.0.8802.1.1.2.1.4.2.1.5"


def parse_cisco_sb_model(sys_descr: str) -> dict:
    """Extract model + firmware from sysDescr like:
       'SG350-10 10-Port Gigabit Managed Switch'
       'Cisco SG250-08 (PID:SG250-08) Software, Version 2.5.7.85'
    """
    out = {}
    # Model — SG followed by digits and optional suffix
    m = re.search(r"\bSG\d{3}-\d+\w*", sys_descr)
    if m:
        out["model"] = m.group(0)
    # Firmware version: Version X.Y.Z.W
    m = re.search(r"Version\s+([\d.]+)", sys_descr, re.IGNORECASE)
    if m:
        out["fw_version"] = m.group(1)
    return out


class CiscoClient:
    """Cisco SB client. Same shape as MikrotikClient so the same API endpoints
    can dispatch to either based on device.vendor."""

    def __init__(self, ip: str, username: str = "", password: str = "",
                 snmp_community: Optional[str] = None, snmp_port: int = 161,
                 web_port: int = 80, ssh_port: int = 22, **kwargs):
        self.ip = ip
        self.username = username
        self.password = password
        self.snmp_port = snmp_port
        self.web_port = web_port
        self.ssh_port = ssh_port
        self._snmp = SnmpClient(ip, snmp_community, port=snmp_port) if snmp_community else None

    def _require_snmp(self) -> SnmpClient:
        if not self._snmp:
            raise RuntimeError("SNMP community not configured for this Cisco device")
        return self._snmp

    # ── Identity / resource ─────────────────────────────────────────────────

    async def get_identity(self) -> dict:
        s = self._require_snmp()
        try:
            name = _decode(await s._get(OID_SYS_NAME))
            return {"name": name}
        except Exception as e:
            raise RuntimeError(f"SNMP get_identity failed: {e}")

    async def get_resource(self) -> dict:
        s = self._require_snmp()
        out = {}
        try:
            sys_descr = _decode(await s._get(OID_SYS_DESCR))
            out["sys-descr"] = sys_descr
            parsed = parse_cisco_sb_model(sys_descr)
            if parsed.get("model"):
                out["board-name"] = parsed["model"]
            if parsed.get("fw_version"):
                out["version"] = parsed["fw_version"]
        except Exception:
            pass
        try:
            out["uptime"] = _decode(await s._get(OID_SYS_UPTIME))
        except Exception:
            pass
        # Try ENTITY-MIB for serial / model / firmware
        try:
            walk = await s._walk(OID_ENT_PHYSICAL_SERIAL_NUM)
            for _, v in walk:
                serial = _decode(v)
                if serial:
                    out.setdefault("serial-number", serial)
                    break
        except Exception:
            pass
        try:
            walk = await s._walk(OID_ENT_PHYSICAL_FIRMWARE_REV)
            for _, v in walk:
                fw = _decode(v)
                if fw:
                    out.setdefault("firmware", fw)
                    break
        except Exception:
            pass
        try:
            walk = await s._walk(OID_ENT_PHYSICAL_MODEL_NAME)
            for _, v in walk:
                model = _decode(v)
                if model and not out.get("board-name"):
                    out["board-name"] = model
                    break
        except Exception:
            pass
        return out

    async def get_routerboard(self) -> dict:
        # Not applicable for Cisco — return an empty dict so callers don't break.
        return {}

    # ── Interfaces ──────────────────────────────────────────────────────────

    async def get_interfaces(self) -> list:
        s = self._require_snmp()
        try:
            descr = {oid.rsplit(".", 1)[-1]: _decode(v)
                     for oid, v in await s._walk(OID_IF_DESCR)}
        except Exception:
            return []
        if not descr:
            return []

        try:
            types = {oid.rsplit(".", 1)[-1]: int(v) if v else 0
                     for oid, v in await s._walk(OID_IF_TYPE)}
        except Exception:
            types = {}
        try:
            oper = {oid.rsplit(".", 1)[-1]: int(v) if v else 4
                    for oid, v in await s._walk(OID_IF_OPER_STATUS)}
        except Exception:
            oper = {}
        try:
            mac = {}
            for oid, v in await s._walk(OID_IF_PHYS_ADDRESS):
                idx = oid.rsplit(".", 1)[-1]
                if isinstance(v, bytes):
                    mac[idx] = ":".join(f"{b:02x}" for b in v)
                else:
                    mac[idx] = _decode(v)
        except Exception:
            mac = {}
        try:
            mtu = {oid.rsplit(".", 1)[-1]: _decode(v) for oid, v in await s._walk(OID_IF_MTU)}
        except Exception:
            mtu = {}

        result = []
        for idx in sorted(descr.keys(), key=lambda x: int(x) if x.isdigit() else x):
            result.append({
                "name": descr.get(idx, ""),
                "type": IF_TYPE_NAMES.get(types.get(idx, 0), str(types.get(idx, ""))),
                "running": OPER_STATUS.get(oper.get(idx, 4), "unknown") == "up",
                "mac-address": mac.get(idx, ""),
                "mtu": mtu.get(idx, ""),
            })
        return result

    async def get_ip_addresses(self) -> list:
        s = self._require_snmp()
        try:
            addrs = await s._walk(OID_IP_AD_ENT_ADDR)
            masks_walk = await s._walk(OID_IP_AD_ENT_NETMASK)
            masks = {}
            for oid, v in masks_walk:
                # netmask OID suffix is the IP itself
                ip_key = oid.split(OID_IP_AD_ENT_NETMASK + ".")[-1]
                masks[ip_key] = _decode(v)
        except Exception:
            return []
        result = []
        for _, val in addrs:
            ip = _decode(val)
            mask = masks.get(ip, "")
            result.append({"address": f"{ip}/{mask}" if mask else ip, "interface": ""})
        return result

    async def get_routes(self) -> list:
        # Could implement via ipCidrRouteTable but rarely useful on L2 switch.
        return []

    async def get_neighbors(self) -> list:
        """Return list of LLDP neighbors discovered by this device."""
        s = self._require_snmp()
        try:
            names_walk = await s._walk(OID_LLDP_REM_SYS_NAME)
            ports_walk = await s._walk(OID_LLDP_REM_PORT_ID)
            ports_desc_walk = await s._walk(OID_LLDP_REM_PORT_DESC)
        except Exception:
            return []

        # OID suffix encodes lldp index — we use it as identifier key
        names = {oid: _decode(v) for oid, v in names_walk}
        ports = {oid: _decode(v) for oid, v in ports_walk}
        ports_desc = {oid: _decode(v) for oid, v in ports_desc_walk}

        result = []
        for oid, name in names.items():
            # Find port for this neighbor index
            port_id = None
            for poid, pval in ports.items():
                if poid.endswith(oid.split(OID_LLDP_REM_SYS_NAME + ".")[-1]):
                    port_id = pval
                    break
            port_desc = None
            for poid, pval in ports_desc.items():
                if poid.endswith(oid.split(OID_LLDP_REM_SYS_NAME + ".")[-1]):
                    port_desc = pval
                    break
            result.append({
                "identity": name,
                "interface-name": port_desc or port_id or "",
            })
        return result

    # ── Stubs for features Cisco SB switches don't support ─────────────────

    async def get_logs(self, limit: int = 100) -> list:
        # Would need SSH to retrieve; not implemented in v1.
        return []

    async def get_firewall_rules(self) -> dict:
        # Cisco SB has ACLs, not firewall — return empty shape compatible with UI.
        return {"filter": [], "nat": []}

    async def get_wireless(self) -> list:
        return []

    async def get_dhcp_leases(self) -> list:
        return []

    async def get_vpn_tunnels(self) -> dict:
        return {"eoip": [], "vxlan": [], "gre": [], "ipip": []}

    async def set_identity(self, name: str) -> None:
        raise NotImplementedError("Renaming Cisco SB via SNMP requires RW community + SET op")
