"""
The role of each router / switch interface and which addresses belong to the routers themselves.

  wan     - in the router's own "WAN" interface list, or carrying a public address: the way to the internet
  uplink  - on a device without a WAN list (a switch, an AP), the interface its default route leaves through: its way to the router.
            Not a WAN - seen in production: ether1 on CRS switches (R2-S1, R2-S2, R1-S3) read as a WAN link
  access  - everything else (where the users and servers are)
  tunnel  - EoIP / GRE / IPIP / WireGuard / L2TP / SSTP / OVPN / PPTP between sites (3.67): neither a WAN nor the LAN

3.67 - which device is at the edge at all (refine()): a WAN interface list alone is not proof - RouterOS's default configuration puts ether1
in it on every hAP / wAP / CRS set up from defconf, so access points and switches (mcprojekt AP3, sanmed R1-S3, R1-S4, R4, mcprojekt R2-S1,
R2-S2) showed their way to the router as a WAN link. A device is at the edge when it has a public address, or when its default route goes
to something that is not one of the client's managed devices (the ISP's modem); a device whose default route goes to another managed
device's address is behind it - its "WAN" interfaces are uplinks.

The addresses come from services/edge_discovery.py's scan (data/router_addresses.json). With them the inventory puts a router's own
address on that router instead of listing it as a host (seen: 192.168.0.2, the WAN address of mcprojekt's MC-R1, as a host of its own),
and NetFlow knows which addresses are a router's WAN (stage 5). Pure helpers + one file reader; no network.
"""
import ipaddress
import json
import os
import time
from typing import Dict, Iterable, List, Optional

ROLES = ("wan", "uplink", "access", "tunnel")
_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "router_addresses.json")
_cache = {"at": 0.0, "mtime": 0.0, "rows": []}


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_private and not a.is_reserved and not a.is_multicast and not ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")


def default_route_iface(routes: Iterable[dict]) -> Optional[str]:
    """The interface an active default route leaves through: "immediate-gw" (7.x "192.168.2.1%bridge") or a gateway naming an interface."""
    for r in routes:
        if not isinstance(r, dict):
            continue
        if str(r.get("dst-address") or "") not in ("0.0.0.0/0", "::/0"):
            continue
        if str(r.get("active", "true")).lower() not in ("true", "yes") or str(r.get("disabled", "false")).lower() in ("true", "yes"):
            continue
        for key in ("immediate-gw", "gateway-status", "gateway"):
            v = str(r.get(key) or "")
            if "%" in v:
                return v.split("%", 1)[1].split()[0].strip() or None
            if v and not any(c.isdigit() for c in v.split(".")[0][:1]) and ":" not in v:
                return v.split()[0]                                    # gateway given as an interface name
    return None


def default_route_gateway(routes: Iterable[dict]) -> Optional[str]:
    """The IPv4 address an active default route goes to ("gateway" 192.168.2.1, or "immediate-gw" 192.168.2.1%bridge); None if it names only
    an interface (pppoe-out1) or there is no default route."""
    for r in routes:
        if not isinstance(r, dict) or str(r.get("dst-address") or "") != "0.0.0.0/0":
            continue
        if str(r.get("active", "true")).lower() not in ("true", "yes") or str(r.get("disabled", "false")).lower() in ("true", "yes"):
            continue
        for key in ("gateway", "immediate-gw"):
            v = str(r.get(key) or "").split("%", 1)[0].split()[0] if r.get(key) else ""
            try:
                return str(ipaddress.IPv4Address(v))
            except ValueError:
                continue
    return None


def is_tunnel(iface: str) -> bool:
    import re
    return bool(re.match(r"^(eoip|gre|gretap|ipip|wireguard|wg\d|wg-|l2tp-|sstp-|ovpn-|pptp-|<l2tp|<sstp|<ovpn|<pptp)", (iface or "").lower()))


def refine(addresses: List[dict], gateways: Dict[int, Optional[str]], wan_lists: Dict[int, List[str]]) -> set:
    """The roles of every address after looking at all devices together (3.67). gateways: device -> its default route's gateway address (None
    when not read). wan_lists: device -> the interfaces in its WAN list. Sets each address's "role" in place and returns the devices at the
    edge (a public address, or a default route to something that is not a managed device)."""
    managed = {r["ip"] for r in addresses if r.get("ip")}
    edge = set()
    for did in {r["device_id"] for r in addresses} | set(gateways) | set(wan_lists):
        own = [r for r in addresses if r["device_id"] == did]
        public = any(is_public(r["ip"]) and not is_tunnel(r.get("iface") or "") for r in own)
        gw = gateways.get(did)
        if public or (gw is not None and gw not in managed) or (gw is None and did not in gateways and wan_lists.get(did)):
            edge.add(did)                      # (route not read: the WAN list is taken as it was before 3.67)
    for r in addresses:
        iface = r.get("iface") or ""
        if is_tunnel(iface):
            r["role"] = "tunnel"
        elif r.get("role") == "wan" and r["device_id"] not in edge:
            r["role"] = "uplink"               # a switch's / AP's way to the router, even with ether1 in a defconf WAN list
        elif r.get("role") == "wan" and not is_public(r["ip"]) and gateways.get(r["device_id"]) in managed:
            r["role"] = "uplink"
    return edge


def role_of(iface: str, ip: Optional[str], wan_ifaces: Iterable[str], default_iface: Optional[str]) -> str:
    if is_tunnel(iface):
        return "tunnel"
    wan = {w.lower() for w in wan_ifaces or []}
    if (iface or "").lower() in wan or (ip and is_public(ip)):
        return "wan"
    if not wan and default_iface and (iface or "").lower() == default_iface.lower():
        return "uplink"
    return "access"


def router_addresses(max_age_sec: Optional[float] = None) -> List[dict]:
    """[{device_id, device_name, device_ip, ip, iface, role, network}] from the last scan (empty when there was none)."""
    try:
        mtime = os.path.getmtime(_PATH)
    except OSError:
        return []
    if mtime != _cache["mtime"]:
        try:
            with open(_PATH, encoding="utf-8") as f:
                _cache["rows"] = [r for r in (json.load(f).get("addresses") or []) if isinstance(r, dict) and r.get("ip")]
        except (OSError, ValueError):
            _cache["rows"] = []
        _cache["mtime"] = mtime
    if max_age_sec is not None and time.time() - mtime > max_age_sec:
        return []
    return list(_cache["rows"])


def by_ip(rows: Optional[List[dict]] = None) -> Dict[str, dict]:
    """A router's own address -> its row (the device it belongs to, the interface, the role)."""
    return {r["ip"]: r for r in (router_addresses() if rows is None else rows)}


def wan_ips(rows: Optional[List[dict]] = None) -> set:
    return {r["ip"] for r in (router_addresses() if rows is None else rows) if r.get("role") == "wan"}


def iface_role(device_id: int, iface: str, rows: Optional[List[dict]] = None) -> Optional[str]:
    for r in (router_addresses() if rows is None else rows):
        if r.get("device_id") == device_id and (r.get("iface") or "").lower() == (iface or "").lower():
            return r.get("role")
    return None


def role_for(ip: str, iface: str, rows: Optional[List[dict]] = None) -> Optional[str]:
    """The role of an interface of the device that has this address (any of its addresses)."""
    rows = router_addresses() if rows is None else rows
    did = next((r.get("device_id") for r in rows if r.get("ip") == ip or r.get("device_ip") == ip), None)
    return iface_role(did, iface, rows) if did is not None else None
