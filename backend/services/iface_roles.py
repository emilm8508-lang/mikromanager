"""
The role of each router / switch interface and which addresses belong to the routers themselves.

  wan     - in the router's own "WAN" interface list, or carrying a public address: the way to the internet
  uplink  - on a device without a WAN list (a switch, an AP), the interface its default route leaves through: its way to the router.
            Not a WAN - seen in production: ether1 on CRS switches (R2-S1, R2-S2, R1-S3) read as a WAN link
  access  - everything else (where the users and servers are)

The addresses come from services/edge_discovery.py's scan (data/router_addresses.json). With them the inventory puts a router's own
address on that router instead of listing it as a host (seen: 192.168.0.2, the WAN address of mcprojekt's MC-R1, as a host of its own),
and NetFlow knows which addresses are a router's WAN (stage 5). Pure helpers + one file reader; no network.
"""
import ipaddress
import json
import os
import time
from typing import Dict, Iterable, List, Optional

ROLES = ("wan", "uplink", "access")
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


def role_of(iface: str, ip: Optional[str], wan_ifaces: Iterable[str], default_iface: Optional[str]) -> str:
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
