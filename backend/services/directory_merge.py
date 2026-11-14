"""
The routers' DHCP leases and ARP tables -> one consistent (IP, MAC, name) per address, for the asset inventory and the host search.

Seen in production (mcprojekt, 3.57): the inventory showed a Hyper-V VM ("wazuh", Ubuntu) made by MikroTik, a "Redmi-Note-13-5G" made by
Dell, an "iPhone" made by Ugreen, and the same PC name on two or three neighbouring addresses. The old merge took the rows of every router
one by one and matched each to an existing entry by its IP *or* its MAC, only filling what was missing. Two things then went wrong:

  * a router that reaches another site's addresses through proxy-ARP / EoIP lists them all under ONE MAC (its peer's): matching by MAC
    folded those addresses into one entry and gave every later lease of them that router's MAC - "made by MikroTik";
  * a DHCP lease keeps the host name of the last device that held the address (a static reservation stays "waiting" with it) while ARP
    shows who has the address now: the old name was glued to the new device's MAC.

Here every observation is collected first, then decided per address:
  * a MAC the ARP tables show for 3 or more addresses is a router's / proxy's, never a device's (kept as `shared_mac`, not as `mac`);
  * the MAC of an address is the one ARP sees now (the router that leases the address first), else the lease's;
  * the name is the one the leases give for THAT MAC - a lease whose MAC is not the device on the address now does not name it.

Pure (no database, no network): backend/tests/test_inventory_identity.py.
"""
import re
from typing import Dict, Iterable, List, Optional

SHARED_MAC_MIN_IPS = 3
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def norm_mac(m: Optional[str]) -> Optional[str]:
    s = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    if len(s) != 12 or s in ("0" * 12, "f" * 12):
        return None
    return ":".join(s[i:i + 2] for i in range(0, 12, 2))


def _true(v) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1")


def _lease(l: dict) -> Optional[dict]:
    ip = (l.get("active-address") or l.get("address") or "").strip()
    mac = norm_mac(l.get("active-mac-address") or l.get("mac-address"))
    if not ip or _true(l.get("disabled")) or _true(l.get("blocked")):
        return None
    status = (l.get("status") or "").strip().lower()
    return {"ip": ip, "mac": mac, "name": (l.get("host-name") or "").strip() or None, "comment": (l.get("comment") or "").strip() or None,
            "bound": status in ("bound", ""), "status": status or None}


def _arp(a: dict) -> Optional[dict]:
    ip = (a.get("address") or "").strip()
    mac = norm_mac(a.get("mac-address"))
    if not ip or not mac or _true(a.get("published")) or _true(a.get("invalid")) or _true(a.get("disabled")):
        return None
    if "complete" in a and not _true(a.get("complete")):
        return None
    return {"ip": ip, "mac": mac}


def build(datas: Iterable[dict]) -> List[dict]:
    """datas: [{"dev": {"name": ...}, "leases": [...], "arp": [...]}] as host_monitor fetches them from the routers.
    Returns [{"ip", "mac", "name", "comment", "sources": set, "devices": set, "shared_mac": mac|None, "notes": [...]}], one per address."""
    leases: List[dict] = []
    arps: List[dict] = []
    for d in datas:
        router = ((d.get("dev") or {}).get("name")) or "?"
        for l in d.get("leases") or []:
            x = _lease(l) if isinstance(l, dict) else None
            if x:
                leases.append({**x, "router": router})
        for a in d.get("arp") or []:
            x = _arp(a) if isinstance(a, dict) else None
            if x:
                arps.append({**x, "router": router})

    ips_by_mac: Dict[str, set] = {}
    for a in arps:
        ips_by_mac.setdefault(a["mac"], set()).add(a["ip"])
    shared = {m for m, ips in ips_by_mac.items() if len(ips) >= SHARED_MAC_MIN_IPS}

    # the name / comment of each MAC, from its leases (a bound lease wins over a waiting reservation)
    name_by_mac: Dict[str, dict] = {}
    for l in sorted(leases, key=lambda x: x["bound"]):
        if l["mac"] and (l["name"] or l["comment"]):
            cur = name_by_mac.setdefault(l["mac"], {})
            cur["name"] = l["name"] or cur.get("name")
            cur["comment"] = l["comment"] or cur.get("comment")

    lease_routers_by_ip: Dict[str, set] = {}
    for l in leases:
        lease_routers_by_ip.setdefault(l["ip"], set()).add(l["router"])

    out: Dict[str, dict] = {}

    def entry(ip: str) -> dict:
        if ip not in out:
            out[ip] = {"ip": ip, "mac": None, "name": None, "comment": None, "sources": set(), "devices": set(), "shared_mac": None, "notes": []}
        return out[ip]

    # ARP: who has the address now. The router that leases the address knows its own LAN best.
    arp_by_ip: Dict[str, List[dict]] = {}
    for a in arps:
        arp_by_ip.setdefault(a["ip"], []).append(a)
    for ip, rows in arp_by_ip.items():
        e = entry(ip)
        e["sources"].add("arp")
        e["devices"].update(r["router"] for r in rows)
        own = [r for r in rows if r["mac"] not in shared]
        if not own:
            e["shared_mac"] = rows[0]["mac"]
            e["notes"].append("reached through a router (proxy-ARP / tunnel): its MAC is not the device's")
            continue
        lessors = lease_routers_by_ip.get(ip, set())
        own.sort(key=lambda r: 0 if r["router"] in lessors else 1)
        macs = {r["mac"] for r in own}
        e["mac"] = own[0]["mac"]
        if len(macs) > 1:
            e["notes"].append(f"routers disagree on the MAC: {', '.join(sorted(macs))}")

    for l in leases:
        e = entry(l["ip"])
        e["sources"].add("dhcp")
        e["devices"].add(l["router"])
        if e["mac"] is None and e["shared_mac"] is None and l["mac"]:
            if l["bound"]:
                e["mac"] = l["mac"]                       # no ARP row (yet): the bound lease's MAC is who has it
            else:
                e["notes"].append(f"only a {l['status'] or 'waiting'} lease, nobody seen on the address")
        if l["mac"] and e["mac"] and l["mac"] != e["mac"]:
            e["notes"].append(f"lease of {l['mac']} ({l['name'] or 'no name'}) - another device than the one on the address now")

    for e in out.values():
        n = name_by_mac.get(e["mac"]) if e["mac"] else None
        if n:
            e["name"], e["comment"] = n.get("name"), n.get("comment")
        elif not e["mac"] and not e["shared_mac"]:
            # nobody seen: a waiting reservation may still name the address
            l = next((x for x in leases if x["ip"] == e["ip"] and x["mac"] and not x["bound"]), None)
            if l and l["mac"] in name_by_mac:
                e["name"] = name_by_mac[l["mac"]].get("name")
                e["comment"] = name_by_mac[l["mac"]].get("comment")
    return list(out.values())
