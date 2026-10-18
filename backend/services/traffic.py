"""Live traffic analyzer: who talks to whom through a router, right now.

A packet capture on the agent's own computer would only see its own traffic on a switched network (and needs a driver, administrator rights and
raises privacy questions). The router sees all of it, so this asks the router: RouterOS "Torch" (/tool/torch) lists, for the seconds asked, every
flow on an interface - source and destination address, protocol and ports, and the rate in each direction. The result is aggregated per device
(addresses resolved to inventory assets), per protocol and per port. Read-only: Torch changes nothing on the router.

Used by the traffic page, which asks again every few seconds for a "live" view and keeps the history in the browser."""
import asyncio
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, Device, Credential
from services.device_client import build_client

MAX_SECONDS = 5
_PROTO_NAMES = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "58": "icmpv6", "89": "ospf", "112": "vrrp"}
_WELL_KNOWN = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 135: "rpc",
               137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
               587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5060: "sip", 5353: "mdns",
               5432: "postgres", 5900: "vnc", 8080: "http-alt", 8291: "winbox", 8443: "https-alt", 8728: "api", 9100: "print"}


def _num(v) -> int:
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return 0


def _port(v) -> Optional[int]:
    n = _num(v)
    return n if n > 0 else None


def normalize(rows: list) -> List[dict]:
    """Torch rows -> flows [{src, dst, proto, sport, dport, service, tx, rx}] (rates in bits per second; tx = from the source to the destination of the
    flow, rx = back). Rows without addresses (the MAC-level ones) are dropped."""
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        src, dst = r.get("src-address") or r.get("src_address"), r.get("dst-address") or r.get("dst_address")
        if not src or not dst:
            continue
        proto = str(r.get("ip-protocol") or r.get("ip_protocol") or "")
        sport, dport = _port(r.get("src-port") or r.get("src_port")), _port(r.get("dst-port") or r.get("dst_port"))
        svc = _WELL_KNOWN.get(dport or 0) or _WELL_KNOWN.get(sport or 0)
        out.append({"src": str(src), "dst": str(dst), "proto": _PROTO_NAMES.get(proto, proto or "?"), "sport": sport, "dport": dport, "service": svc,
                    "tx": _num(r.get("tx")), "rx": _num(r.get("rx"))})
    out.sort(key=lambda f: -(f["tx"] + f["rx"]))
    return out


def _names() -> Dict[str, dict]:
    with SessionLocal() as db:
        return {a.ip: {"id": a.id, "name": a.name or a.ip, "type": a.asset_type} for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()
                if not a.key.startswith(("mon:", "prt:"))}


def aggregate(flows: List[dict], names: Dict[str, dict]) -> dict:
    """Per device (bits per second in each direction, the asset it resolves to), per protocol and per service."""
    dev: Dict[str, dict] = {}
    proto: Dict[str, int] = {}
    svc: Dict[str, int] = {}
    for f in flows:
        total = f["tx"] + f["rx"]
        for ip, up, down in ((f["src"], f["tx"], f["rx"]), (f["dst"], f["rx"], f["tx"])):
            d = dev.setdefault(ip, {"ip": ip, "up": 0, "down": 0, "flows": 0})
            d["up"] += up
            d["down"] += down
            d["flows"] += 1
        proto[f["proto"]] = proto.get(f["proto"], 0) + total
        key = f["service"] or (f"{f['proto']}/{f['dport']}" if f["dport"] else f["proto"])
        svc[key] = svc.get(key, 0) + total
    for ip, d in dev.items():
        n = names.get(ip)
        d["name"] = n["name"] if n else None
        d["asset_id"] = n["id"] if n else None
        d["type"] = n["type"] if n else None
        try:
            d["local"] = ipaddress.ip_address(ip).is_private
        except ValueError:
            d["local"] = False
    return {"devices": sorted(dev.values(), key=lambda d: -(d["up"] + d["down"]))[:60],
            "protocols": sorted(([k, v] for k, v in proto.items()), key=lambda kv: -kv[1]),
            "services": sorted(([k, v] for k, v in svc.items()), key=lambda kv: -kv[1])[:20]}


def mikrotik_devices() -> List[dict]:
    """The routers that can be asked (a MikroTik with a stored credential)."""
    with SessionLocal() as db:
        rows = db.execute(select(Device, Credential).join(Credential, Device.credential_id == Credential.id)).all()
        return [{"id": d.id, "name": d.identity or d.name or d.ip, "ip": d.ip} for d, _c in rows if (d.vendor or "mikrotik").lower() == "mikrotik"]


async def interfaces(device_id: int) -> List[str]:
    client = _client(device_id)
    rows = await asyncio.wait_for(client.get_interfaces(), 12)
    return sorted({str(r.get("name")) for r in rows if r.get("name") and not _b(r.get("disabled"))}, key=lambda n: (not n.startswith("ether"), n))


def _b(v) -> bool:
    return v is True or str(v).lower() in ("true", "yes", "1")


def _client(device_id: int):
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        c = db.get(Credential, d.credential_id) if d and d.credential_id else None
        if not d or not c or (d.vendor or "mikrotik").lower() != "mikrotik":
            raise ValueError("this device cannot be asked for traffic (a MikroTik with a stored credential is needed)")
        return build_client(d, c)


async def sample(device_id: int, interface: str, seconds: int = 3) -> dict:
    """One Torch run of `seconds` on `interface`: {"flows", "agg", "at"}. Raises ValueError for a device that cannot be asked."""
    seconds = max(1, min(MAX_SECONDS, int(seconds or 3)))
    client = _client(device_id)
    rows = await client.torch(interface, seconds)
    flows = normalize(rows)
    return {"flows": flows[:300], "agg": aggregate(flows, _names()), "at": datetime.utcnow().isoformat() + "Z", "interface": interface, "seconds": seconds}
