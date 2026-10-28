"""
The small network tools an administrator reaches for (idea: NETworkManager), run from the agent's own position in the network.

  * Wake on LAN  - the magic packet for a MAC address, sent as a UDP broadcast (the global one and, for a host of the inventory, its /24);
  * SNMP         - GET and WALK of one OID on a host of the inventory, with the community of its stored credential or one typed in. Read only: there is no SET here on purpose;
  * RDAP         - who a public address, a domain or an AS number belongs to (the public RDAP service answers; the query leaves the network, so it is only run when asked);
  * Path         - the traceroute to a host as a chain of hops, with the inventory's names and the latency each hop adds.

Everything is started by a person from the page; nothing runs on its own. The guard rails are in the checks below: only addresses the inventory knows for SNMP, only
public addresses for RDAP, one magic packet per MAC every few seconds, at most MAX_WALK rows of a walk.
"""
import asyncio
import ipaddress
import re
import socket
import time
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, Device, VulnHost, Credential
from services.crypto import decrypt

MAX_WALK = 300
WOL_PORT = 9
WOL_GAP_SEC = 8
RDAP_BASE = "https://rdap.org"
_wol_last: Dict[str, float] = {}
_OID = re.compile(r"^\.?\d+(\.\d+){0,40}$")
_MAC = re.compile(r"^([0-9a-f]{2}[:\-]?){5}[0-9a-f]{2}$", re.I)
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
KNOWN_OIDS = {
    "1.3.6.1.2.1.1.1": "sysDescr", "1.3.6.1.2.1.1.2": "sysObjectID", "1.3.6.1.2.1.1.3": "sysUpTime", "1.3.6.1.2.1.1.4": "sysContact", "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation", "1.3.6.1.2.1.2.1": "ifNumber", "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.2.2.1.5": "ifSpeed", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus", "1.3.6.1.2.1.2.2.1.10": "ifInOctets", "1.3.6.1.2.1.2.2.1.16": "ifOutOctets", "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.4.20.1.1": "ipAdEntAddr", "1.3.6.1.2.1.25.1.1": "hrSystemUptime", "1.3.6.1.2.1.25.2.3.1.3": "hrStorageDescr", "1.3.6.1.2.1.33.1.2.1": "upsBatteryStatus",
}


# ── Wake on LAN ──────────────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    m = (mac or "").strip()
    if not _MAC.match(m):
        raise ValueError("a MAC address is required (aa:bb:cc:dd:ee:ff)")
    h = re.sub(r"[^0-9a-f]", "", m.lower())
    if h == "0" * 12 or h == "f" * 12:
        raise ValueError("this MAC address cannot be woken")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def magic_packet(mac: str) -> bytes:
    raw = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + raw * 16


def _subnet_broadcast(ip: str) -> Optional[str]:
    try:
        a = ipaddress.ip_address(ip)
        if a.version != 4 or not a.is_private:
            return None
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).broadcast_address)
    except ValueError:
        return None


def wake(mac: str, now: Optional[float] = None, sender=None) -> dict:
    """Sends the magic packet; returns {"mac", "sent_to": [...]}. ValueError for a bad MAC or a repeat within WOL_GAP_SEC. `sender(packet, addr)` is for tests."""
    mac = normalize_mac(mac)
    t = now if now is not None else time.time()
    if mac in _wol_last and t - _wol_last[mac] < WOL_GAP_SEC:
        raise ValueError(f"a packet for this MAC was sent a moment ago - wait {WOL_GAP_SEC} seconds")
    targets = ["255.255.255.255"]
    with SessionLocal() as db:
        for a in db.execute(select(Asset).where(Asset.mac.is_not(None))).scalars().all():
            try:
                if normalize_mac(a.mac) == mac and a.ip:
                    b = _subnet_broadcast(a.ip)
                    if b and b not in targets:
                        targets.append(b)
            except ValueError:
                continue
    packet = magic_packet(mac)
    if sender is None:
        def sender(pkt, addr):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(2)
                s.sendto(pkt, (addr, WOL_PORT))
    sent, errors = [], []
    for addr in targets:
        try:
            sender(packet, addr)
            sent.append(addr)
        except OSError as e:
            errors.append(f"{addr}: {e}")
    if not sent:
        raise ValueError("nothing could be sent: " + "; ".join(errors))
    _wol_last[mac] = t
    return {"mac": mac, "sent_to": sent, "errors": errors}


def hosts() -> List[dict]:
    """The hosts of the inventory the tools can be pointed at: name, address, MAC, and whether a stored SNMP community exists for it."""
    with SessionLocal() as db:
        snmp_ips = {d.ip for d in db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
                    if (c := db.get(Credential, d.credential_id)) is not None and c.snmp_community_enc}
        out = []
        for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all():
            out.append({"name": a.name or a.ip, "ip": a.ip, "mac": a.mac, "snmp": a.ip in snmp_ips, "type": a.asset_type})
    out.sort(key=lambda h: h["name"].lower())
    return out


# ── SNMP ─────────────────────────────────────────────────────────────────────

def _known(ip: str) -> bool:
    with SessionLocal() as db:
        return bool(db.execute(select(Asset.id).where(Asset.ip == ip).limit(1)).first() or db.execute(select(Device.id).where(Device.ip == ip).limit(1)).first()
                    or db.execute(select(VulnHost.id).where(VulnHost.ip == ip).limit(1)).first())


def _stored_community(ip: str) -> Optional[str]:
    with SessionLocal() as db:
        for d in db.execute(select(Device).where(Device.ip == ip, Device.credential_id.is_not(None))).scalars().all():
            c = db.get(Credential, d.credential_id)
            if c is not None and c.snmp_community_enc:
                try:
                    return decrypt(c.snmp_community_enc)
                except Exception:
                    continue
    return None


def oid_name(oid: str) -> Optional[str]:
    """A known name for the OID or for its table column ("sysDescr.0", "ifDescr.3")."""
    o = oid.lstrip(".")
    parts = o.split(".")
    for cut in range(len(parts), 0, -1):
        base = ".".join(parts[:cut])
        if base in KNOWN_OIDS:
            rest = ".".join(parts[cut:])
            return KNOWN_OIDS[base] + (f".{rest}" if rest else "")
    return None


def _show(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        try:
            s = bytes(v).decode("utf-8")
            if s.isprintable():
                return s
        except UnicodeDecodeError:
            pass
        return bytes(v).hex(":")
    return str(v)


async def snmp_query(ip: str, op: str, oid: str, community: Optional[str] = None, port: int = 161, client=None) -> dict:
    """GET or WALK of one OID. {"rows": [{"oid", "name", "value"}], "truncated": bool}. ValueError for what the guard rails refuse."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("an IP address is required")
    if op not in ("get", "walk"):
        raise ValueError("only GET and WALK are available (read only)")
    if not _OID.match(oid or ""):
        raise ValueError("an OID in numeric form is required (1.3.6.1.2.1.1.1.0)")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port out of range")
    if not _known(ip):
        raise ValueError("only addresses the inventory knows can be queried")
    comm = (community or "").strip() or _stored_community(ip)
    if not comm:
        raise ValueError("no SNMP community: type one, or store it in the credential of the device")
    if client is None:
        from services.snmp_client import SnmpClient
        client = SnmpClient(ip, comm, port=int(port), timeout=4.0)
    oid = oid.lstrip(".")
    try:
        if op == "get":
            raw = [(oid, await client._get(oid))]
        else:
            raw = await client._walk(oid)
    except asyncio.TimeoutError:
        raise ValueError("no answer (timeout) - wrong community, SNMP off, or a blocked port")
    except Exception as e:
        raise ValueError(f"{type(e).__name__}: {e}"[:200])
    rows = [{"oid": o, "name": oid_name(o), "value": _show(v)[:500]} for o, v in raw[:MAX_WALK]]
    return {"rows": rows, "truncated": len(raw) > MAX_WALK}


# ── RDAP ─────────────────────────────────────────────────────────────────────

def classify(q: str) -> tuple:
    """("ip" | "autnum" | "domain", normalised query). ValueError for anything else, and for addresses that are not public."""
    q = (q or "").strip().lower()
    if not q:
        raise ValueError("enter an address, a domain or an AS number")
    m = re.fullmatch(r"(?:as)?(\d{1,10})", q)
    if m and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", q):
        return "autnum", m.group(1)
    try:
        a = ipaddress.ip_address(q)
    except ValueError:
        a = None
    if a is not None:
        if not a.is_global:
            raise ValueError("only public addresses can be looked up (RDAP knows nothing about internal ones)")
        return "ip", str(a)
    if _HOST.match(q):
        return "domain", q
    raise ValueError("not an IP address, a domain or an AS number")


def summarize(kind: str, d: dict) -> dict:
    """The few fields of an RDAP answer a person reads."""
    def events():
        return [{"action": e.get("eventAction"), "date": e.get("eventDate")} for e in d.get("events", []) if e.get("eventAction")][:8]

    def entities():
        out = []
        for e in d.get("entities", []):
            vc = e.get("vcardArray") or []
            name = None
            if len(vc) > 1:
                for item in vc[1]:
                    if item and item[0] == "fn":
                        name = item[3]
            out.append({"roles": e.get("roles", []), "handle": e.get("handle"), "name": name})
        return out[:8]
    out = {"kind": kind, "handle": d.get("handle"), "name": d.get("name") or d.get("ldhName"), "status": d.get("status", []), "events": events(), "entities": entities(),
           "country": d.get("country"), "type": d.get("type")}
    if kind == "ip":
        out["range"] = f"{d.get('startAddress')} - {d.get('endAddress')}" if d.get("startAddress") else None
        out["cidr"] = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in d.get("cidr0_cidrs", [])]
    if kind == "domain":
        out["nameservers"] = [n.get("ldhName") for n in d.get("nameservers", []) if n.get("ldhName")]
    if kind == "autnum":
        out["range"] = f"{d.get('startAutnum')} - {d.get('endAutnum')}" if d.get("startAutnum") else None
    return out


async def rdap(query: str, fetch=None) -> dict:
    kind, q = classify(query)
    url = f"{RDAP_BASE}/{kind}/{q}"
    if fetch is None:
        import aiohttp

        async def fetch(u):
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                async with s.get(u, headers={"Accept": "application/rdap+json"}, allow_redirects=True) as r:
                    if r.status == 404:
                        raise ValueError("nothing found for this query")
                    r.raise_for_status()
                    return await r.json(content_type=None)
    try:
        data = await fetch(url)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"the RDAP service did not answer: {type(e).__name__}: {e}"[:200])
    return summarize(kind, data)


# ── Path ─────────────────────────────────────────────────────────────────────

def resolve(target: str) -> str:
    t = (target or "").strip()
    try:
        a = ipaddress.ip_address(t)
    except ValueError:
        a = None
    if a is not None:
        if a.version != 4:
            raise ValueError("only IPv4 targets")
        return str(a)
    if not _HOST.match(t):
        raise ValueError("an IPv4 address or a host name is required")
    try:
        return socket.getaddrinfo(t, None, socket.AF_INET)[0][4][0]
    except OSError:
        raise ValueError("the name does not resolve")


async def path(target: str, tracer=None) -> dict:
    """{"target", "ip", "hops": [{n, ip, ms, delta, name, scope}], "reached"}: the traceroute with the inventory's names and what each hop adds to the latency."""
    ip = resolve(target)
    if tracer is None:
        from services import traceroute
        tracer = traceroute.trace
    r = await tracer(ip)
    with SessionLocal() as db:
        names = {a.ip: a.name for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all() if a.name}
    hops, prev = [], 0.0
    for h in r.get("hops", []):
        scope = None
        if h.get("ip"):
            a = ipaddress.ip_address(h["ip"])
            scope = "private" if a.is_private else "public"
        ms = h.get("ms")
        delta = None
        if ms is not None:
            delta = round(max(0.0, ms - prev), 1)
            prev = ms
        hops.append({"n": h["n"], "ip": h.get("ip"), "ms": ms, "delta": delta, "name": names.get(h.get("ip")), "scope": scope})
    return {"target": target, "ip": ip, "hops": hops, "reached": bool(r.get("reached")), "error": r.get("error")}
