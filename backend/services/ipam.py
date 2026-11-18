"""
IP address management from what the routers already know: how full each subnet and each DHCP pool is, what is free, and which addresses
are in conflict.

Every 30 minutes the MikroTik routers with a stored credential are read (over the shared API login of services/mikrotik_client.py, so
this adds no router log lines of its own): /ip/address (the subnets), /ip/pool and /ip/dhcp-server (the DHCP ranges and which server
hands them out), /ip/dhcp-server/lease and /ip/arp (who uses which address now). The inventory's addresses (Asset.ip) count as used too.

  subnets   every IPv4 network a router has an address in (up to /16): size, used, free, usage %, and the first free addresses;
  pools     every DHCP pool: size, bound leases, usage %, and - from the usage history (services/metrics.py, kind other) - the days until
            it is full when it grows steadily;
  conflicts an address answered by two or more MACs at once (ARP entries of different routers, or an ARP entry and the bound lease of
            another MAC). A MAC that a router shows for many addresses (proxy ARP, a router's own) is not counted;
  static in pool   addresses inside a DHCP range used without a lease: a fixed address the DHCP server may hand out again.

Alerts (through the SOC layer), each after two passes in a row, closed after a good one:
  net.ip_conflict   an address with two MACs (medium);
  net.dhcp_pool     a pool at 90% or more (medium; high from 98%), or growing to full within 7 days (medium).
Read-only on the routers.
"""
import asyncio
import ipaddress
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Asset

_LAST_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ipam_last.json")
INTERVAL_SEC = 1800
MAX_PREFIX = 16                      # larger networks are listed but not counted address by address
FREE_LIST = 40
SHARED_MAC_MIN = 8                   # a MAC a router shows for this many addresses is a proxy-ARP / router MAC
POOL_WARN, POOL_CRIT = 90.0, 98.0
FORECAST_DAYS = 7
STREAK = 2

_task: Optional[asyncio.Task] = None
_last: Dict[str, object] = {"at": None, "routers": 0, "errors": [], "duration_sec": None}
_result: Dict[str, object] = {}
_streak: Dict[Tuple[str, str], int] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── Parsing (pure) ───────────────────────────────────────────────────────────

def _yes(v) -> bool:
    return v is True or str(v).lower() in ("true", "yes")


def _mac(v) -> Optional[str]:
    s = str(v or "").strip().upper().replace("-", ":")
    return s if len(s) == 17 else None


def _ip(v) -> Optional[ipaddress.IPv4Address]:
    try:
        a = ipaddress.ip_address(str(v or "").split("/")[0].strip())
        return a if a.version == 4 else None
    except ValueError:
        return None


def parse_ranges(spec: str) -> List[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    """RouterOS pool ranges: "192.168.1.100-192.168.1.200,192.168.1.210", or a prefix "10.0.0.0/24"."""
    out = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                n = ipaddress.ip_network(part, strict=False)
                if n.version == 4:
                    out.append((n.network_address, n.broadcast_address))
            elif "-" in part:
                a, b = (ipaddress.ip_address(x.strip()) for x in part.split("-", 1))
                if a.version == 4 and b.version == 4 and a <= b:
                    out.append((a, b))
            else:
                a = ipaddress.ip_address(part)
                if a.version == 4:
                    out.append((a, a))
        except ValueError:
            continue
    return out


def _in_ranges(a: ipaddress.IPv4Address, ranges) -> bool:
    return any(lo <= a <= hi for lo, hi in ranges)


def _range_size(ranges) -> int:
    return sum(int(hi) - int(lo) + 1 for lo, hi in ranges)


def networks(addresses: List[dict]) -> Dict[str, dict]:
    """/ip/address rows -> {network: {"router", "interface", "gateway"}} (IPv4, enabled, valid)."""
    out = {}
    for r in addresses:
        if _yes(r.get("disabled")) or _yes(r.get("invalid")):
            continue
        try:
            iface = ipaddress.ip_interface(str(r.get("address") or ""))
        except ValueError:
            continue
        if iface.version != 4 or iface.network.prefixlen >= 31:
            continue
        out[str(iface.network)] = {"interface": r.get("interface"), "gateway": str(iface.ip)}
    return out


def used_addresses(leases: List[dict], arp: List[dict]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, str]]:
    """(ip -> MACs from ARP, ip -> MACs of bound leases, ip -> lease status) of one router. A MAC the router shows for SHARED_MAC_MIN or
    more addresses (proxy ARP / its own) is dropped."""
    arp_by_ip: Dict[str, Set[str]] = defaultdict(set)
    count: Dict[str, int] = defaultdict(int)
    rows = []
    for r in arp:
        a, m = _ip(r.get("address")), _mac(r.get("mac-address"))
        if not a or not m or _yes(r.get("invalid")) or _yes(r.get("disabled")):
            continue
        st = str(r.get("status") or "").lower()
        if st in ("failed", "incomplete") or (r.get("complete") is not None and not _yes(r.get("complete"))):
            continue
        rows.append((str(a), m))
        count[m] += 1
    for a, m in rows:
        if count[m] < SHARED_MAC_MIN:
            arp_by_ip[a].add(m)
    lease_by_ip: Dict[str, Set[str]] = defaultdict(set)
    status: Dict[str, str] = {}
    for r in leases:
        a = _ip(r.get("active-address") or r.get("address"))
        if not a or _yes(r.get("disabled")):
            continue
        st = str(r.get("status") or "").lower()
        status[str(a)] = st
        if st == "bound":
            m = _mac(r.get("active-mac-address") or r.get("mac-address"))
            if m:
                lease_by_ip[str(a)].add(m)
    return arp_by_ip, lease_by_ip, status


def conflicts(per_router: List[Tuple[str, Dict[str, Set[str]], Dict[str, Set[str]]]]) -> List[dict]:
    """Addresses with two or more MACs at once: ARP of different routers, or ARP against a bound lease of another MAC."""
    arp_all: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))    # ip -> mac -> routers
    lease_all: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    for router, arp_by_ip, lease_by_ip in per_router:
        for ip, macs in arp_by_ip.items():
            for m in macs:
                arp_all[ip][m].add(router)
        for ip, macs in lease_by_ip.items():
            for m in macs:
                lease_all[ip][m].add(router)
    out = []
    for ip, macs in arp_all.items():
        seen = set(macs)
        if len(seen) == 1:
            lease_macs = set(lease_all.get(ip, {}))
            if lease_macs and not (lease_macs & seen):
                seen |= lease_macs
        if len(seen) >= 2:
            out.append({"ip": ip, "macs": sorted(seen)[:6], "routers": sorted({r for m in macs.values() for r in m} | {r for m in lease_all.get(ip, {}).values() for r in m})[:6]})
    return sorted(out, key=lambda x: ipaddress.ip_address(x["ip"]))


def _free(net: ipaddress.IPv4Network, used: Set[ipaddress.IPv4Address], limit: int = FREE_LIST) -> List[str]:
    out = []
    for a in net.hosts():
        if a not in used:
            out.append(str(a))
            if len(out) >= limit:
                break
    return out


# ── Reading the routers ──────────────────────────────────────────────────────

async def _read(dev: dict) -> dict:
    from services.mikrotik_client import MikrotikClient
    c = MikrotikClient(dev["ip"], dev["username"], dev["password"], api_port=dev["api_port"], web_port=dev["web_port"])
    out = {"dev": dev, "error": None}
    for key, rest, api in (("addresses", "ip/address", "/ip/address"), ("pools", "ip/pool", "/ip/pool"), ("servers", "ip/dhcp-server", "/ip/dhcp-server"),
                           ("leases", "ip/dhcp-server/lease", "/ip/dhcp-server/lease"), ("arp", "ip/arp", "/ip/arp")):
        try:
            out[key] = await asyncio.wait_for(c._rest_or_api(rest, api), timeout=30) or []
        except Exception as e:
            out[key] = []
            if key == "addresses":
                out["error"] = f"{type(e).__name__}: {e}"[:200]
    return out


def build(reads: List[dict], asset_ips: Iterable[str]) -> dict:
    """The IPAM picture from the routers' tables (pure apart from nothing - testable)."""
    nets: Dict[str, dict] = {}
    pools: List[dict] = []
    per_router = []
    arp_any: Dict[str, Set[str]] = defaultdict(set)
    lease_any: Dict[str, str] = {}
    for r in reads:
        name = r["dev"]["name"]
        for n, info in networks(r.get("addresses") or []).items():
            nets.setdefault(n, {**info, "router": name})
        arp_by_ip, lease_by_ip, status = used_addresses(r.get("leases") or [], r.get("arp") or [])
        per_router.append((name, arp_by_ip, lease_by_ip))
        for ip, ms in arp_by_ip.items():
            arp_any[ip] |= ms
        for ip, st in status.items():
            if st == "bound" or ip not in lease_any:
                lease_any[ip] = st
        served = {}
        for s in r.get("servers") or []:
            if not _yes(s.get("disabled")) and s.get("address-pool"):
                served[str(s["address-pool"])] = {"server": s.get("name"), "interface": s.get("interface")}
        for p in r.get("pools") or []:
            ranges = parse_ranges(p.get("ranges"))
            if not ranges:
                continue
            size = _range_size(ranges)
            bound = sum(1 for ip, st in status.items() if st == "bound" and _in_ranges(ipaddress.ip_address(ip), ranges))
            srv = served.get(str(p.get("name")))
            pools.append({"key": f"{name}:{p.get('name')}", "router": name, "name": p.get("name"), "ranges": p.get("ranges"), "size": size, "bound": bound,
                          "pct": round(100.0 * bound / size, 1) if size else None, "server": srv["server"] if srv else None, "interface": srv["interface"] if srv else None,
                          "served": bool(srv)})
    used_ips: Set[ipaddress.IPv4Address] = set()
    for ip in list(arp_any) + [ip for ip, st in lease_any.items() if st == "bound"] + list(asset_ips or []):
        a = _ip(ip)
        if a:
            used_ips.add(a)
    pool_ranges = [(p, parse_ranges(p["ranges"])) for p in pools if p["served"]]
    subnets = []
    for n, info in nets.items():
        net = ipaddress.ip_network(n)
        size = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        counted = net.prefixlen >= MAX_PREFIX
        inside = {a for a in used_ips if a in net} if counted else set()
        gw = _ip(info["gateway"])
        if gw:
            inside.add(gw)
        static_in_pool = []
        for a in sorted(inside):
            for p, ranges in pool_ranges:
                if _in_ranges(a, ranges) and lease_any.get(str(a)) != "bound" and str(a) != info["gateway"]:
                    static_in_pool.append({"ip": str(a), "pool": p["name"], "router": p["router"]})
                    break
        subnets.append({"network": n, "router": info["router"], "interface": info["interface"], "gateway": info["gateway"], "size": size,
                        "used": len(inside) if counted else None, "free": size - len(inside) if counted else None,
                        "pct": round(100.0 * len(inside) / size, 1) if counted and size else None,
                        "free_list": _free(net, inside) if counted else [], "static_in_pool": static_in_pool[:50],
                        "pools": [p["name"] for p, ranges in pool_ranges if any(lo in net for lo, _hi in ranges)]})
    subnets.sort(key=lambda s: ipaddress.ip_network(s["network"]))
    pools.sort(key=lambda p: (-(p["pct"] or 0), p["key"]))
    return {"subnets": subnets, "pools": pools, "conflicts": conflicts(per_router)}


# ── The pass ─────────────────────────────────────────────────────────────────

def _forecast(key: str, now: datetime) -> Optional[float]:
    from services import metrics
    t = metrics.trend(metrics.points(f"ipam:pool:{key}", FORECAST_DAYS, 2000, now))
    if (t.get("slope") or 0) >= 0.5 and (t.get("r2") or 0) >= metrics.MIN_R2 and t.get("span_days", 0) >= 2:
        return t.get("days_to_limit")
    return None


def _judge(res: dict, now: datetime) -> None:
    from services import soc
    bad_conf = {c["ip"]: c for c in res["conflicts"]}
    bad_pool = {}
    for p in res["pools"]:
        if not p["served"] or p["pct"] is None:
            continue
        d = p.get("days_to_full")
        if p["pct"] >= POOL_WARN or (d is not None and d <= FORECAST_DAYS):
            bad_pool[p["key"]] = p
    keys = {("net.ip_conflict", ip) for ip in bad_conf} | {("net.dhcp_pool", k) for k in bad_pool}
    for rule, k in keys:
        _streak[(rule, k)] = _streak.get((rule, k), 0) + 1
        if _streak[(rule, k)] < STREAK:
            continue
        first = _streak[(rule, k)] == STREAK
        if rule == "net.ip_conflict":
            c = bad_conf[k]
            soc.raise_alert(rule=rule, device=k, ip=k, title="IP address conflict", severity="medium", category="detection", fp_detail=k,
                            detail={"message": f"{k} is answered by {len(c['macs'])} MACs: {', '.join(c['macs'])} (seen by {', '.join(c['routers'])})",
                                    "description": "two devices use one address"}, count=1 if first else 0, source="rules", now=now)
        else:
            p = bad_pool[k]
            sev = "high" if p["pct"] >= POOL_CRIT else "medium"
            when = f", full in ~{p['days_to_full']:.0f} days" if p.get("days_to_full") is not None else ""
            soc.raise_alert(rule=rule, device=p["router"], title="DHCP pool running out", severity=sev, category="resource", fp_detail=k,
                            detail={"message": f"pool {p['name']} on {p['router']}: {p['bound']} of {p['size']} leased ({p['pct']}%){when}",
                                    "description": f"DHCP {p['name']}"}, count=1 if first else 0, source="rules", now=now)
    for (rule, k) in list(_streak):
        if (rule, k) not in keys:
            _streak.pop((rule, k), None)
            soc.resolve(rule=rule, device=k if rule == "net.ip_conflict" else k.split(":", 1)[0], fp_detail=k, now=now)
    # an alert open from before a restart (no streak here) is closed when its condition is gone
    with SessionLocal() as db:
        from models.database import SocAlert
        open_rows = db.execute(select(SocAlert).where(SocAlert.rule.in_(("net.ip_conflict", "net.dhcp_pool")), SocAlert.status.notin_(("closed", "false_positive")))).scalars().all()
        stale = [(a.rule, a.fingerprint.split("|", 2)[-1] if a.fingerprint else "", a.device_name) for a in open_rows]
    for rule, k, dev in stale:
        if k and (rule, k) not in keys:
            soc.resolve(rule=rule, device=dev, fp_detail=k, now=now)


async def run_cycle(now: Optional[datetime] = None) -> dict:
    from services import host_monitor, metrics
    started = _now()
    now = now or started
    devices = host_monitor._load_devices()
    sem = asyncio.Semaphore(3)

    async def one(d):
        async with sem:
            return await _read(d)
    reads = await asyncio.gather(*[one(d) for d in devices]) if devices else []
    with SessionLocal() as db:
        asset_ips = [a.ip for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all() if not a.state]
    res = build([r for r in reads if not r["error"]], asset_ips)
    with SessionLocal() as db:
        for p in res["pools"]:
            if p["served"] and p["pct"] is not None:
                metrics.record(f"ipam:pool:{p['key']}", p["pct"], name=f"DHCP {p['name']} ({p['router']})", kind="other", unit="%", now=now, db=db)
        db.commit()
    for p in res["pools"]:
        p["days_to_full"] = _forecast(p["key"], now) if p["served"] else None
    try:
        _judge(res, now)
    except Exception as e:
        print(f"[ipam] alerts error: {type(e).__name__}: {e}")
    errors = [{"router": r["dev"]["name"], "error": r["error"]} for r in reads if r["error"]]
    _last.update(at=_iso(_now()), routers=len(reads) - len(errors), errors=errors, duration_sec=round((_now() - started).total_seconds(), 1))
    _result.clear()
    _result.update(res, at=_iso(now))
    try:
        os.makedirs(os.path.dirname(_LAST_PATH), exist_ok=True)
        with open(_LAST_PATH, "w", encoding="utf-8") as f:
            json.dump({"result": res, "at": _iso(now), "last": _last}, f)
    except Exception as e:
        print(f"[ipam] could not keep the last pass: {e}")
    return {"routers": _last["routers"], "subnets": len(res["subnets"]), "pools": len(res["pools"]), "conflicts": len(res["conflicts"])}


def _load_last() -> None:
    if _result:
        return
    try:
        with open(_LAST_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        _result.update(saved.get("result") or {}, at=saved.get("at"))
        _last.update(saved.get("last") or {})
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[ipam] last pass unreadable: {e}")


def overview() -> dict:
    _load_last()
    return {"subnets": _result.get("subnets", []), "pools": _result.get("pools", []), "conflicts": _result.get("conflicts", []),
            "at": _result.get("at"), "last": dict(_last), "interval_sec": INTERVAL_SEC}


def public_summary() -> dict:
    """For Central: counts, the fullest subnets and pools (network and pool names, no host addresses), the number of conflicts."""
    o = overview()
    return {"subnets": len(o["subnets"]), "pools": len(o["pools"]), "conflicts": len(o["conflicts"]),
            "static_in_pool": sum(len(s["static_in_pool"]) for s in o["subnets"]),
            "full_subnets": [{"net": s["network"], "pct": s["pct"], "free": s["free"]} for s in sorted(o["subnets"], key=lambda s: -(s["pct"] or 0)) if (s["pct"] or 0) >= 80][:10],
            "full_pools": [{"n": p["name"], "r": p["router"], "pct": p["pct"], "size": p["size"], "days": p.get("days_to_full")} for p in o["pools"]
                           if p["served"] and ((p["pct"] or 0) >= 80 or p.get("days_to_full") is not None)][:10],
            "at": o["at"]}


async def _loop():
    await asyncio.sleep(180)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            _last["errors"] = [{"router": "-", "error": f"{type(e).__name__}: {e}"}]
            print(f"[ipam] cycle error: {e}")
        await asyncio.sleep(INTERVAL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None
