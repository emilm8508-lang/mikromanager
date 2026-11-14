"""
Router logs: the detections over the structured lines of services/routeros_log.py, the same for both ways a line arrives (syslog, and the
log read over the RouterOS API by services/resource_monitor.py), plus whether each router sends its log to this agent at all.

Rules (each an alert of the router, merged while it repeats - one alert with a count, the latest line as a sample, the sources and users):
  login_failed      5 failed logins within 10 min (any service); 20+ or any from outside the management networks: high      T1110
  login_outside     a successful login from outside the management networks (a public address)                        high   T1078
  login_new_source  a successful login of a user from an address it has not used on this router in 90 days           medium T1078
  config_change     "added / changed / removed by" - who, from where, what (one alert per router, counting)           low
  reboot            a restart; after a power loss (no proper shutdown) medium; a power supply failing high
  ipsec_from_outside IKE negotiations failing from internet addresses (10 within an hour): the sources with their owner;
                    a known internet scanner (Shodan, Censys, Shadowserver, Palo Alto Xpanse ...) is "scanner", severity info T1595
  winbox_denied     5 refused management connections within 10 min, the sources with their owner                         T1595
  tls_failed        "ssl: no common ciphers" carries no address: matched with this agent's own connections to the router
                    (seen in production: the agent's api-ssl tries, once an hour - fixed in 3.61, see mikrotik_client) and
                    with NetFlow; the alert says who it was, or that nobody could be found
WAN / uplink link down is decided in services/syslog_receiver.py with the interface's role (services/iface_roles.py).

The same line read twice (by syslog and by the API) counts once. Owners of public addresses come from RDAP (cached 30 days in
data/ip_owner.json, looked up in the background - an alert first shows the address, its owner once known); RDAP can be switched off.
"""
import asyncio
import ipaddress
import json
import os
import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from services import routeros_log

_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_SETTINGS_PATH = os.path.join(_DIR, "router_logs.json")
_LOGINS_PATH = os.path.join(_DIR, "router_logins.json")
_OWNER_PATH = os.path.join(_DIR, "ip_owner.json")
_LOGGING_PATH = os.path.join(_DIR, "router_logging.json")
DEFAULTS = {"mgmt_nets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"], "rdap": True}
OWNER_TTL_DAYS = 30
NEW_SOURCE_DAYS = 90

# Well-known internet scanners (published by their operators). The owner looked up over RDAP is checked against SCANNER_NAMES as well.
SCANNER_NETS = [("Palo Alto Networks (Cortex Xpanse)", n) for n in ("147.185.132.0/23", "198.235.24.0/24", "205.210.31.0/24")] + \
               [("Shadowserver", n) for n in ("184.105.139.0/24", "184.105.247.0/24", "74.82.47.0/24", "65.49.1.0/24", "216.218.206.0/24")] + \
               [("Censys", n) for n in ("162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24", "167.94.146.0/24", "206.168.32.0/22")]
SCANNER_NAMES = re.compile(r"censys|shodan|shadowserver|palo alto|expanse|binaryedge|onyphe|stretchoid|internet[- ]measurement|leakix|"
                           r"criminal ?ip|driftnet|recyber|cyble|bitsight|rapid7|project sonar|alpha strike|netsystemsresearch|ipip\.net", re.I)

_windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
_agg: Dict[Tuple[str, str, str], dict] = {}
_seen_lines: Dict[Tuple[str, str], float] = {}
_owner_cache: Dict[str, dict] = {}
_owner_queue: Optional[asyncio.Queue] = None
_logins: Dict[str, Dict[str, str]] = {}
_logins_loaded = [False]
_stats = Counter()
_task: Optional[asyncio.Task] = None


def settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_SETTINGS_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved.get("mgmt_nets"), list):
            nets = []
            for n in saved["mgmt_nets"]:
                try:
                    nets.append(str(ipaddress.ip_network(str(n), strict=False)))
                except ValueError:
                    continue
            s["mgmt_nets"] = nets or s["mgmt_nets"]
        s["rdap"] = bool(saved.get("rdap", True))
    except (OSError, ValueError):
        pass
    return s


def update_settings(new: dict) -> dict:
    s = settings()
    if "mgmt_nets" in new:
        nets = []
        for n in new["mgmt_nets"] or []:
            try:
                nets.append(str(ipaddress.ip_network(str(n).strip(), strict=False)))
            except ValueError:
                raise ValueError(f"not a network: {n}")
        if not nets:
            raise ValueError("at least one management network")
        s["mgmt_nets"] = nets
    if "rdap" in new:
        s["rdap"] = bool(new["rdap"])
    _write(_SETTINGS_PATH, s)
    return s


def _write(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def in_mgmt(ip: Optional[str], nets: Optional[List[str]] = None) -> bool:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return True                                      # no address (local console): not "outside"
    return any(a in ipaddress.ip_network(n, strict=False) for n in (nets or settings()["mgmt_nets"]))


# ── who is behind an address ─────────────────────────────────────────────────

def _load_owners() -> None:
    if _owner_cache:
        return
    try:
        with open(_OWNER_PATH, encoding="utf-8") as f:
            _owner_cache.update(json.load(f))
    except (OSError, ValueError):
        pass


def owner(ip: Optional[str]) -> Optional[dict]:
    """{"owner", "country", "scanner": name|None, "source": list|rdap} for a public address when known; queues an RDAP lookup otherwise."""
    if not ip or routeros_log.is_private(ip):
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in SCANNER_NETS:
        if a in ipaddress.ip_network(net):
            return {"owner": name, "country": None, "scanner": name, "source": "list"}
    _load_owners()
    o = _owner_cache.get(ip)
    if o and (time.time() - o.get("at", 0)) < OWNER_TTL_DAYS * 86400:
        return {k: o.get(k) for k in ("owner", "country", "scanner")} | {"source": "rdap"}
    if _owner_queue is not None and settings()["rdap"]:
        try:
            _owner_queue.put_nowait(ip)
        except asyncio.QueueFull:
            pass
    return None


def parse_rdap(data: dict) -> dict:
    """The network's name / holder and country from an RDAP "ip network" answer."""
    names = [str(data.get("name") or "")]
    for e in data.get("entities") or []:
        if not isinstance(e, dict):
            continue
        for item in ((e.get("vcardArray") or [None, []])[1] or []):
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and item[3]:
                names.append(str(item[3]))
        for r in e.get("remarks") or []:
            if isinstance(r, dict):
                names.extend(str(d) for d in (r.get("description") or [])[:1])
    holder = next((n for n in names[1:] if n and n.strip()), None) or names[0] or None
    blob = " ".join(names)
    m = SCANNER_NAMES.search(blob)
    return {"owner": (holder or "")[:120] or None, "country": data.get("country"), "scanner": m.group(0) if m else None}


async def _owner_worker() -> None:
    import aiohttp
    while True:
        ip = await _owner_queue.get()
        _load_owners()
        o = _owner_cache.get(ip)
        if o and (time.time() - o.get("at", 0)) < OWNER_TTL_DAYS * 86400:
            continue
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                async with s.get(f"https://rdap.org/ip/{ip}", headers={"Accept": "application/rdap+json"}) as r:
                    data = await r.json(content_type=None) if r.status == 200 else {}
            info = parse_rdap(data) if isinstance(data, dict) and data else {"owner": None, "country": None, "scanner": None}
        except Exception as e:
            info = {"owner": None, "country": None, "scanner": None, "error": f"{type(e).__name__}"}
        _owner_cache[ip] = {**info, "at": time.time()}
        if len(_owner_cache) > 5000:
            for k in sorted(_owner_cache, key=lambda k: _owner_cache[k].get("at", 0))[:1000]:
                _owner_cache.pop(k, None)
        try:
            _write(_OWNER_PATH, _owner_cache)
        except OSError:
            pass
        await asyncio.sleep(1.5)                          # RDAP servers limit the rate


def describe(ip: Optional[str]) -> Optional[str]:
    o = owner(ip)
    if not o:
        return ip
    tag = " [scanner]" if o.get("scanner") else ""
    return f"{ip} ({o.get('owner') or '?'}{', ' + o['country'] if o.get('country') else ''}){tag}"


# ── who caused a line without an address ─────────────────────────────────────

def self_connections(device_ips: List[str], at: datetime, window_sec: float) -> List[dict]:
    """This agent's own connections to the router (services/mikrotik_client.py keeps them) around `at`."""
    try:
        from services import mikrotik_client
        log = list(mikrotik_client._ACCESS_LOG)
    except Exception:
        return []
    out = []
    for e in log:
        if e.get("ip") in device_ips and abs((e["at"] - at).total_seconds()) <= window_sec:
            out.append({"kind": e.get("kind"), "origin": e.get("origin"), "at": e["at"].isoformat() + "Z"})
    return out


def netflow_sources(device_ips: List[str], at: datetime, window_sec: float, ports: Tuple[int, ...]) -> List[str]:
    try:
        from services import netflow
        return netflow.mgmt_sources(device_ips, (at - datetime(1970, 1, 1)).total_seconds(), window_sec, ports)     # `at` is naive UTC
    except Exception:
        return []


# ── the rules ────────────────────────────────────────────────────────────────

def _hit(key: Tuple[str, str], window: int, now: float) -> int:
    q = _windows[key]
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    return len(q)


def _bump(rule: str, device: str, key: str, p: dict, message: str, now: datetime) -> dict:
    a = _agg.setdefault((rule, device, key), {"count": 0, "sources": Counter(), "users": Counter(), "services": Counter(), "first": now})
    a["count"] += 1
    a["last"], a["sample"] = now, message[:300]
    if p.get("src_ip"):
        a["sources"][p["src_ip"]] += 1
    if p.get("user"):
        a["users"][p["user"]] += 1
    if p.get("service"):
        a["services"][p["service"]] += 1
    return a


def _detail(a: dict, extra: Optional[dict] = None) -> dict:
    srcs = [{"ip": ip, "n": n, "who": describe(ip)} for ip, n in a["sources"].most_common(10)]
    d = {"message": a["sample"], "count": a["count"], "first": a["first"].isoformat() + "Z", "last": a["last"].isoformat() + "Z",
         "sources": [s["who"] for s in srcs], "users": [u for u, _ in a["users"].most_common(10)], "services": sorted(a["services"])}
    if extra:
        d.update(extra)
    return d


def _loaded_logins() -> Dict[str, Dict[str, str]]:
    if not _logins_loaded[0]:
        try:
            with open(_LOGINS_PATH, encoding="utf-8") as f:
                _logins.update(json.load(f))
        except (OSError, ValueError):
            pass
        _logins_loaded[0] = True
    return _logins


# builtin syslog rules this module replaces for the lines it understands (services/syslog_receiver.py skips them then)
REPLACES = {"login_failed": "auth_failure", "config_change": "config_change", "reboot": "restart", "power_fail": "restart", "psu_fail": "restart",
            "ipsec_fail": "ipsec_probe", "ipsec_respond": "ipsec_probe", "winbox_denied": "winbox_denied"}


def handle(*, device: str, device_ip: str, message: str, app: Optional[str] = None, asset_id: Optional[int] = None, via: str = "syslog",
           at: Optional[datetime] = None, device_ips: Optional[List[str]] = None, now: Optional[float] = None) -> dict:
    """One router log line through the rules. Returns {"parsed", "raised": [rule ids], "skip_builtin": {ids}, "duplicate": bool}."""
    from services import soc
    now = now or time.time()
    at = at or datetime.utcnow()
    p = routeros_log.parse(message, app)
    out = {"parsed": p, "raised": [], "skip_builtin": set(), "duplicate": False}
    if p["kind"] in REPLACES:
        out["skip_builtin"].add(REPLACES[p["kind"]])
    # The same line arriving the other way (syslog and the API read of the log) within 10 min counts once; repeats on one way are real
    # repeats (a password guesser writes the very same line again and again) and all count.
    dkey = (device_ip, message.strip())
    seen = _seen_lines.setdefault(dkey, {"syslog": [], "api": []})
    for w in seen.values():
        w[:] = [t for t in w if now - t < 600]
    mine, other = seen.setdefault(via, []), seen["api" if via == "syslog" else "syslog"]
    if len(other) > len(mine):
        mine.append(now)
        out["duplicate"] = True
        return out
    mine.append(now)
    if len(_seen_lines) > 20000:
        for k in [k for k, v in _seen_lines.items() if not any(v.values())][:10000]:
            _seen_lines.pop(k, None)
    _stats[p["kind"]] += 1
    ips = device_ips or [device_ip]
    nets = settings()["mgmt_nets"]

    def raise_(rule, title, sev, cat, key, a, mitre=None, extra=None):
        soc.raise_alert(rule=f"routerlog.{rule}", device=device, title=title, severity=sev, category=cat, fp_detail=key, ip=device_ip,
                        detail=_detail(a, extra), mitre=mitre, source="syslog", asset_id=asset_id, now=at)
        out["raised"].append(rule)

    k = p["kind"]
    if k == "login_failed":
        a = _bump("login_failed", device, "", p, message, at)
        n = _hit(("login_failed", device_ip), 600, now)
        if n >= 5:
            outside = any(not in_mgmt(ip, nets) for ip in a["sources"])
            raise_("login_failed", f"Failed logins ({', '.join(sorted(a['services'])) or 'router'})", "high" if (n >= 20 or outside) else "medium",
                   "auth", "", a, "T1110", {"in_10_min": n, "from_outside": outside})
    elif k == "login_ok" and p.get("user"):
        logins = _loaded_logins()
        key = f"{device_ip}|{p['user']}"
        known = logins.setdefault(key, {})
        src = p.get("src_ip") or "local"
        cutoff = (datetime.utcnow() - timedelta(days=NEW_SOURCE_DAYS)).isoformat()
        is_new = src not in known or known[src] < cutoff
        had_history = bool(known)
        known[src] = datetime.utcnow().isoformat()
        try:
            _write(_LOGINS_PATH, logins)
        except OSError:
            pass
        if p.get("src_ip") and not in_mgmt(p["src_ip"], nets):
            a = _bump("login_outside", device, f"{p['user']}|{src}", p, message, at)
            raise_("login_outside", f"Login from outside the management network: {p['user']}", "high", "auth", f"{p['user']}|{src}", a, "T1078")
        elif is_new and had_history:
            a = _bump("login_new_source", device, f"{p['user']}|{src}", p, message, at)
            raise_("login_new_source", f"Login from a new address: {p['user']}", "medium", "auth", f"{p['user']}|{src}", a, "T1078")
    elif k == "config_change":
        a = _bump("config_change", device, "", p, message, at)
        raise_("config_change", "Configuration changed", "low", "system", "", a, None, {"by": p.get("user"), "from": describe(p.get("src_ip"))})
    elif k in ("reboot", "power_fail", "psu_fail"):
        a = _bump(k, device, "", p, message, at)
        title, sev = {"reboot": ("Router restarted", "low"), "power_fail": ("Router restarted after a power loss", "medium"),
                      "psu_fail": ("Power supply failure", "high")}[k]
        raise_(k, title, sev, "hardware" if k != "reboot" else "system", p.get("interface") or "", a)
    elif k in ("ipsec_fail", "ipsec_respond"):
        if p.get("src_ip") and not routeros_log.is_private(p["src_ip"]):
            o = owner(p["src_ip"])
            scanner = bool(o and o.get("scanner"))
            key = "scanner" if scanner else "other"
            a = _bump("ipsec_from_outside", device, key, p, message, at)
            n = _hit((f"ipsec|{key}", device_ip), 3600, now)
            if n >= 10:
                raise_("ipsec_from_outside", "IPsec negotiations from known scanners" if scanner else "IPsec negotiations from outside",
                       "info" if scanner else ("medium" if n >= 50 else "low"), "network", key, a, "T1595",
                       {"in_hour": n, "scanner": scanner, "local_address": p.get("dst_ip")})
    elif k == "winbox_denied":
        a = _bump("winbox_denied", device, "", p, message, at)
        n = _hit(("winbox_denied", device_ip), 600, now)
        if n >= 5:
            outside = any(not in_mgmt(ip, nets) for ip in a["sources"])
            raise_("winbox_denied", "Refused management connections", "medium" if outside else "low", "network", "", a, "T1595",
                   {"in_10_min": n, "from_outside": outside})
    elif k == "ssl_no_cipher":
        window = 900 if via == "syslog" else 4200            # a line read over the API may be up to an hour old when it is read
        mine = self_connections(ips, at, window)
        flows = netflow_sources(ips, at, 600, (443, 8443, 8729, 993, 995))
        for f in flows:
            p.setdefault("candidates", []).append(f)
        if flows and not p.get("src_ip"):
            p["src_ip"] = flows[0]
        a = _bump("tls_failed", device, "self" if mine and not flows else "other", p, message, at)
        if mine and not flows:
            kinds = sorted({m["kind"] or "?" for m in mine})
            raise_("tls_failed", "TLS handshake failed: this agent's own connection", "info", "system", "self", a, None,
                   {"caused_by": f"this agent ({', '.join(kinds)}; {mine[-1].get('origin')})",
                    "advice": "RouterOS api-ssl without a certificate offers only anonymous (ADH) ciphers; 3.61 offers them too"})
        else:
            raise_("tls_failed", "TLS handshake failed", "low", "network", "other", a, None,
                   {"caused_by": ", ".join(describe(x) or x for x in flows[:5]) if flows else "unknown - no NetFlow record and no connection of this agent at that time"})
    return out


# ── does the router send its log here? ───────────────────────────────────────

def _agent_ip_for(device_ip: str) -> Optional[str]:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((device_ip, 514))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def judge_logging(actions: List[dict], rules: List[dict], agent_ip: Optional[str]) -> dict:
    """{"remote": [addresses], "to_agent": bool, "topics": [...]} from /system/logging/action and /system/logging."""
    remote = {}
    for a in actions or []:
        if str(a.get("target") or "").lower() == "remote" and a.get("remote"):
            remote[str(a.get("name") or "")] = str(a["remote"]).split(":")[0]
    topics = []
    used = set()
    for r in rules or []:
        if str(r.get("disabled", "false")).lower() in ("true", "yes"):
            continue
        act = str(r.get("action") or "")
        if act in remote:
            used.add(act)
            topics.append(str(r.get("topics") or ""))
    addrs = sorted({remote[a] for a in used})
    return {"remote": addrs, "to_agent": bool(agent_ip and agent_ip in addrs), "topics": topics, "agent_ip": agent_ip}


async def check_logging() -> List[dict]:
    """Every MikroTik with a credential: does it send its log to a remote syslog, and to this agent? Saved for the coverage and Central."""
    from sqlalchemy import select
    from models.database import SessionLocal, Device, Credential
    from services.device_client import build_client
    with SessionLocal() as db:
        rows = db.execute(select(Device, Credential).join(Credential, Device.credential_id == Credential.id)).all()
        rows = [(d, c) for d, c in rows if (d.vendor or "mikrotik").lower() == "mikrotik"]
    out = []
    sem = asyncio.Semaphore(4)

    async def one(d, c):
        async with sem:
            name = d.identity or d.name or d.ip
            try:
                client = build_client(d, c)
                actions = await asyncio.wait_for(client._try_methods("system/logging/action", "/system/logging/action"), timeout=10)
                rules = await asyncio.wait_for(client._try_methods("system/logging", "/system/logging"), timeout=10)
                j = judge_logging(actions if isinstance(actions, list) else [], rules if isinstance(rules, list) else [], _agent_ip_for(d.ip))
                out.append({"device_id": d.id, "name": name, "ip": d.ip, **j, "error": None})
            except Exception as e:
                out.append({"device_id": d.id, "name": name, "ip": d.ip, "remote": [], "to_agent": None, "topics": [], "error": f"{type(e).__name__}: {e}"[:160]})

    await asyncio.gather(*[one(d, c) for d, c in rows])
    _write(_LOGGING_PATH, {"at": datetime.utcnow().isoformat() + "Z", "routers": out})
    return out


def logging_status() -> dict:
    try:
        with open(_LOGGING_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"at": None, "routers": []}


def public_summary() -> dict:
    st = logging_status()
    rs = st.get("routers") or []
    return {"at": st.get("at"), "routers": len(rs), "to_agent": sum(1 for r in rs if r.get("to_agent")),
            "not_sending": [r["name"] for r in rs if r.get("to_agent") is False][:40], "unknown": [r["name"] for r in rs if r.get("to_agent") is None][:40],
            "lines": dict(_stats)}


async def _loop() -> None:
    await asyncio.sleep(300)
    while True:
        try:
            await check_logging()
        except Exception as e:
            print(f"[router_logs] logging check error: {type(e).__name__}: {e}")
        await asyncio.sleep(6 * 3600)


def start() -> None:
    global _task, _owner_queue
    if _owner_queue is None:
        _owner_queue = asyncio.Queue(maxsize=500)
        asyncio.get_event_loop().create_task(_owner_worker())
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())
