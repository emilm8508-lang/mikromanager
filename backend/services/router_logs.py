"""
Router logs: the detections over the structured lines of services/routeros_log.py, the same for both ways a line arrives (syslog, and the
log read over the RouterOS API by services/resource_monitor.py), plus whether each router sends its log to this agent at all.

Rules (each an alert of the router, merged while it repeats - one alert with a count, the latest line as a sample, the sources and users):
  login_failed      5 failed logins within 10 min (any service); 20+ or any from outside the management networks: high      T1110
  login_failed_outside  fewer than that, but from outside the management networks: one alert per router, counting     medium T1110
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


def _is_agent_logon(user: Optional[str], src_ip: Optional[str]) -> bool:
    """The agent's own login (services/logons.is_agent_logon): its account, not from the internet. 3.94.6: the account name alone is not
    enough - the agent's credentials are often "admin", and a login as admin from the internet is anything but the agent's."""
    if not user:
        return False
    try:
        from services import logons
        return logons.is_agent_logon(user, src_ip)
    except Exception:
        return False


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
    if p["kind"] in ("login_ok", "logout") and _is_agent_logon(p.get("user"), p.get("src_ip")):
        out["self"] = True                                    # the agent's own API / REST login (3.73): not a person's, no rule, no logon
        return out
    if p["kind"] in ("login_ok", "login_failed") and p.get("user"):
        try:                                                  # who logged on to the router (3.70: services/logons.py)
            from services import logons
            logons.record([{"host_ip": device_ip, "host_name": device, "user": p.get("user"), "logon_type": (p.get("service") or "").lower() or None,
                            "source_ip": p.get("src_ip"), "at": at, "result": "success" if p["kind"] == "login_ok" else "failure",
                            "source": "routeros_log"}])
        except Exception as e:
            print(f"[router_logs] logon record error: {type(e).__name__}: {e}")
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
        elif p.get("src_ip") and not in_mgmt(p["src_ip"], nets):
            # 3.94.6: a single failed login from outside the management networks. A slow guesser stays under 5 in 10 min for ever - seen
            # in production: admin via winbox from several internet addresses, one every day or two, not one alert. Each attempt counts
            # into one alert per router; that the service answers the internet at all is the finding.
            b = _bump("login_failed_outside", device, "", p, message, at)
            svc = ", ".join(sorted(b["services"])) or "router"
            raise_("login_failed_outside", f"Failed login from outside the management network ({svc})", "medium", "auth", "", b, "T1110",
                   {"from_outside": True, "exposed_services": sorted(b["services"])})
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


# 3.68: why a router's logging could not be read - before, one "unknown" list (sanmed R1 and psb PSB, the most important routers, in it)
# with nothing to act on
READ_REASONS = {
    "no_credential": "no credential assigned to the router",
    "credentials_rejected": "the router refused the user name / password",
    "no_api_permission": "the user may not read /system/logging (needs the read policy)",
    "timeout": "the router did not answer in time",
    "api_unreachable": "the API / REST service is off or filtered (connection refused / reset)",
    "no_rest_api_closed": "no REST on the router (RouterOS 6, or the www service answers without REST) and the API service (8728 / 8729) is off or filtered",
    "no_rest_api_timeout": "no REST on the router (RouterOS 6, or the www service answers without REST) and the API did not answer in time",
    "api_ssl_failed": "api-ssl (8729) failed the TLS handshake before (no certificate / no common cipher) and is not tried again for a while",
    "address_dead": "nothing answers at the address (no ping, no port) - the device may be gone or moved",
    "error": "another error (see the message)",
}


def _one(e: str) -> Optional[str]:
    """The reason one access method's error says, or None."""
    e = e.lower()
    if re.search(r"invalid user name or password|login failure|cannot log ?in|authenticat|\b401\b|unauthori", e):
        return "credentials_rejected"
    if re.search(r"not enough permissions|permission|policy|\b403\b|forbidden", e):
        return "no_api_permission"
    if "api-ssl previously failed" in e or re.search(r"ssl|tls|handshake|no common cipher", e):
        return "api_ssl_failed"
    if re.search(r"timeout|timed out", e):
        return "timeout"
    if re.search(r"refused|reset by peer|unreachable|no route|connecterror|connection aborted|errno 111|winerror 10061|10054|cannot connect", e):
        return "api_unreachable"
    return None


def _parts(err: str) -> Dict[str, str]:
    """"... REST: X | API: Y | SNMP: Z" (mikrotik_client._try_methods) -> {"rest": X, "api": Y, "snmp": Z}."""
    out: Dict[str, str] = {}
    for m in re.finditer(r"\b(REST|API|SNMP): (.*?)(?= \| (?:REST|API|SNMP): |$)", err or "", re.S):
        out[m.group(1).lower()] = m.group(2).strip()
    return out


def _rest_absent(rest: str) -> bool:
    """The REST answer says there is no REST here: a page instead of JSON (ContentTypeError: the www service of RouterOS 6, or webfig),
    404, or no answer from www at all - nothing to do with the credentials."""
    r = rest.lower()
    return bool(re.search(r"contenttypeerror|attempt to decode json|unexpected mimetype|\b404\b|not found|jsondecodeerror", r))


def explain_error(err: Optional[str]) -> Tuple[str, Optional[str]]:
    """(reason, the part of the message that says it) - 3.72. The message names each method that failed ("REST: ... | API: ..."); before,
    the whole text was matched at once and cut at 160 characters, so a REST answer that was a web page (ContentTypeError: 200 ... -
    seen on psb PSB and sanmed R4-S1, R4-S2, R4-S4, R4-S5) hid the API's reason and came out as "error". Now: what the API says
    decides; a REST that is not there only says the API is the way in."""
    e = err or ""
    parts = _parts(e)
    api, rest = parts.get("api"), parts.get("rest")
    if api is not None:
        r = _one(api)
        if rest is not None and _rest_absent(rest):
            if r in (None, "api_unreachable"):
                return "no_rest_api_closed", f"API: {api}"[:200]
            if r == "timeout":
                return "no_rest_api_timeout", f"API: {api}"[:200]
        if r:
            return r, f"API: {api}"[:200]
    if rest is not None:
        r = _one(rest)
        if r and r != "api_unreachable":
            return r, f"REST: {rest}"[:200]
        if _rest_absent(rest) and api is None:
            return "no_rest_api_closed", f"REST: {rest}"[:200]
    return (_one(e) or "error"), e[:200] or None


def classify_error(err: Optional[str]) -> str:
    return explain_error(err)[0]


def router_kind(d) -> Optional[str]:
    """None for a RouterOS device whose logging is checked; else why it is left out: "swos" (no API - a switch OS), "not_routeros" (a
    printer / another maker's device marked mikrotik). A device marked mikrotik without a version yet is checked (it may be a router
    nobody gave a credential)."""
    from services.vuln_scan import device_product
    from services import asset_type
    ident = device_product(d)
    if ident["product"] == "MikroTik RouterOS":
        return None
    if ident["product"] and "swos" in ident["product"].lower():
        return "swos"
    if ident["reason"] == "no version":
        return "not_routeros" if asset_type.printer_name(d.identity or d.name) else None
    if "SwOS" in (ident["reason"] or ""):
        return "swos"
    return "not_routeros"


def setup_script(agent_ip: Optional[str], firewall_logging: bool = False, action: str = "mikromanager", port: int = 514) -> str:
    """A RouterOS script that sends the log to this agent - for the administrator to copy (3.68). Never run by the application.
    Idempotent: the action and each rule are only added when missing."""
    target = agent_ip or "<AGENT-IP>"
    topics = ["system,!debug", "account", "critical", "error", "warning"] + (["firewall"] if firewall_logging else [])
    lines = [f"# MikroManager: send this router's log to the agent at {target} (UDP {port})",
             f':if ([:len [/system logging action find name="{action}"]] = 0) do={{ /system logging action add name={action} target=remote '
             f'remote={target} remote-port={port} bsd-syslog=no }} else={{ /system logging action set [find name="{action}"] remote={target} remote-port={port} }}']
    for t in topics:
        lines.append(f':if ([:len [/system logging find action="{action}" topics="{t}"]] = 0) do={{ /system logging add action={action} topics={t} }}')
    return "\n".join(lines)


async def check_logging() -> List[dict]:
    """Every RouterOS device: does it send its log to a remote syslog, and to this agent? Saved for the coverage and Central.
    3.68: a device without a credential is listed with that reason, a failure with its reason (READ_REASONS); SwOS switches and printers
    marked mikrotik are left out (counted in "skipped"); a router that does not send its log here gets the script to copy."""
    from sqlalchemy import select
    from models.database import SessionLocal, Device, Credential
    from services.device_client import build_client
    with SessionLocal() as db:
        devs = [d for d in db.execute(select(Device)).scalars().all() if (d.vendor or "mikrotik").lower() == "mikrotik"]
        creds = {c.id: c for c in db.execute(select(Credential)).scalars().all()}
    out = []
    skipped: Dict[str, List[str]] = {}
    rows = []
    for d in devs:
        kind = router_kind(d)
        if kind:
            skipped.setdefault(kind, []).append(d.identity or d.name or d.ip)
            continue
        rows.append((d, creds.get(d.credential_id) if d.credential_id else None))
    sem = asyncio.Semaphore(4)
    try:
        from services import syslog_receiver
        port = int(syslog_receiver.settings().get("syslog_port") or 514)
    except Exception:
        port = 514

    async def one(d, c):
        async with sem:
            name = d.identity or d.name or d.ip
            agent_ip = _agent_ip_for(d.ip)
            base = {"device_id": d.id, "name": name, "ip": d.ip, "agent_ip": agent_ip,
                    "last_ok": (d.version_seen_at.isoformat() + "Z") if getattr(d, "version_seen_at", None) else None}      # 3.75
            if c is None:
                out.append({**base, "remote": [], "to_agent": None, "topics": [], "error": None, "reason": "no_credential",
                            "script": setup_script(agent_ip, port=port)})
                return
            try:
                client = build_client(d, c)
                actions = await asyncio.wait_for(client._try_methods("system/logging/action", "/system/logging/action"), timeout=10)
                rules = await asyncio.wait_for(client._try_methods("system/logging", "/system/logging"), timeout=10)
                fw_log = False
                try:
                    fw = await asyncio.wait_for(client._try_methods("ip/firewall/filter", "/ip/firewall/filter"), timeout=10)
                    fw_log = any(str(r.get("log", "false")).lower() in ("true", "yes") and str(r.get("disabled", "false")).lower() not in ("true", "yes")
                                 for r in (fw if isinstance(fw, list) else []) if isinstance(r, dict))
                except Exception:
                    pass
                j = judge_logging(actions if isinstance(actions, list) else [], rules if isinstance(rules, list) else [], agent_ip)
                row = {**base, **j, "error": None, "reason": None, "firewall_logging": fw_log}
                try:                                          # 3.77: the agent's own account here - which group, full rights or not
                    from services import agent_self
                    users = await asyncio.wait_for(client._try_methods("user", "/user"), timeout=10)
                    groups = await asyncio.wait_for(client._try_methods("user/group", "/user/group"), timeout=10)
                    me = next((u for u in (users or []) if isinstance(u, dict) and str(u.get("name") or "").lower() == (c.username or "").lower()), None)
                    if me:
                        g = next((x for x in (groups or []) if isinstance(x, dict) and x.get("name") == me.get("group")), {})
                        row.update(agent_user=me.get("name"), agent_group=me.get("group"),
                                   agent_full=agent_self.full_rights(me.get("group"), g.get("policy")),
                                   agent_address_limited=bool(str(me.get("address") or "").strip()))
                except Exception:
                    pass
                if not j["to_agent"]:
                    row["reason"] = "sends_elsewhere" if j["remote"] else "not_configured"
                    row["script"] = setup_script(agent_ip, fw_log, port=port)
                out.append(row)
            except Exception as e:
                err = f"{type(e).__name__}: {e}"[:1200]                 # whole: the API's part comes after the REST one
                reason, said = explain_error(err)
                if reason in ("timeout", "api_unreachable", "no_rest_api_closed", "no_rest_api_timeout", "error") and d.online is False:
                    reason = "address_dead"                          # 3.75: nothing answers at the address (the liveness check says so)
                out.append({**base, "remote": [], "to_agent": None, "topics": [], "error": said, "reason": reason,
                            "script": setup_script(agent_ip, port=port)})

    await asyncio.gather(*[one(d, c) for d, c in rows])
    _write(_LOGGING_PATH, {"at": datetime.utcnow().isoformat() + "Z", "routers": out, "skipped": skipped})
    return out


def _agent_logins() -> dict:
    try:
        from services import agent_self
        return agent_self.logins()
    except Exception:
        return {}


def logging_status() -> dict:
    try:
        with open(_LOGGING_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"at": None, "routers": []}


def public_summary() -> dict:
    st = logging_status()
    rs = st.get("routers") or []
    scripts: Dict[str, dict] = {}
    for r in rs:
        if r.get("script") and not r.get("to_agent"):
            s = scripts.setdefault(r.get("agent_ip") or "?", {"agent_ip": r.get("agent_ip"), "routers": [], "script": r["script"]})
            s["routers"].append(r["name"])
            if r.get("firewall_logging"):
                s["script"] = r["script"]                       # the variant with the firewall topic
    return {"at": st.get("at"), "routers": len(rs), "to_agent": sum(1 for r in rs if r.get("to_agent")),
            "not_sending": [r["name"] for r in rs if r.get("to_agent") is False][:40], "unknown": [r["name"] for r in rs if r.get("to_agent") is None][:40],
            # 3.68: why each could not be read / does not send, what was left out, and the script to copy
            "why": [{"n": r["name"], "r": r.get("reason"), "e": (r.get("error") or "")[:120] or None, "ok": r.get("last_ok")}
                    for r in rs if not r.get("to_agent")][:60],
            "skipped": {k: len(v) for k, v in (st.get("skipped") or {}).items()},
            # 3.77: routers where the agent's account has full rights (it only needs read, api, rest-api) - and the agent's own logins
            "agent_full_rights": [r["name"] for r in rs if r.get("agent_full")][:60],
            "agent_account_checked": sum(1 for r in rs if r.get("agent_group")),
            "agent_logins": _agent_logins(),
            "scripts": [{"agent_ip": s["agent_ip"], "routers": s["routers"][:40], "script": s["script"]} for s in scripts.values()][:5],
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
