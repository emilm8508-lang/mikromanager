"""
Syslog and SNMP trap receiver: events from the devices that cannot run an agent.

A switch, a printer, a UPS, a firewall or a router of another make cannot be asked questions, but it can tell: syslog says what it logs (a failed login,
a link going down, a configuration change), an SNMP trap says that something happened (linkDown, coldStart, a vendor alarm). This module listens for both
(UDP; off until switched on in the application), recognises what matters and hands it to the SOC layer:

  * the sender must be a device the agent knows (an inventory asset or a managed device) - anything else is only counted ("unknown sources"), so the port
    is not a way to write into the alert queue; every source is rate limited;
  * every message is parsed (RFC 3164 / RFC 5424 syslog, the RouterOS "topics message" form; SNMP v1 and v2c traps - v3 needs the keys of the device and
    is reported as unsupported), the interesting ones are kept in `syslog_events` (14 days, at most 30 000 rows; info is only counted unless asked for);
  * detections (below, plus the user's own patterns): repeated failed logins, a link down - closed by its "link up" - a configuration change, a restart,
    anything critical; each becomes an alert of the source device, merged while it repeats.

The trap decoder is written from RFC 3416 / ITU X.690 (BER), nothing more is needed for v1/v2c.
"""
import asyncio
import json
import os
import re
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from sqlalchemy import select, delete, func

from models.database import SessionLocal, SyslogEvent, Asset, Device

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "syslog.json")
DEFAULTS = {"enabled": False, "syslog_port": 514, "trap_port": 162, "accept_unknown": False, "store_info": False, "communities": [], "rules": [], "disabled": []}
KEEP_DAYS = 14
KEEP_ROWS = 30000
RATE_MAX = 200                    # messages per source per RATE_WINDOW seconds; more are dropped (and counted)
RATE_WINDOW = 10
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
SEV_SOC = {"low", "medium", "high", "critical"}

_settings: Dict = dict(DEFAULTS)
_transports: Dict[str, asyncio.DatagramTransport] = {}
_queue: Optional[asyncio.Queue] = None
_tasks: List[asyncio.Task] = []
_errors: Dict[str, Optional[str]] = {"syslog": None, "trap": None}
_stats = {"received": 0, "stored": 0, "unknown": 0, "rate_dropped": 0, "bad": 0, "traps": 0, "v3": 0, "bad_community": 0, "since": None}
_unknown: Dict[str, int] = defaultdict(int)
_rate: Dict[str, Deque[float]] = defaultdict(deque)
_known_cache: Dict = {"at": 0.0, "ips": {}}
_windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)       # (rule id, source ip) -> times of the matches
_last_prune = [0.0]


# ── Settings ─────────────────────────────────────────────────────────────────

def load_settings() -> Dict:
    s = dict(DEFAULTS)
    try:
        with open(_PATH, encoding="utf-8") as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except Exception:
        pass
    _settings.clear()
    _settings.update(s)
    return _settings


def _save() -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f, ensure_ascii=False)
    os.replace(tmp, _PATH)


def settings() -> Dict:
    return {**{k: v for k, v in _settings.items() if k != "communities"}, "communities": len(_settings.get("communities") or [])}


def _port(v, default: int) -> int:
    try:
        p = int(v)
    except (TypeError, ValueError):
        raise ValueError("port must be a number")
    if not (1 <= p <= 65535):
        raise ValueError("port must be between 1 and 65535")
    return p


async def update_settings(body: Dict) -> Dict:
    """Changes the settings and re-opens the ports. Raises ValueError for a bad value."""
    new = dict(_settings)
    for k in ("enabled", "accept_unknown", "store_info"):
        if k in body and body[k] is not None:
            new[k] = bool(body[k])
    for k in ("syslog_port", "trap_port"):
        if body.get(k) is not None:
            new[k] = _port(body[k], DEFAULTS[k])
    if new["syslog_port"] == new["trap_port"]:
        raise ValueError("syslog and trap ports must differ")
    if body.get("communities") is not None:
        coms = [str(c).strip() for c in body["communities"] if str(c).strip()]
        if len(coms) > 20 or any(len(c) > 64 for c in coms):
            raise ValueError("at most 20 communities of 64 characters")
        new["communities"] = coms
    if body.get("rules") is not None:
        new["rules"] = _clean_rules(body["rules"])
    if body.get("disabled") is not None:
        new["disabled"] = [str(x) for x in body["disabled"]][:50]
    _settings.clear()
    _settings.update(new)
    _save()
    await restart()
    return settings()


def _clean_rules(rules) -> List[dict]:
    out = []
    for i, r in enumerate(list(rules)[:50]):
        name = str(r.get("name") or "").strip()[:80]
        pat = str(r.get("pattern") or "").strip()[:300]
        if not name or not pat:
            raise ValueError("a rule needs a name and a pattern")
        try:
            re.compile(pat, re.I)
        except re.error as e:
            raise ValueError(f"rule '{name}': bad pattern ({e})")
        sev = str(r.get("severity") or "medium")
        if sev not in SEV_SOC:
            raise ValueError("severity must be low, medium, high or critical")
        src = str(r.get("source") or "any")
        out.append({"id": f"c{i + 1}", "name": name, "pattern": pat, "severity": sev, "source": src if src in ("any", "syslog", "trap") else "any",
                    "threshold": max(1, min(int(r.get("threshold") or 1), 1000)), "window_sec": max(10, min(int(r.get("window_sec") or 300), 86400)),
                    "enabled": bool(r.get("enabled", True))})
    return out


# ── Syslog parsing ───────────────────────────────────────────────────────────

_RE_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)
_RE_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[[^\]]*\])+)\s*(.*)$", re.S)
_RE_3164 = re.compile(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (\S+) (.*)$", re.S)
_RE_TAG = re.compile(r"^([\w\-./]{1,48})(?:\[\d+\])?: (.*)$", re.S)
_RE_TOPICS = re.compile(r"^([a-z][\w-]*(?:,[\w-]+)+) (.*)$", re.S)


def parse_syslog(data: bytes) -> Optional[dict]:
    """{facility, severity (0-7), host, app, message} or None for an empty datagram."""
    text = data.decode("utf-8", "replace").replace("\x00", "").strip()
    if not text:
        return None
    facility, severity = None, 6
    m = _RE_PRI.match(text)
    if m:
        pri = int(m.group(1))
        if pri < 192:
            facility, severity, text = pri >> 3, pri & 7, m.group(2).lstrip()
    host = app = None
    m5 = _RE_5424.match(text)
    if m5:
        host, app = (m5.group(2) if m5.group(2) != "-" else None), (m5.group(3) if m5.group(3) != "-" else None)
        text = m5.group(6)
    else:
        m3 = _RE_3164.match(text)
        if m3:
            host, text = m3.group(1), m3.group(2)
        mt = _RE_TAG.match(text)
        if mt:
            app, text = mt.group(1), mt.group(2)
        else:
            mp = _RE_TOPICS.match(text)           # RouterOS: "system,info,account user admin logged in"
            if mp:
                app, text = mp.group(1), mp.group(2)
    return {"facility": facility, "severity": severity, "host": host, "app": app, "message": text.strip()[:1000]}


# ── SNMP trap decoding (BER, v1 / v2c) ───────────────────────────────────────

class _BerError(ValueError):
    pass


def _tlv(b: bytes, i: int) -> Tuple[int, bytes, int]:
    if i + 2 > len(b):
        raise _BerError("truncated")
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > len(b):
            raise _BerError("bad length")
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise _BerError("truncated value")
    return tag, b[i:i + n], i + n


def _children(b: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b):
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def _int(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=True) if v else 0


def _oid(v: bytes) -> str:
    if not v:
        return ""
    parts = [str(v[0] // 40), str(v[0] % 40)]
    n = 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def _value(tag: int, v: bytes) -> str:
    if tag == 0x02:
        return str(_int(v))
    if tag == 0x04:
        if all(32 <= c < 127 or c in (9, 10, 13) for c in v):
            return v.decode("ascii")
        return v.hex()
    if tag == 0x05:
        return ""
    if tag == 0x06:
        return _oid(v)
    if tag == 0x40 and len(v) == 4:
        return ".".join(str(c) for c in v)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(v, "big"))
    return v.hex()


GENERIC_TRAPS = {0: "1.3.6.1.6.3.1.1.5.1", 1: "1.3.6.1.6.3.1.1.5.2", 2: "1.3.6.1.6.3.1.1.5.3", 3: "1.3.6.1.6.3.1.1.5.4", 4: "1.3.6.1.6.3.1.1.5.5", 5: "1.3.6.1.6.3.1.1.5.6"}
TRAP_NAMES = {"1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown", "1.3.6.1.6.3.1.1.5.4": "linkUp",
              "1.3.6.1.6.3.1.1.5.5": "authenticationFailure", "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss"}
_OID_TRAP = "1.3.6.1.6.3.1.1.4.1.0"
_OID_UPTIME = "1.3.6.1.2.1.1.3.0"


def decode_trap(data: bytes) -> Optional[dict]:
    """{version, community, oid, name, varbinds: [(oid, value)], agent} of an SNMPv1 trap / v2c trap or inform; {'version': 3, ...} for v3 (not decoded);
    None when it is not an SNMP message."""
    try:
        tag, body, _ = _tlv(data, 0)
        if tag != 0x30:
            return None
        parts = _children(body)
        if len(parts) < 3 or parts[0][0] != 0x02:
            return None
        version = _int(parts[0][1])
        if version == 3:
            return {"version": 3, "community": None, "oid": None, "name": None, "varbinds": [], "agent": None}
        if version not in (0, 1) or parts[1][0] != 0x04:
            return None
        community = parts[1][1].decode("utf-8", "replace")
        ptag, pval = parts[2]
        fields = _children(pval)
        agent = None
        if ptag == 0xA4:                                     # v1 Trap-PDU: enterprise, agent-addr, generic, specific, time-stamp, varbinds
            enterprise = _oid(fields[0][1])
            agent = _value(fields[1][0], fields[1][1])
            generic, specific = _int(fields[2][1]), _int(fields[3][1])
            oid = GENERIC_TRAPS.get(generic) if generic != 6 else f"{enterprise}.0.{specific}"
            vb = fields[5][1]
        elif ptag in (0xA7, 0xA6):                           # v2c SNMPv2-Trap / InformRequest: request-id, error, error-index, varbinds
            vb = fields[3][1]
            oid = None
        else:
            return None
        varbinds = []
        for t, v in _children(vb):
            if t != 0x30:
                continue
            ch = _children(v)
            if len(ch) == 2 and ch[0][0] == 0x06:
                varbinds.append((_oid(ch[0][1]), _value(ch[1][0], ch[1][1])))
        if oid is None:
            oid = next((v for k, v in varbinds if k == _OID_TRAP), "") or ""
        return {"version": version + 1 if version == 1 else 1, "snmp_version": "v2c" if version == 1 else "v1", "community": community, "oid": oid,
                "name": TRAP_NAMES.get(oid), "varbinds": [(k, v) for k, v in varbinds if k not in (_OID_TRAP, _OID_UPTIME)], "agent": agent}
    except (_BerError, IndexError, ValueError):
        return None


def trap_text(t: dict) -> str:
    vb = "; ".join(f"{k}={v}" for k, v in t["varbinds"][:8])
    return f"SNMP trap {t.get('name') or t.get('oid') or '?'}" + (f" ({t['oid']})" if t.get("name") and t.get("oid") else "") + (f": {vb}" if vb else "")


def trap_interface(t: dict) -> str:
    """The interface a link trap is about: ifDescr when the trap carries it, else ifIndex."""
    for k, v in t["varbinds"]:
        if k.startswith("1.3.6.1.2.1.2.2.1.2."):
            return v
    for k, v in t["varbinds"]:
        if k.startswith("1.3.6.1.2.1.2.2.1.1."):
            return f"ifIndex {v}"
    return ""


# ── Which sources are known ──────────────────────────────────────────────────

def known_sources(force: bool = False) -> Dict[str, dict]:
    """ip -> {asset_id, name} of the devices whose messages are taken (the inventory and the managed devices), cached for a minute."""
    if not force and time.time() - _known_cache["at"] < 60 and _known_cache["ips"]:
        return _known_cache["ips"]
    ips: Dict[str, dict] = {"127.0.0.1": {"asset_id": None, "name": "localhost"}}
    try:
        with SessionLocal() as db:
            for a in db.execute(select(Asset.id, Asset.ip, Asset.name).where(Asset.ip.is_not(None))).all():
                ips[a[1]] = {"asset_id": a[0], "name": a[2] or a[1]}
            for d in db.execute(select(Device.ip, Device.name).where(Device.ip.is_not(None))).all():
                ips.setdefault(d[0], {"asset_id": None, "name": d[1] or d[0]})
    except Exception as e:
        print(f"[syslog] could not read the known sources: {e}")
    _known_cache.update(at=time.time(), ips=ips)
    return ips


def _rate_ok(ip: str, now: float) -> bool:
    q = _rate[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_MAX:
        return False
    q.append(now)
    return True


# ── Detections ───────────────────────────────────────────────────────────────

# (id, name, description, regex, severity, category, mitre, threshold, window s, source)
BUILTIN = [
    ("auth_failure", "Repeated failed logins (syslog)", "Five failed logins from the same device within five minutes.",
     r"(login failure|login failed|authentication fail|failed password|invalid user|bad password|access denied for user|invalid password)", "medium", "auth", "T1110", 5, 300, "syslog"),
    ("config_change", "Configuration changed", "A device logs that its configuration was changed (RouterOS \"changed by\", Cisco CONFIG_I, Linux sudo is not included).",
     r"(\b(added|changed|removed|enabled|disabled|moved) by \S+|%SYS-5-CONFIG_I|configuration (changed|saved)|config(uration)? (changed|saved) by)", "low", "system", None, 1, 60, "syslog"),
    ("restart", "Device restarted", "A restart or a shutdown reported by the device itself.",
     r"(system (is )?(rebooting|restarting|shutting down)|reload requested|restarted|cold start|%SYS-5-RESTART)", "low", "system", None, 1, 60, "syslog"),
]
LINK_DOWN = [re.compile(p, re.I) for p in (r"^(\S+) link down", r"Interface (\S+), changed state to down", r"(\S+): link is down", r"%LINK-\d-UPDOWN: Interface (\S+), changed state to down")]
LINK_UP = [re.compile(p, re.I) for p in (r"^(\S+) link up", r"Interface (\S+), changed state to up", r"(\S+): link (?:is )?up", r"%LINK-\d-UPDOWN: Interface (\S+), changed state to up")]


def rules_list() -> List[dict]:
    off = set(_settings.get("disabled") or [])
    out = [{"id": r[0], "name": r[1], "description": r[2], "severity": r[4], "builtin": True, "enabled": r[0] not in off, "threshold": r[7], "window_sec": r[8],
            "pattern": r[3], "source": r[9]} for r in BUILTIN]
    out.append({"id": "link", "name": "Link down / up", "description": "A link that goes down (syslog or an SNMP linkDown trap) is an alert of the device until its link up arrives.",
                "severity": "medium", "builtin": True, "enabled": "link" not in off, "threshold": 1, "window_sec": 0, "pattern": None, "source": "any"})
    out.append({"id": "critical", "name": "Critical messages", "description": "Anything the device logs as critical, alert or emergency.", "severity": "high", "builtin": True,
                "enabled": "critical" not in off, "threshold": 1, "window_sec": 0, "pattern": None, "source": "syslog"})
    return out + [{**c, "builtin": False} for c in (_settings.get("rules") or [])]


def _raise(rule_id: str, title: str, ev: dict, severity: str, category: str, detail_key: str = "", mitre: Optional[str] = None, count: int = 1) -> None:
    from services import soc
    soc.raise_alert(rule=f"syslog.{rule_id}", device=ev.get("name") or ev["ip"], title=title, severity=severity, category=category, fp_detail=detail_key, ip=ev["ip"],
                    detail={"message": ev["message"], "app": ev.get("app"), "source": ev["kind"], "trap": ev.get("oid")}, count=count, mitre=mitre, source="syslog",
                    asset_id=ev.get("asset_id"))


def _hit(rule_id: str, ip: str, threshold: int, window: int, now: float) -> int:
    """The matches of this rule from this device in the window (appends this one); 0 when under the threshold."""
    q = _windows[(rule_id, ip)]
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    return len(q) if len(q) >= threshold else 0


def evaluate(ev: dict, now: Optional[float] = None) -> List[str]:
    """Runs the detections on one event; returns the ids of the rules that raised an alert."""
    now = now or time.time()
    off = set(_settings.get("disabled") or [])
    text = ev["message"]
    raised: List[str] = []
    from services import soc
    # links: down opens an alert of the interface, up closes it
    if "link" not in off:
        iface = None
        if ev["kind"] == "trap" and ev.get("trap_name") in ("linkDown", "linkUp"):
            iface, down = trap_interface(ev["trap"]), ev["trap_name"] == "linkDown"
        else:
            down = None
            for rx in LINK_DOWN:
                m = rx.search(text)
                if m:
                    iface, down = m.group(1), True
                    break
            if down is None:
                for rx in LINK_UP:
                    m = rx.search(text)
                    if m:
                        iface, down = m.group(1), False
                        break
        if iface is not None and down is not None:
            if down:
                _raise("link_down", f"Link down: {iface}" if iface else "Link down", ev, "medium", "network", detail_key=iface)
                raised.append("link")
            else:
                soc.resolve(rule="syslog.link_down", device=ev.get("name") or ev["ip"], fp_detail=iface)
    for r in BUILTIN:
        if r[0] in off or (r[9] != "any" and r[9] != ev["kind"]) or not re.search(r[3], text, re.I):
            continue
        n = _hit(r[0], ev["ip"], r[7], r[8], now)
        if n:
            sev = "high" if r[0] == "auth_failure" and n >= 20 else r[4]
            _raise(r[0], r[1], ev, sev, r[5], mitre=r[6], count=n if r[7] > 1 else 1)
            raised.append(r[0])
    if "critical" not in off and ev["kind"] == "syslog" and ev["severity"] <= 2:
        _raise("critical", f"Critical message ({SEVERITIES[ev['severity']]})", ev, "high", "system", detail_key=ev.get("app") or "")
        raised.append("critical")
    for c in _settings.get("rules") or []:
        if not c.get("enabled", True) or (c["source"] != "any" and c["source"] != ev["kind"]):
            continue
        try:
            hit = re.search(c["pattern"], text, re.I)
        except re.error:
            continue
        if hit:
            n = _hit(c["id"], ev["ip"], c["threshold"], c["window_sec"], now)
            if n:
                _raise(c["id"], c["name"], ev, c["severity"], "detection", count=n if c["threshold"] > 1 else 1)
                raised.append(c["id"])
    return raised


# ── Processing ───────────────────────────────────────────────────────────────

def _handle(kind: str, data: bytes, ip: str, now: Optional[float] = None) -> Optional[dict]:
    """One datagram -> an event dict (not yet stored), or None when it is dropped. Pure of any I/O except the known-sources cache."""
    now = now or time.time()
    _stats["received"] += 1
    known = known_sources()
    src = known.get(ip)
    if src is None and not _settings.get("accept_unknown"):
        _stats["unknown"] += 1
        _unknown[ip] += 1
        if len(_unknown) > 200:
            _unknown.pop(next(iter(_unknown)))
        return None
    if not _rate_ok(ip, now):
        _stats["rate_dropped"] += 1
        return None
    ev = {"kind": kind, "ip": ip, "asset_id": (src or {}).get("asset_id"), "name": (src or {}).get("name"), "at": datetime.utcnow()}
    if kind == "syslog":
        p = parse_syslog(data)
        if p is None:
            _stats["bad"] += 1
            return None
        ev.update(facility=p["facility"], severity=p["severity"], host=p["host"], app=p["app"], message=p["message"])
        return ev
    t = decode_trap(data)
    if t is None:
        _stats["bad"] += 1
        return None
    if t["version"] == 3:
        _stats["v3"] += 1
        return None
    coms = _settings.get("communities") or []
    if coms and t["community"] not in coms:
        _stats["bad_community"] += 1
        return None
    _stats["traps"] += 1
    name = t.get("name")
    sev = 3 if name in ("linkDown", "authenticationFailure") else 5 if name else 6
    ev.update(facility=None, severity=sev, host=t.get("agent"), app=name or t.get("oid"), message=trap_text(t)[:1000], trap=t, oid=t.get("oid"), trap_name=name)
    ev["name"] = (src or {}).get("name") or t.get("agent") or ip
    return ev


def _store(batch: List[dict]) -> int:
    keep = [e for e in batch if e["kind"] == "trap" or e["severity"] <= 5 or e.get("raised") or _settings.get("store_info")]
    if not keep:
        return 0
    with SessionLocal() as db:
        for e in keep:
            db.add(SyslogEvent(at=e["at"], source_ip=e["ip"], asset_id=e.get("asset_id"), host=e.get("host"), app=(e.get("app") or "")[:80] or None,
                               facility=e.get("facility"), severity=e["severity"], kind=e["kind"], message=e["message"][:1000], raised=",".join(e.get("raised") or []) or None))
        db.commit()
    _stats["stored"] += len(keep)
    return len(keep)


def process(batch: List[dict]) -> None:
    for e in batch:
        e.setdefault("name", None)
        try:
            e["raised"] = evaluate(e)
        except Exception as ex:
            print(f"[syslog] detection error: {type(ex).__name__}: {ex}")
            e["raised"] = []
    _store(batch)
    if time.time() - _last_prune[0] > 600:
        _last_prune[0] = time.time()
        prune()


def prune() -> None:
    with SessionLocal() as db:
        db.execute(delete(SyslogEvent).where(SyslogEvent.at < datetime.utcnow() - timedelta(days=KEEP_DAYS)))
        n = db.execute(select(func.count()).select_from(SyslogEvent)).scalar() or 0
        if n > KEEP_ROWS:
            cut = db.execute(select(SyslogEvent.id).order_by(SyslogEvent.id.desc()).offset(KEEP_ROWS).limit(1)).scalar()
            if cut:
                db.execute(delete(SyslogEvent).where(SyslogEvent.id <= cut))
        db.commit()


# ── The sockets ──────────────────────────────────────────────────────────────

class _Proto(asyncio.DatagramProtocol):
    def __init__(self, kind: str):
        self.kind = kind

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            ev = _handle(self.kind, data[:8192], addr[0])
            if ev is not None and _queue is not None and _queue.qsize() < 5000:
                _queue.put_nowait(ev)
        except Exception as e:
            print(f"[syslog] datagram error: {type(e).__name__}: {e}")


async def _writer() -> None:
    while True:
        await asyncio.sleep(1.0)
        batch: List[dict] = []
        while _queue is not None and not _queue.empty() and len(batch) < 500:
            batch.append(_queue.get_nowait())
        if batch:
            try:
                process(batch)
            except Exception as e:
                print(f"[syslog] processing error: {type(e).__name__}: {e}")


async def _open(kind: str, port: int) -> None:
    loop = asyncio.get_event_loop()
    try:
        tr, _ = await loop.create_datagram_endpoint(lambda: _Proto(kind), local_addr=("0.0.0.0", port))
        _transports[kind] = tr
        _errors["syslog" if kind == "syslog" else "trap"] = None
    except OSError as e:
        _errors["syslog" if kind == "syslog" else "trap"] = f"cannot listen on UDP {port}: {e.strerror or e}"
        print(f"[syslog] {_errors['syslog' if kind == 'syslog' else 'trap']}")


async def restart() -> None:
    await stop()
    if _settings.get("enabled"):
        await start()


async def start() -> None:
    global _queue
    if not _settings_loaded[0]:
        load_settings()
        _settings_loaded[0] = True
    if not _settings.get("enabled") or _transports:
        return
    _queue = asyncio.Queue()
    _stats["since"] = datetime.utcnow().isoformat() + "Z"
    await _open("syslog", int(_settings["syslog_port"]))
    await _open("trap", int(_settings["trap_port"]))
    _tasks.append(asyncio.get_event_loop().create_task(_writer()))


async def stop() -> None:
    closing = bool(_transports)
    for tr in list(_transports.values()):
        tr.close()
    _transports.clear()
    for t in _tasks:
        t.cancel()
    _tasks.clear()
    if closing:
        await asyncio.sleep(0.1)                 # the sockets are really closed on the loop's next turns: the same port can be opened again after this


_settings_loaded = [False]


# ── Reading ──────────────────────────────────────────────────────────────────

def status() -> dict:
    with SessionLocal() as db:
        day = datetime.utcnow() - timedelta(hours=24)
        stored24 = db.execute(select(func.count()).select_from(SyslogEvent).where(SyslogEvent.at >= day)).scalar() or 0
        by_src = db.execute(select(SyslogEvent.source_ip, func.count()).where(SyslogEvent.at >= day).group_by(SyslogEvent.source_ip)
                            .order_by(func.count().desc()).limit(10)).all()
    return {"settings": settings(), "listening": {"syslog": "syslog" in _transports, "trap": "trap" in _transports}, "errors": dict(_errors), "stats": dict(_stats),
            "stored_24h": stored24, "top_sources": [{"ip": ip, "n": n, "name": (known_sources().get(ip) or {}).get("name")} for ip, n in by_src],
            "unknown": sorted(({"ip": k, "n": v} for k, v in _unknown.items()), key=lambda x: -x["n"])[:15], "rules": rules_list()}


def events(*, limit: int = 200, offset: int = 0, kind: Optional[str] = None, source_ip: Optional[str] = None, max_severity: Optional[int] = None,
           q: Optional[str] = None) -> dict:
    stmt = select(SyslogEvent)
    if kind in ("syslog", "trap"):
        stmt = stmt.where(SyslogEvent.kind == kind)
    if source_ip:
        stmt = stmt.where(SyslogEvent.source_ip == source_ip)
    if max_severity is not None:
        stmt = stmt.where(SyslogEvent.severity <= max_severity)
    if q:
        stmt = stmt.where(func.lower(SyslogEvent.message).like(f"%{q.strip().lower()}%"))
    with SessionLocal() as db:
        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar() or 0
        rows = db.execute(stmt.order_by(SyslogEvent.id.desc()).limit(max(1, min(limit, 1000))).offset(max(0, offset))).scalars().all()
        names = known_sources()
        items = [{"id": r.id, "at": r.at.isoformat() + "Z", "ip": r.source_ip, "name": (names.get(r.source_ip) or {}).get("name"), "asset_id": r.asset_id, "host": r.host,
                  "app": r.app, "severity": r.severity, "kind": r.kind, "message": r.message, "raised": r.raised.split(",") if r.raised else []} for r in rows]
    return {"total": total, "items": items}


def public_summary() -> dict:
    """The numbers for Central (inside the SOC status): whether it is on, how much came in and from how many devices."""
    s = status()
    return {"on": bool(s["settings"]["enabled"]), "listening": s["listening"], "stored_24h": s["stored_24h"], "sources": len(s["top_sources"]),
            "unknown": len(s["unknown"]), "errors": [v for v in s["errors"].values() if v]}
