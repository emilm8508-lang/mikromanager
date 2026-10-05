"""
Close monitoring of selected hosts ("Monitoring hostów") — for a device that
intermittently loses connectivity: gather every log/signal the agent can see
about that one host into a single timeline, and name a probable cause when the
evidence allows it.

Sources (all read-only):
  - Reachability probe run by the agent itself (ping, or TCP connect when a
    port is set) every ~30 s — gives the exact outage windows everything else
    is correlated against.
  - Every Mikrotik device's system log, matched to the host by IP, by MAC, and
    by the switch port the host sits on (learned from the bridge host table).
    Persisted, because RouterOS keeps its log only in a small in-memory ring
    buffer — the line explaining a short outage is usually gone before anyone
    looks. The first collection backfills whatever the buffers still hold.
  - DHCP lease / ARP / bridge-host tables: where the host currently shows up,
    plus events when its IP, MAC or switch port changes.
  - Wazuh alerts mentioning the host (when Wazuh is connected); PRTG/Check_MK
    sensor state is shown as current context.

IP <-> MAC are resolved from the devices' tables, so a host given only a MAC is
still followed when its DHCP address changes (and vice versa).

Cause analysis is a small rule table over the correlated events (see
_RULES / analyze()) — deliberately honest: with no matching evidence the
answer is "unknown / host-side", never a guess. Unverified against live
devices: RouterOS log wording varies between versions, so the patterns are
conservative substrings of messages RouterOS is known to emit.
"""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import statistics
import time
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import delete, func, select

from models.database import (
    SessionLocal, Device, Credential, WatchedHost, HostEvent,
    VulnHost, LinuxHost, WindowsHost,
)
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient
from services import edge_selfcheck

INTERVAL_SEC = int(os.environ.get("MIKROTIK_HOSTMON_INTERVAL_SEC", "30"))
LOG_POLL_SEC = int(os.environ.get("MIKROTIK_HOSTMON_LOG_POLL_SEC", "60"))
RETENTION_DAYS = int(os.environ.get("MIKROTIK_HOSTMON_RETENTION_DAYS", "30"))
_DIRECTORY_TTL_SEC = 300
_DEVICE_TIMEOUT_SEC = 20
_UPLINK_HOST_COUNT = 8      # a port that learned more MACs than this is a trunk/uplink, not the host's own port
_MAX_REPORT_EVENTS = 1000

_task: Optional[asyncio.Task] = None
_lock = asyncio.Lock()
_state = {"last_collect": 0.0, "last_prune": 0.0}
_directory = {"at": 0.0, "entries": []}


# ── Identifiers ──────────────────────────────────────────────────────────────

def normalize_mac(raw) -> Optional[str]:
    if not raw:
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", str(raw))
    if len(hexes) != 12:
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


def _valid_ip(raw) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(raw).strip()))
    except ValueError:
        return None


def _ip_regex(ip: str):
    # not part of a longer number/address (10.0.0.5 must not match 10.0.0.50 or 110.0.0.5)
    return re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?!\d|\.\d)")


# ── RouterOS log timestamps ──────────────────────────────────────────────────

_MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}


def parse_log_time(raw, now: datetime) -> datetime:
    """RouterOS prints "HH:MM:SS" (today), "mon/dd HH:MM:SS" or
    "mon/dd/yyyy HH:MM:SS" depending on version and age; REST may also give
    ISO. Anything unparseable falls back to 'now' (collection time)."""
    s = str(raw or "").strip().lower()
    try:
        m = re.fullmatch(r"(\d{2}):(\d{2}):(\d{2})", s)
        if m:
            t = now.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3]), microsecond=0)
            return t - timedelta(days=1) if t > now + timedelta(minutes=10) else t
        m = re.fullmatch(r"([a-z]{3})/(\d{1,2})(?:/(\d{4}))? (\d{2}):(\d{2}):(\d{2})", s)
        if m and m[1] in _MONTHS:
            year = int(m[3]) if m[3] else now.year
            t = datetime(year, _MONTHS[m[1]], int(m[2]), int(m[4]), int(m[5]), int(m[6]))
            return t.replace(year=t.year - 1) if (not m[3] and t > now + timedelta(days=1)) else t
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})[ t](\d{2}):(\d{2}):(\d{2})", s)
        if m:
            return datetime(*(int(g) for g in m.groups()))
    except ValueError:
        pass
    return now


# ── Event classification (log text -> machine code) ─────────────────────────

_PORT_EVENT_RE = re.compile(r"link (?:up|down)|speed|duplex|loop|topology|stp|poe|flap|negotiat|error", re.I)
_DEVICE_EVENT_RE = re.compile(r"reboot|restart|shutdown|power|watchdog|kernel failure", re.I)
_WARN_RE = re.compile(r"link down|disconnected|deauth|conflict|loop|fail|timeout|lost|expired|deassigned|without success", re.I)

# (code, test(ev)) in PRIORITY order — the first rule that fits names the
# event; analyze() also ranks causes between events by this same order.
_RULES = [
    ("port_link_down", lambda m, t, ev: ev["matched_on"] == "port" and "link down" in m),
    ("device_reboot", lambda m, t, ev: ev["matched_on"] == "device" and bool(_DEVICE_EVENT_RE.search(m))),
    ("loop_stp", lambda m, t, ev: bool(re.search(r"\bloop\b|topology change|\br?stp\b", m))),
    ("wifi_key_timeout", lambda m, t, ev: bool(re.search(r"key exchange timeout|4-?way|handshake timeout", m))),
    ("wifi_weak_signal", lambda m, t, ev: "signal strength too weak" in m or "signal too weak" in m),
    ("wifi_data_loss", lambda m, t, ev: "extensive data loss" in m),
    ("wifi_deauth", lambda m, t, ev: bool(re.search(r"deauth|disassoc|sta has left|connection lost|disconnected", m)) and ("wireless" in t or "wifi" in t or "disconnected," in m)),
    ("ip_conflict", lambda m, t, ev: bool(re.search(r"conflict|already in use|already assigned|duplicate|declined", m))),
    ("dhcp_pool_exhausted", lambda m, t, ev: bool(re.search(r"no free address|pool is empty|no more free|without success", m))),
    ("dhcp_ip_changed", lambda m, t, ev: ev.get("kind") == "ip_changed" or bool(re.search(r"deassigned|lease expired|released", m))),
    ("firewall_block", lambda m, t, ev: "firewall" in t and bool(re.search(r"drop|reject|block", m))),
]
_PRIORITY = [code for code, _ in _RULES]


def classify_event(ev: dict) -> Optional[str]:
    m = (ev.get("message") or "").lower()
    t = (ev.get("topics") or "").lower()
    for code, test in _RULES:
        try:
            if test(m, t, ev):
                return code
        except Exception:
            continue
    return None


def _severity(topics: str, message: str) -> str:
    t = (topics or "").lower()
    if "error" in t or "critical" in t:
        return "error"
    if "warning" in t or _WARN_RE.search(message or ""):
        return "warn"
    return "info"


def _dedup_key(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "ignore")).hexdigest()


# ── Cause analysis (pure — takes plain dicts, easy to test) ─────────────────

def compute_outages(probe_events: List[dict], range_start: datetime, now: datetime) -> List[dict]:
    """probe_down/probe_up events (any order) -> [{start, end|None, duration_sec}]."""
    outages, open_start = [], None
    for ev in sorted(probe_events, key=lambda e: e["ts"]):
        if ev["kind"] == "probe_down" and open_start is None:
            open_start = ev["ts"]
        elif ev["kind"] == "probe_up" and open_start is not None:
            outages.append({"start": open_start, "end": ev["ts"]})
            open_start = None
    if open_start is not None:
        outages.append({"start": open_start, "end": None})
    out = []
    for o in outages:
        if (o["end"] or now) >= range_start:
            o["duration_sec"] = int(((o["end"] or now) - o["start"]).total_seconds())
            out.append(o)
    return out


_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def analyze(events: List[dict], outages: List[dict], now: datetime) -> dict:
    """events: dicts with id, ts(datetime), message, topics, matched_on, kind.
    Returns {"findings": per outage, "indicators": per cause code, "summary"}.
    A finding's confidence reflects timing only: 'high' = the evidence landed
    right at the start of the outage, 'medium' = during it, 'low' = nearby."""
    classified = []
    for ev in events:
        code = classify_event(ev)
        if code:
            classified.append((code, ev))

    findings = []
    for o in outages:
        start, end = o["start"], o["end"] or now
        cands = []
        for code, ev in classified:
            ts = ev["ts"]
            if not (start - timedelta(minutes=5) <= ts <= end + timedelta(seconds=60)):
                continue
            if start - timedelta(seconds=120) <= ts <= start + timedelta(seconds=60):
                conf = "high"
            elif start <= ts <= end + timedelta(seconds=60):
                conf = "medium"
            else:
                conf = "low"
            cands.append((code, conf, ev["id"]))
        best: Dict[str, dict] = {}
        for code, conf, eid in cands:
            b = best.setdefault(code, {"code": code, "confidence": conf, "evidence": []})
            if _CONF_RANK[conf] < _CONF_RANK[b["confidence"]]:
                b["confidence"] = conf
            b["evidence"].append(eid)
        ranked = sorted(best.values(), key=lambda b: (_CONF_RANK[b["confidence"]], _PRIORITY.index(b["code"])))
        findings.append({
            "start": o["start"], "end": o["end"], "duration_sec": o["duration_sec"],
            "code": ranked[0]["code"] if ranked else "unknown",
            "confidence": ranked[0]["confidence"] if ranked else None,
            "evidence": ranked[0]["evidence"][:10] if ranked else [],
            "also": [b["code"] for b in ranked[1:4]],
        })

    counts = Counter(code for code, _ in classified)
    last = {}
    for code, ev in classified:
        if code not in last or ev["ts"] > last[code]:
            last[code] = ev["ts"]
    indicators = sorted(({"code": c, "count": n, "last_ts": last[c]} for c, n in counts.items()),
                        key=lambda i: (-i["count"], _PRIORITY.index(i["code"])))

    summary = None
    if findings:
        known = Counter(f["code"] for f in findings if f["code"] != "unknown")
        if known:
            top, n = sorted(known.items(), key=lambda kv: (-kv[1], _PRIORITY.index(kv[0])))[0]
            summary = {"code": top, "outages_with_cause": n, "outages": len(findings)}
        else:
            summary = {"code": "unknown", "outages_with_cause": 0, "outages": len(findings)}
        starts = sorted(f["start"] for f in findings)
        if len(starts) >= 3:
            gaps = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
            mean = statistics.mean(gaps)
            if mean >= 30 and statistics.pstdev(gaps) / mean < 0.2:
                summary["periodic_sec"] = int(mean)
    return {"findings": findings, "indicators": indicators, "summary": summary}


# ── Device access ────────────────────────────────────────────────────────────

def _load_devices() -> List[dict]:
    """Mikrotik devices with a stored credential — the only ones whose logs /
    DHCP / ARP / bridge tables this reads (Cisco SB has no log access)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(Device, Credential).join(Credential, Device.credential_id == Credential.id)
        ).all()
    out = []
    for d, c in rows:
        if (d.vendor or "mikrotik").lower() != "mikrotik":
            continue
        try:
            password = decrypt(c.password_enc)
        except Exception:
            continue
        out.append({"id": d.id, "name": d.identity or d.name or d.ip, "ip": d.ip,
                    "api_port": d.api_port, "web_port": d.web_port,
                    "username": c.username, "password": password})
    return out


async def _fetch_device(dev: dict, with_logs: bool) -> dict:
    """One device's tables (+ log). Sequential on one client, each step
    time-boxed; a failing step just yields nothing for that step."""
    client = MikrotikClient(dev["ip"], dev["username"], dev["password"],
                            api_port=dev["api_port"], web_port=dev["web_port"])
    res = {"dev": dev, "logs": None, "leases": [], "arp": [], "bridge": [], "error": None}

    async def _step(coro):
        return await asyncio.wait_for(coro, _DEVICE_TIMEOUT_SEC)

    try:
        if with_logs:
            try:
                res["logs"] = await _step(client.get_logs(limit=1000)) or []
            except Exception as e:
                res["error"] = f"{type(e).__name__}: {e}"
        for key, fn in (("leases", client.get_dhcp_leases), ("arp", client.get_arp), ("bridge", client.get_bridge_hosts)):
            try:
                res[key] = await _step(fn()) or []
            except Exception:
                pass
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    return res


async def _fetch_all(devices: List[dict], with_logs: bool) -> List[dict]:
    sem = asyncio.Semaphore(4)

    async def _bounded(dev):
        async with sem:
            return await _fetch_device(dev, with_logs)

    return await asyncio.gather(*[_bounded(d) for d in devices])


# ── Presence / IP<->MAC resolution ──────────────────────────────────────────

def _lease_mac(l: dict) -> Optional[str]:
    return normalize_mac(l.get("active-mac-address") or l.get("mac-address"))


def _lease_ip(l: dict) -> Optional[str]:
    return l.get("active-address") or l.get("address")


def _resolve(host: dict, datas: List[dict]) -> dict:
    """Where the host shows up right now, plus its current IP/MAC. A given MAC
    is authoritative for the IP (DHCP addresses move); a given IP is used to
    discover the MAC."""
    mac = host["mac"]
    found_ip = None
    found_mac = None
    if mac:
        for d in datas:
            for l in d["leases"]:
                if _lease_mac(l) == mac and _lease_ip(l):
                    if found_ip is None or l.get("status") == "bound":
                        found_ip = _lease_ip(l)
            for a in d["arp"]:
                if normalize_mac(a.get("mac-address")) == mac and a.get("address") and found_ip is None:
                    found_ip = a["address"]
    else:
        for d in datas:
            for l in d["leases"]:
                if _lease_ip(l) == host["ip"] and _lease_mac(l):
                    found_mac = _lease_mac(l)
            for a in d["arp"]:
                if a.get("address") == host["ip"] and normalize_mac(a.get("mac-address")) and not found_mac:
                    found_mac = normalize_mac(a["mac-address"])
    ip = (found_ip or host["resolved_ip"] or host["ip"]) if mac else host["ip"]
    cur_mac = mac or found_mac or host["resolved_mac"]
    ips = {i for i in (host["ip"], ip) if i}
    macs = {m for m in (mac, cur_mac) if m}

    entries, ports, ports_by_device, seen_on = [], [], {}, set()
    for d in datas:
        name = d["dev"]["name"]
        for l in d["leases"]:
            if _lease_ip(l) in ips or _lease_mac(l) in macs:
                seen_on.add(name)
                entries.append({"type": "dhcp", "device": name, "address": _lease_ip(l), "mac": _lease_mac(l),
                                "host_name": l.get("host-name"), "status": l.get("status"),
                                "server": l.get("server"), "last_seen": l.get("last-seen"),
                                "expires_after": l.get("expires-after")})
        for a in d["arp"]:
            if a.get("address") in ips or normalize_mac(a.get("mac-address")) in macs:
                seen_on.add(name)
                entries.append({"type": "arp", "device": name, "address": a.get("address"),
                                "mac": normalize_mac(a.get("mac-address")), "interface": a.get("interface"),
                                "status": a.get("status")})
        per_iface = Counter(b.get("on-interface") for b in d["bridge"] if b.get("local") not in ("true", True))
        for b in d["bridge"]:
            if normalize_mac(b.get("mac-address")) in macs and b.get("local") not in ("true", True):
                seen_on.add(name)
                iface = b.get("on-interface")
                uplink = per_iface.get(iface, 0) > _UPLINK_HOST_COUNT
                entries.append({"type": "port", "device": name, "interface": iface, "vid": b.get("vid"),
                                "age": b.get("age"), "uplink": uplink})
                if iface and not uplink:
                    ports.append(f"{name}:{iface}")
                    ports_by_device.setdefault(name, set()).add(iface)
    return {"ip": ip, "mac": cur_mac, "ips": ips, "macs": macs, "entries": entries, "ports": sorted(set(ports)),
            "ports_by_device": ports_by_device, "seen_on": seen_on}


# ── Log matching ─────────────────────────────────────────────────────────────

def _match_logs(host: dict, res: dict, data: dict, now: datetime) -> List[dict]:
    dev_name = data["dev"]["name"]
    dev_id = data["dev"]["id"]
    ip_res = [_ip_regex(i) for i in res["ips"]]
    macs = res["macs"]
    ifaces = res["ports_by_device"].get(dev_name, set())
    iface_res = [re.compile(r"(?<![\w-])" + re.escape(i) + r"(?![\w-])") for i in ifaces]
    out = []
    for e in data["logs"] or []:
        msg = str(e.get("message") or "")
        topics = str(e.get("topics") or "")
        matched = None
        if any(r.search(msg) for r in ip_res):
            matched = "ip"
        elif macs and any(m in msg.upper() for m in macs):
            matched = "mac"
        elif iface_res and _PORT_EVENT_RE.search(msg) and any(r.search(msg) for r in iface_res):
            matched = "port"
        elif dev_name in res["seen_on"] and "system" in topics.lower() and _DEVICE_EVENT_RE.search(msg):
            matched = "device"
        if not matched:
            continue
        out.append({
            "ts": parse_log_time(e.get("time"), now), "source": "device-log", "kind": None,
            "device_name": dev_name, "topics": topics, "message": msg, "matched_on": matched,
            "severity": _severity(topics, msg), "data": None,
            "dedup_key": _dedup_key(dev_id, e.get(".id"), e.get("time"), topics, msg),
        })
    return out


# ── Persistence helpers ──────────────────────────────────────────────────────

def _insert_events(host_id: int, events: List[dict]) -> int:
    if not events:
        return 0
    cutoff = min(e["ts"] for e in events) - timedelta(hours=1)
    with SessionLocal() as db:
        existing = set(db.execute(
            select(HostEvent.dedup_key).where(HostEvent.host_id == host_id, HostEvent.ts >= cutoff)
        ).scalars().all())
        added = 0
        for e in events:
            if e["dedup_key"] in existing:
                continue
            existing.add(e["dedup_key"])
            db.add(HostEvent(host_id=host_id, ts=e["ts"], source=e["source"], kind=e.get("kind"),
                             device_name=e.get("device_name"), topics=e.get("topics"), message=e.get("message"),
                             matched_on=e.get("matched_on"), severity=e.get("severity", "info"),
                             data=json.dumps(e["data"]) if e.get("data") else None, dedup_key=e["dedup_key"]))
            added += 1
        db.commit()
    return added


def _structured(host_id: int, kind: str, now: datetime, severity: str, message: str, data: dict) -> dict:
    return {"ts": now, "source": "probe" if kind.startswith("probe") else "presence", "kind": kind,
            "device_name": None, "topics": None, "message": message, "matched_on": None,
            "severity": severity, "data": data, "dedup_key": _dedup_key(host_id, kind, now.isoformat())}


def _host_view(h: WatchedHost) -> dict:
    return {"id": h.id, "name": h.name, "ip": h.ip, "mac": h.mac, "resolved_ip": h.resolved_ip,
            "resolved_mac": h.resolved_mac, "probe_port": h.probe_port, "probe_state": h.probe_state,
            "probe_state_since": h.probe_state_since, "presence": h.presence}


def _enabled_hosts(only_id: Optional[int] = None) -> List[dict]:
    with SessionLocal() as db:
        q = select(WatchedHost).where(WatchedHost.enabled.is_(True))
        if only_id is not None:
            q = q.where(WatchedHost.id == only_id)
        return [_host_view(h) for h in db.execute(q).scalars().all()]


# ── Cycle ────────────────────────────────────────────────────────────────────

async def _probe(host: dict, now: datetime) -> None:
    target = host["resolved_ip"] or host["ip"]
    if not target:
        return
    loop = asyncio.get_event_loop()
    ok, _method, detail = await edge_selfcheck._check_one(loop, target, host["probe_port"])
    if not ok:  # one quick retry so a single lost packet isn't an "outage"
        await asyncio.sleep(2)
        ok, _method, detail = await edge_selfcheck._check_one(loop, target, host["probe_port"])
    state = "up" if ok else "down"
    prev = host["probe_state"]
    events = []
    since = host["probe_state_since"]
    if prev != state:
        if state == "down":
            events.append(_structured(host["id"], "probe_down", now, "error", detail, {"target": target}))
        elif prev == "down":
            dur = int((now - since).total_seconds()) if since else None
            events.append(_structured(host["id"], "probe_up", now, "info", detail, {"target": target, "duration_sec": dur}))
        since = now
    with SessionLocal() as db:
        h = db.get(WatchedHost, host["id"])
        if h:
            h.probe_state, h.probe_state_since, h.last_probe_at = state, since, now
            db.commit()
    _insert_events(host["id"], events)


def _apply_presence(host: dict, res: dict, now: datetime) -> List[dict]:
    """Persists the resolved IP/MAC + presence, returns change events."""
    events = []
    if host["resolved_ip"] and res["ip"] and host["resolved_ip"] != res["ip"]:
        events.append(_structured(host["id"], "ip_changed", now, "warn", "",
                                  {"old": host["resolved_ip"], "new": res["ip"]}))
    if not host["mac"] and host["resolved_mac"] and res["mac"] and host["resolved_mac"] != res["mac"]:
        events.append(_structured(host["id"], "mac_changed", now, "warn", "",
                                  {"old": host["resolved_mac"], "new": res["mac"]}))
    try:
        old_ports = set(json.loads(host["presence"] or "{}").get("ports") or [])
    except ValueError:
        old_ports = set()
    new_ports = set(res["ports"])
    if old_ports and new_ports and old_ports != new_ports:
        events.append(_structured(host["id"], "port_changed", now, "warn", "",
                                  {"old": sorted(old_ports), "new": sorted(new_ports)}))
    with SessionLocal() as db:
        h = db.get(WatchedHost, host["id"])
        if h:
            h.resolved_ip, h.resolved_mac = res["ip"], res["mac"]
            h.presence = json.dumps({"updated": now.isoformat(), "entries": res["entries"], "ports": res["ports"]})
            h.last_collect_at, h.last_error = now, None
            db.commit()
    return events


def _wazuh_events(host: dict, res: dict, now: datetime) -> List[dict]:
    try:
        from services import wazuh_monitor
        alerts = wazuh_monitor._cache.get("data") or []
    except Exception:
        return []
    out = []
    for a in alerts:
        if a.get("ip") in res["ips"]:
            lvl = a.get("rule_level")
            out.append({"ts": now, "source": "wazuh", "kind": None, "device_name": a.get("agent_name"),
                        "topics": f"wazuh level {lvl}", "message": a.get("rule_description") or "",
                        "matched_on": "ip", "severity": "warn" if (lvl or 0) >= 8 else "info", "data": None,
                        "dedup_key": _dedup_key(host["id"], "wazuh", a.get("detected_at"), a.get("rule_description"))})
    return out


async def _collect(hosts: List[dict], now: datetime) -> None:
    devices = _load_devices()
    datas = await _fetch_all(devices, with_logs=True) if devices else []
    _update_directory(datas)
    for host in hosts:
        try:
            res = _resolve(host, datas)
            events = _apply_presence(host, res, now)
            for d in datas:
                if d["logs"] is not None:
                    events.extend(_match_logs(host, res, d, now))
            events.extend(_wazuh_events(host, res, now))
            _insert_events(host["id"], events)
            if not devices:
                _set_error(host["id"], "no Mikrotik device with credentials to read logs from")
        except Exception as e:
            _set_error(host["id"], f"{type(e).__name__}: {e}")
            print(f"[host_monitor] collect error for host {host['id']}: {e}")


def _set_error(host_id: int, msg: str) -> None:
    with SessionLocal() as db:
        h = db.get(WatchedHost, host_id)
        if h:
            h.last_error = msg
            db.commit()


def _prune() -> None:
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    with SessionLocal() as db:
        db.execute(delete(HostEvent).where(HostEvent.ts < cutoff))
        db.commit()


async def run_cycle(force_collect: bool = False, only_host_id: Optional[int] = None) -> None:
    async with _lock:
        hosts = _enabled_hosts(only_host_id)
        if not hosts:
            return
        now = datetime.now()
        await asyncio.gather(*[_probe(h, now) for h in hosts], return_exceptions=True)
        if force_collect or time.time() - _state["last_collect"] >= LOG_POLL_SEC:
            hosts = _enabled_hosts(only_host_id)   # fresh resolved_*/presence after the probe step
            await _collect(hosts, datetime.now())
            if only_host_id is None:
                _state["last_collect"] = time.time()
        if time.time() - _state["last_prune"] > 3600:
            _state["last_prune"] = time.time()
            _prune()


async def _loop():
    await asyncio.sleep(20)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            print(f"[host_monitor] cycle error: {e}")
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


# ── Directory / search ───────────────────────────────────────────────────────

def _update_directory(datas: List[dict]) -> None:
    """Rebuilds the searchable host list from DHCP leases + ARP (+ the hosts
    the agent already knows from its own scans), merged by IP / MAC."""
    by_ip: Dict[str, dict] = {}
    by_mac: Dict[str, dict] = {}
    entries: List[dict] = []

    def _get(ip, mac):
        if not ip and not mac:
            return {"name": None, "ip": None, "mac": None, "sources": set(), "devices": set(), "comment": None}
        e = (by_ip.get(ip) if ip else None) or (by_mac.get(mac) if mac else None)
        if e is None:
            e = {"name": None, "ip": None, "mac": None, "sources": set(), "devices": set(), "comment": None}
            entries.append(e)
        if ip and not e["ip"]:
            e["ip"] = ip
        if mac and not e["mac"]:
            e["mac"] = mac
        if e["ip"]:
            by_ip[e["ip"]] = e
        if e["mac"]:
            by_mac[e["mac"]] = e
        return e

    for d in datas:
        dn = d["dev"]["name"]
        for l in d["leases"]:
            e = _get(_lease_ip(l), _lease_mac(l))
            e["name"] = e["name"] or l.get("host-name") or None
            e["comment"] = e["comment"] or l.get("comment") or None
            e["sources"].add("dhcp")
            e["devices"].add(dn)
        for a in d["arp"]:
            mac = normalize_mac(a.get("mac-address"))
            if not mac:
                continue
            e = _get(a.get("address"), mac)
            e["sources"].add("arp")
            e["devices"].add(dn)

    with SessionLocal() as db:
        for dv in db.execute(select(Device)).scalars().all():
            e = _get(dv.ip, normalize_mac(dv.mac))
            e["name"] = e["name"] or dv.identity or dv.name
            e["sources"].add("device")
        for lh in db.execute(select(LinuxHost)).scalars().all():
            e = _get(lh.ip, None)
            e["name"] = e["name"] or lh.hostname
            e["sources"].add("linux")
        for wh in db.execute(select(WindowsHost)).scalars().all():
            e = _get(wh.ip, None)
            e["name"] = e["name"] or wh.hostname
            e["sources"].add("windows")
        for vh in db.execute(select(VulnHost)).scalars().all():
            e = _get(vh.ip, None)
            e["sources"].add("scan")

    _directory["entries"] = [
        {**e, "sources": sorted(e["sources"]), "devices": sorted(e["devices"])} for e in entries
    ]
    _directory["at"] = time.time()


async def search_hosts(query: str, refresh: bool = False) -> dict:
    q = (query or "").strip().lower()
    if len(q) < 2:
        return {"results": [], "refreshed": False}
    refreshed = False
    if refresh or time.time() - _directory["at"] > _DIRECTORY_TTL_SEC:
        devices = _load_devices()
        _update_directory(await _fetch_all(devices, with_logs=False) if devices else [])
        refreshed = True
    qhex = re.sub(r"[^0-9a-f]", "", q)
    with SessionLocal() as db:
        watched = db.execute(select(WatchedHost)).scalars().all()
    w_ips = {h.ip for h in watched if h.ip} | {h.resolved_ip for h in watched if h.resolved_ip}
    w_macs = {h.mac for h in watched if h.mac} | {h.resolved_mac for h in watched if h.resolved_mac}
    results = []
    for e in _directory["entries"]:
        mac_plain = (e["mac"] or "").replace(":", "").lower()
        if (q in (e["name"] or "").lower() or q in (e["ip"] or "") or q in (e["comment"] or "").lower()
                or (len(qhex) >= 2 and qhex in mac_plain)):
            results.append({**e, "watched": bool((e["ip"] and e["ip"] in w_ips) or (e["mac"] and e["mac"] in w_macs))})
    results.sort(key=lambda r: ((r["ip"] or "") != q, _ip_sort(r["ip"])))
    return {"results": results[:100], "refreshed": refreshed, "total": len(results)}


def _ip_sort(ip: Optional[str]):
    try:
        return [int(p) for p in (ip or "").split(".")]
    except ValueError:
        return [999]


# ── CRUD ─────────────────────────────────────────────────────────────────────

def _validated(name: str, ip: Optional[str], mac: Optional[str], probe_port) -> tuple:
    name = (name or "").strip()
    if not name:
        raise ValueError("name required")
    ip_n = _valid_ip(ip) if ip else None
    if ip and not ip_n:
        raise ValueError("invalid IP address")
    mac_n = normalize_mac(mac) if mac else None
    if mac and not mac_n:
        raise ValueError("invalid MAC address")
    if not ip_n and not mac_n:
        raise ValueError("IP or MAC required")
    port = None
    if probe_port not in (None, "", 0):
        try:
            port = int(probe_port)
        except (TypeError, ValueError):
            raise ValueError("invalid probe port")
        if not 1 <= port <= 65535:
            raise ValueError("invalid probe port")
    return name, ip_n, mac_n, port


def _check_duplicate(db, ip_n, mac_n, exclude_id=None) -> None:
    for h in db.execute(select(WatchedHost)).scalars().all():
        if exclude_id is not None and h.id == exclude_id:
            continue
        if (ip_n and h.ip == ip_n) or (mac_n and h.mac == mac_n):
            raise ValueError(f"already monitored as '{h.name}'")


def create_host(name: str, ip: Optional[str], mac: Optional[str], note: Optional[str], probe_port) -> dict:
    name, ip_n, mac_n, port = _validated(name, ip, mac, probe_port)
    with SessionLocal() as db:
        _check_duplicate(db, ip_n, mac_n)
        h = WatchedHost(name=name, ip=ip_n, mac=mac_n, note=(note or None), probe_port=port,
                        resolved_ip=ip_n, resolved_mac=mac_n)
        db.add(h)
        db.commit()
        return {"id": h.id}


def update_host(host_id: int, name: str, ip: Optional[str], mac: Optional[str], note: Optional[str],
                probe_port, enabled: bool) -> dict:
    name, ip_n, mac_n, port = _validated(name, ip, mac, probe_port)
    with SessionLocal() as db:
        h = db.get(WatchedHost, host_id)
        if not h:
            raise LookupError("host not found")
        _check_duplicate(db, ip_n, mac_n, exclude_id=host_id)
        h.name, h.ip, h.mac, h.note, h.probe_port, h.enabled = name, ip_n, mac_n, (note or None), port, enabled
        h.resolved_ip, h.resolved_mac = ip_n or h.resolved_ip, mac_n or h.resolved_mac
        db.commit()
    return {"ok": True}


def delete_host(host_id: int) -> dict:
    with SessionLocal() as db:
        h = db.get(WatchedHost, host_id)
        if not h:
            raise LookupError("host not found")
        db.execute(delete(HostEvent).where(HostEvent.host_id == host_id))
        db.delete(h)
        db.commit()
    return {"ok": True}


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def list_hosts() -> List[dict]:
    now = datetime.now()
    day_ago = now - timedelta(hours=24)
    out = []
    with SessionLocal() as db:
        hosts = db.execute(select(WatchedHost).order_by(WatchedHost.name)).scalars().all()
        for h in hosts:
            events_24h = db.execute(select(func.count(HostEvent.id)).where(
                HostEvent.host_id == h.id, HostEvent.ts >= day_ago)).scalar() or 0
            downs_24h = db.execute(select(func.count(HostEvent.id)).where(
                HostEvent.host_id == h.id, HostEvent.ts >= day_ago, HostEvent.kind == "probe_down")).scalar() or 0
            out.append({
                "id": h.id, "name": h.name, "ip": h.ip, "mac": h.mac, "note": h.note, "enabled": h.enabled,
                "probe_port": h.probe_port, "resolved_ip": h.resolved_ip, "resolved_mac": h.resolved_mac,
                "probe_state": h.probe_state, "probe_state_since": _iso(h.probe_state_since),
                "last_probe_at": _iso(h.last_probe_at), "last_collect_at": _iso(h.last_collect_at),
                "last_error": h.last_error, "events_24h": events_24h, "outages_24h": downs_24h,
            })
    return out


# ── Report ───────────────────────────────────────────────────────────────────

def _external_state(ips: set) -> dict:
    """PRTG / Check_MK state for this host's IP — current-state context only
    (their change history isn't kept by the agent), read from the monitors'
    last cached poll without any extra request."""
    prtg, checkmk = [], []
    try:
        from services import prtg_monitor
        for s in prtg_monitor._cache.get("data") or []:
            if s.get("ip") in ips:
                prtg.append({"sensor": s.get("sensor_name"), "status": s.get("status_name"),
                             "message": s.get("message"), "problem": s.get("status") in (4, 5, 6, 10, 13, 14)})
    except Exception:
        pass
    try:
        from services import checkmk_monitor
        data = checkmk_monitor._cache.get("data") or {}
        for h in data.get("hosts", []):
            if h.get("ip") in ips:
                checkmk.append({"kind": "host", "name": h.get("host_name"), "state": h.get("state_name"),
                                "output": h.get("plugin_output"), "problem": h.get("state") != 0})
        for s in data.get("services", []):
            if s.get("ip") in ips:
                checkmk.append({"kind": "service", "name": s.get("description"), "state": s.get("state_name"),
                                "output": s.get("plugin_output"), "problem": s.get("state") != 0})
    except Exception:
        pass
    return {"prtg": prtg, "checkmk": checkmk}


def get_report(host_id: int, hours: int = 72) -> dict:
    now = datetime.now()
    hours = max(1, min(int(hours), RETENTION_DAYS * 24))
    range_start = now - timedelta(hours=hours)
    with SessionLocal() as db:
        h = db.get(WatchedHost, host_id)
        if not h:
            raise LookupError("host not found")
        rows = db.execute(
            select(HostEvent).where(HostEvent.host_id == host_id, HostEvent.ts >= range_start)
            .order_by(HostEvent.ts.desc()).limit(_MAX_REPORT_EVENTS)
        ).scalars().all()
        # probe up/down pairs can straddle the range start — look back a bit further for the opening "down"
        probe_rows = db.execute(
            select(HostEvent).where(HostEvent.host_id == host_id, HostEvent.kind.in_(("probe_down", "probe_up")),
                                    HostEvent.ts >= range_start - timedelta(days=7))
        ).scalars().all()
        host = {"id": h.id, "name": h.name, "ip": h.ip, "mac": h.mac, "note": h.note, "enabled": h.enabled,
                "probe_port": h.probe_port, "resolved_ip": h.resolved_ip, "resolved_mac": h.resolved_mac,
                "probe_state": h.probe_state, "probe_state_since": _iso(h.probe_state_since),
                "last_probe_at": _iso(h.last_probe_at), "last_collect_at": _iso(h.last_collect_at),
                "last_error": h.last_error, "created_at": _iso(h.created_at)}
        try:
            presence = json.loads(h.presence) if h.presence else None
        except ValueError:
            presence = None

    ev_dicts = [{"id": r.id, "ts": r.ts, "source": r.source, "kind": r.kind, "device": r.device_name,
                 "topics": r.topics, "message": r.message, "matched_on": r.matched_on,
                 "severity": r.severity, "data": json.loads(r.data) if r.data else None} for r in rows]
    outages = compute_outages([{"ts": r.ts, "kind": r.kind} for r in probe_rows], range_start, now)
    analysis = analyze(ev_dicts, outages, now)

    def _ser(o):
        return {k: (_iso(v) if isinstance(v, datetime) else v) for k, v in o.items()}

    ips = {i for i in (host["ip"], host["resolved_ip"]) if i}
    return {
        "host": host, "presence": presence, "hours": hours,
        "events": [_ser(e) for e in ev_dicts],
        "outages": [_ser(o) for o in outages],
        "findings": [_ser(f) for f in analysis["findings"]],
        "indicators": [_ser(i) for i in analysis["indicators"]],
        "summary": analysis["summary"],
        "external": _external_state(ips),
    }
