"""
The SOC layer of the agent: alerts with a life of their own, built from everything the agent and the systems connected to it report.

Until now an alert event was a one-off message: it went to Central, Central matched its rules and sent a Telegram message, and the agent
kept only a type, a device and a count for the statistics. A SOC needs more than that - an alert that stays until somebody deals with it,
that is not raised a hundred times when the same thing repeats, that closes by itself when the thing recovers, that says who looked at
it and what was decided - and that is what this module keeps (`SocAlert`):

  ingest()      every alert event of one report cycle (WAN down, failed logins, a Wazuh rule, a Checkmk service ...) becomes an alert, or adds to
                the open one with the same fingerprint (family | device | detail); a recovery event (wan_up, tunnel_up, checkmk_service_ok ...)
                closes the matching alert by itself; an alert marked as a false positive stays one when the thing repeats (it is the exception);
  raise_alert() the same for the detection rules of the agent itself (services/soc_rules.py), which do not come as events;
  update()      the analyst's side: acknowledge, take, close, mark as a false positive, an owner, a note - each step written to the alert's trail;
  stats() / public_summary()  the numbers for the page and the compact view Central gets in the snapshot's plaintext metadata (no internal IP).

Only the detection and the triage state live here; the evidence stays on the agent (Central gets a title, a severity, a device name and the
few fields an analyst needs to decide whether to look).
"""
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, func, delete

from models.database import SessionLocal, SocAlert, Asset

SEVERITIES = ("info", "low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATUSES = ("new", "ack", "in_progress", "false_positive", "closed")
OPEN = ("new", "ack", "in_progress")
STALE_DAYS = 14          # an open alert of a one-off kind that has not recurred for this long is closed as stale
KEEP_DAYS = 90           # closed alerts and false positives are kept this long after their last occurrence
LOG_MAX = 60
PUBLIC_MAX = 80          # open alerts in the summary for Central
_TEXT_MAX = 300

# event type -> (family, kind, category, severity, MITRE ATT&CK technique, English title)
#   family: down / up events of one thing share it (and so their fingerprint)
#   kind:   problem  - opens an alert that stays until the recovery event comes (or somebody closes it)
#           recovery - closes the open alert of its family
#           event    - a one-off thing: an alert that is merged while it repeats and closed as stale when it stops
CATALOG: Dict[str, tuple] = {
    "failed_logins":              ("auth", "event", "auth", "medium", "T1110", "Repeated failed logins"),
    "login_after_failures":       ("authok", "event", "auth", "high", "T1110", "Successful login after failed attempts"),
    "device_rebooted":            ("reboot", "event", "system", "low", None, "Device rebooted"),
    "device_log_critical":        ("devlog", "event", "system", "medium", None, "Critical entries in the device log"),
    "wan_ip_changed":             ("wanip", "event", "network", "low", None, "WAN address changed"),
    "wan_down":                   ("wan", "problem", "availability", "high", None, "WAN link down"),
    "wan_up":                     ("wan", "recovery", "availability", "high", None, "WAN link up"),
    "tunnel_down":                ("tunnel", "problem", "availability", "high", None, "Tunnel down"),
    "tunnel_up":                  ("tunnel", "recovery", "availability", "high", None, "Tunnel up"),
    "host_service_down":          ("service", "problem", "availability", "medium", None, "Service not running"),
    "host_service_up":            ("service", "recovery", "availability", "medium", None, "Service running"),
    "asset_down":                 ("assetdown", "problem", "availability", "high", None, "Device not answering"),
    "asset_up":                   ("assetdown", "recovery", "availability", "high", None, "Device answering"),
    "bizservice_problem":         ("bizsvc", "problem", "availability", "medium", None, "Business service impaired"),
    "bizservice_ok":              ("bizsvc", "recovery", "availability", "medium", None, "Business service restored"),
    "hostmon_host_down":          ("hostmon", "problem", "availability", "medium", None, "Host not answering"),
    "hostmon_host_up":            ("hostmon", "recovery", "availability", "medium", None, "Host answering"),
    "idrac_unreachable":          ("idrac", "problem", "hardware", "high", None, "iDRAC unreachable"),
    "idrac_reachable":            ("idrac", "recovery", "hardware", "high", None, "iDRAC reachable"),
    "idrac_health_degraded":      ("idrac_health", "event", "hardware", "high", None, "Server hardware health degraded"),
    "interface_errors":           ("iferr", "event", "network", "low", None, "Interface errors"),
    "interface_overload":         ("ifload", "event", "network", "medium", None, "Interface overloaded"),
    "memory_high":                ("memory", "event", "resource", "medium", None, "Memory use high"),
    "disk_space_low":             ("disk", "event", "resource", "medium", None, "Disk space low"),
    "hyperv_vm_down":             ("hvvm", "problem", "availability", "medium", None, "Virtual machine stopped"),
    "hyperv_vm_up":               ("hvvm", "recovery", "availability", "medium", None, "Virtual machine running"),
    "hyperv_host_down":           ("hvhost", "problem", "availability", "high", None, "Hyper-V host unreachable"),
    "hyperv_host_up":             ("hvhost", "recovery", "availability", "high", None, "Hyper-V host reachable"),
    "hyperv_vm_no_heartbeat":     ("hvbeat", "event", "availability", "medium", None, "VM without heartbeat"),
    "hyperv_snapshot_old":        ("hvsnap", "event", "system", "low", None, "Old VM snapshot"),
    "hyperv_replication_problem": ("hvrepl", "event", "availability", "medium", None, "VM replication problem"),
    "hyperv_host_pressure":       ("hvpress", "event", "resource", "medium", None, "Hyper-V host under pressure"),
    "vuln_overdue":               ("vulnover", "event", "vulnerability", "medium", None, "Vulnerability scan overdue"),
    "wazuh_alert":                ("wazuh", "event", "detection", "medium", None, "Wazuh alert"),
    "prtg_sensor_down":           ("prtg", "problem", "availability", "medium", None, "PRTG sensor down"),
    "prtg_sensor_up":             ("prtg", "recovery", "availability", "medium", None, "PRTG sensor up"),
    "checkmk_service_problem":    ("cmkservice", "problem", "availability", "medium", None, "Checkmk service problem"),
    "checkmk_service_ok":         ("cmkservice", "recovery", "availability", "medium", None, "Checkmk service OK"),
    "checkmk_host_down":          ("cmkhost", "problem", "availability", "high", None, "Checkmk host down"),
    "checkmk_host_up":            ("cmkhost", "recovery", "availability", "high", None, "Checkmk host up"),
}

# fields that tell two things of one family apart (a tunnel of a router, a service of a host, a sensor, an interface ...)
_DETAIL_KEYS = ("tunnel_type", "tunnel_name", "iface", "interface", "service_name", "sensor_name", "description", "rule_description", "rule_id",
                "mount", "vm_name", "kind")
# what of an event is kept as the alert's evidence
_EVIDENCE_KEYS = ("sources", "users", "count", "window_sec", "threshold", "log_message", "log_time", "rule_level", "rule_id", "rule_description",
                  "agent_name", "plugin_output", "state_name", "status_name", "message", "sensor_name", "service", "tunnel_type", "tunnel_name",
                  "iface", "interface", "detail", "from_state", "to_state", "duration_sec", "description", "mount", "vm_name", "groups", "mitre",
                  "src_ip", "user", "location", "path", "cve", "package", "vuln_severity", "tactics", "full_log", "affected")

_last_housekeeping = [0.0]
_seen_events: Dict[tuple, float] = {}      # (type, fingerprint, detected_at) of the events already taken in, so a repeated copy counts once
_SEEN_KEEP_SEC = 4 * 3600


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _cut(v):
    """A value that is safe to keep and send: strings cut, lists cut and cleaned, nested things left out."""
    if isinstance(v, str):
        return v[:_TEXT_MAX]
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_cut(x) for x in list(v)[:10] if isinstance(x, (str, int, float))]
    return None


def classify(e: dict) -> dict:
    """What kind of alert an event is: {type, family, kind, category, severity, mitre, title, source}."""
    t = str(e.get("type") or "")
    fam, kind, cat, sev, mitre, title = CATALOG.get(t) or (t, "event", "other", "low", None, t.replace("_", " ").capitalize())
    try:
        count = int(e.get("count") or 1)
    except (TypeError, ValueError):
        count = 1
    if t == "failed_logins" and count >= 20:
        sev = "high"
    elif t == "login_after_failures" and count >= 5:
        sev = "critical"
    elif t == "bizservice_problem" and e.get("state") == "down":
        sev = "critical"                       # a degraded service is medium: it still works
    elif t == "wazuh_alert":
        try:
            lvl = int(e.get("rule_level") or 0)
        except (TypeError, ValueError):
            lvl = 0
        sev = "critical" if lvl >= 13 else "high" if lvl >= 11 else "medium" if lvl >= 8 else "low"
        if e.get("mitre"):
            mitre = ",".join(str(x) for x in (e["mitre"] if isinstance(e["mitre"], (list, tuple)) else [e["mitre"]]))[:120]
        groups = [str(g) for g in (e.get("groups") or [])]
        if "vulnerability-detector" in groups or e.get("cve"):
            cat = "vulnerability"
        elif any(g.startswith("authentication") or g in ("invalid_login", "adduser", "account_changed", "win_group_changed") for g in groups):
            cat = "auth"
    source = "wazuh" if t.startswith("wazuh_") else "checkmk" if t.startswith("checkmk_") else "prtg" if t.startswith("prtg_") else "agent"
    return {"type": t, "family": fam, "kind": kind, "category": cat, "severity": sev, "mitre": mitre, "title": title, "source": source}


def _device_of(e: dict) -> Optional[str]:
    return (e.get("device_name") or e.get("server_name") or e.get("host_name") or e.get("agent_name") or None)


def fingerprint(family: str, device: Optional[str], e: dict) -> str:
    """The identity of an alert: the family, the device and whatever tells two of them on one device apart."""
    detail = "|".join(str(e[k]) for k in _DETAIL_KEYS if e.get(k) not in (None, ""))
    return f"{family}|{(device or '').strip().lower()}|{detail}"[:240]


def _evidence(e: dict) -> dict:
    out = {}
    for k in _EVIDENCE_KEYS:
        if k in e:
            v = _cut(e[k])
            if v not in (None, "", []):
                out[k] = v
    return out


def _log(row: SocAlert, who: str, action: str, value=None, now: Optional[datetime] = None) -> None:
    try:
        entries = json.loads(row.log) if row.log else []
    except Exception:
        entries = []
    entry = {"t": _iso(now or _now()), "who": who, "a": action}
    if value is not None:
        entry["v"] = value
    entries.append(entry)
    row.log = json.dumps(entries[-LOG_MAX:], ensure_ascii=False)


def _asset_id(db, ip: Optional[str], name: Optional[str]) -> Optional[int]:
    """The inventory asset an alert is about: by address, else by name ("host: vm" names of the VM events are cut at the colon)."""
    try:
        if ip:
            r = db.execute(select(Asset.id).where(Asset.ip == ip).limit(1)).first()
            if r:
                return r[0]
        if name:
            base = name.split(":")[0].strip().lower()
            if base:
                r = db.execute(select(Asset.id).where(func.lower(Asset.name) == base).limit(1)).first()
                if r:
                    return r[0]
    except Exception:
        pass
    return None


def _correlate(db, row: SocAlert, now: datetime) -> None:
    """An availability alert about something behind a device that is down (per services/availability.py) is a consequence of that device's
    fault: it is marked with it (the page shows it as such and the risk score does not count it twice)."""
    if row.root_asset_id or row.category != "availability" or row.rule == "asset_down" or not row.asset_id:
        return
    try:
        from services import availability
        root = availability.upstream_down(db, row.asset_id)
    except Exception:
        root = None
    if root:
        row.root_asset_id, row.root_name = root
        _log(row, "auto", "correlated", root[1], now)


def _upsert(db, *, fp: str, rule: str, source: str, category: str, severity: str, title: str, device: Optional[str], ip: Optional[str],
            detail: dict, count: int, mitre: Optional[str], now: datetime, asset_id: Optional[int] = None) -> str:
    """One alert for one fingerprint: the open one (or the false positive) gets the occurrence added, otherwise a new one is opened."""
    row = db.execute(
        select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.status.in_(OPEN + ("false_positive",))).order_by(SocAlert.id.desc()).limit(1)
    ).scalars().first()
    rank = RANK.get(severity, 1)
    if row is not None:
        row.count = (row.count or 0) + max(1, count)
        row.last_seen = now
        if detail:
            row.detail = json.dumps(detail, ensure_ascii=False)
        if rank > (row.rank or 0) and row.status != "false_positive":
            row.rank, row.severity = rank, severity
            _log(row, "auto", "escalated", severity, now)
        if ip and not row.ip:
            row.ip = ip
        _correlate(db, row, now)
        return "updated"
    if asset_id is None:
        asset_id = _asset_id(db, ip, device)
    row = SocAlert(fingerprint=fp, rule=rule, source=source, category=category, severity=severity, rank=rank, title=title,
                   device_name=(device or None), ip=ip, asset_id=asset_id, detail=json.dumps(detail, ensure_ascii=False) if detail else None,
                   status="new", count=max(1, count), mitre=mitre, first_seen=now, last_seen=now)
    _log(row, "auto", "opened", severity, now)
    _correlate(db, row, now)
    db.add(row)
    db.flush()                       # the session does not autoflush: a repeat in the same batch must find this row
    return "opened"


def _close_recovered(db, fp: str, now: datetime, e: dict) -> int:
    db.flush()
    rows = db.execute(select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.status.in_(OPEN))).scalars().all()
    for r in rows:
        r.status, r.closed_at, r.closed_by = "closed", now, "auto: recovered"
        _log(r, "auto", "recovered", e.get("duration_sec"), now)
    return len(rows)


def ingest(events: List[dict], now: Optional[datetime] = None) -> dict:
    """The alert events of one report cycle -> alerts. Never raises into the caller's loop (a failure is logged and the events are lost
    for the SOC only - they still go to Central the old way)."""
    now = now or _now()
    opened = updated = closed = 0
    clock = time.time()
    for k in [k for k, v in _seen_events.items() if clock - v > _SEEN_KEEP_SEC]:
        del _seen_events[k]
    try:
        with SessionLocal() as db:
            for e in events or []:
                if not isinstance(e, dict) or not e.get("type"):
                    continue
                c = classify(e)
                device = _device_of(e)
                fp = fingerprint(c["family"], device, e)
                if e.get("detected_at"):
                    key = (c["type"], fp, str(e["detected_at"]))
                    if key in _seen_events:
                        continue
                    _seen_events[key] = clock
                if c["kind"] == "recovery":
                    closed += _close_recovered(db, fp, now, e)
                    continue
                try:
                    count = max(1, int(e.get("count") or 1))
                except (TypeError, ValueError):
                    count = 1
                r = _upsert(db, fp=fp, rule=c["type"], source=c["source"], category=c["category"], severity=c["severity"], title=c["title"],
                            device=device, ip=e.get("ip") or e.get("device_ip"), detail=_evidence(e), count=count, mitre=c["mitre"], now=now,
                            asset_id=e.get("asset_id") if isinstance(e.get("asset_id"), int) else None)
                opened += r == "opened"
                updated += r == "updated"
            db.commit()
        housekeeping(now)
    except Exception as ex:
        print(f"[soc] ingest error: {type(ex).__name__}: {ex}")
    return {"opened": opened, "updated": updated, "closed": closed}


def raise_alert(*, rule: str, device: Optional[str], title: str, severity: str = "medium", category: str = "detection", fp_detail: str = "",
                ip: Optional[str] = None, detail: Optional[dict] = None, count: int = 1, mitre: Optional[str] = None, source: str = "rules",
                asset_id: Optional[int] = None, now: Optional[datetime] = None) -> str:
    """An alert from a detection rule of the agent itself (not from an event). Returns "opened" / "updated"."""
    now = now or _now()
    severity = severity if severity in RANK else "medium"
    fp = f"{rule}|{(device or '').strip().lower()}|{fp_detail}"[:240]
    with SessionLocal() as db:
        r = _upsert(db, fp=fp, rule=rule, source=source, category=category, severity=severity, title=title, device=device, ip=ip,
                    detail={k: _cut(v) for k, v in (detail or {}).items() if _cut(v) not in (None, "", [])}, count=count, mitre=mitre, now=now,
                    asset_id=asset_id)
        db.commit()
    return r


def resolve(*, rule: str, device: Optional[str], fp_detail: str = "", who: str = "auto: recovered", now: Optional[datetime] = None) -> int:
    """Closes the open alert a rule raised once the condition is gone."""
    now = now or _now()
    fp = f"{rule}|{(device or '').strip().lower()}|{fp_detail}"[:240]
    with SessionLocal() as db:
        n = _close_recovered(db, fp, now, {})
        db.commit()
    return n


def housekeeping(now: Optional[datetime] = None, force: bool = False) -> None:
    """Closes the open one-off alerts that have not recurred for STALE_DAYS and forgets what is older than KEEP_DAYS. At most every 10 minutes."""
    if not force and time.time() - _last_housekeeping[0] < 600:
        return
    _last_housekeeping[0] = time.time()
    now = now or _now()
    with SessionLocal() as db:
        stale = db.execute(select(SocAlert).where(SocAlert.status.in_(OPEN), SocAlert.last_seen < now - timedelta(days=STALE_DAYS))).scalars().all()
        for r in stale:
            kind = (CATALOG.get(r.rule) or (None, "event"))[1]
            if kind == "problem":
                continue                    # a problem stays open until its recovery arrives (or somebody closes it)
            r.status, r.closed_at, r.closed_by = "closed", now, "auto: stale"
            _log(r, "auto", "stale", None, now)
        db.execute(delete(SocAlert).where(SocAlert.status.in_(("closed", "false_positive")), SocAlert.last_seen < now - timedelta(days=KEEP_DAYS)))
        db.commit()


# ── The analyst's side ───────────────────────────────────────────────────────

def update(ids: List[int], *, status: Optional[str] = None, owner: Optional[str] = None, note: Optional[str] = None,
           who: str = "?", set_owner: bool = False, set_note: bool = False) -> int:
    """Status / owner / note of the alerts with these ids; every change goes into the alert's trail. Returns how many were changed."""
    if status is not None and status not in STATUSES:
        raise ValueError("unknown status")
    now = _now()
    n = 0
    with SessionLocal() as db:
        for r in db.execute(select(SocAlert).where(SocAlert.id.in_([int(i) for i in ids]))).scalars().all():
            changed = False
            if status is not None and status != r.status:
                r.status = status
                if status in ("closed", "false_positive"):
                    r.closed_at, r.closed_by = now, who
                else:
                    r.closed_at, r.closed_by = None, None
                _log(r, who, "status", status, now)
                changed = True
            if set_owner and (owner or None) != r.owner:
                r.owner = (owner or None)
                _log(r, who, "owner", r.owner, now)
                changed = True
            if set_note and (note or None) != r.note:
                r.note = (note or None)
                _log(r, who, "note", None, now)
                changed = True
            n += changed
        db.commit()
    return n


def _row(a: SocAlert, full: bool = True) -> dict:
    try:
        detail = json.loads(a.detail) if a.detail else {}
    except Exception:
        detail = {}
    out = {
        "id": a.id, "rule": a.rule, "source": a.source, "category": a.category, "severity": a.severity, "title": a.title,
        "device_name": a.device_name, "ip": a.ip, "asset_id": a.asset_id, "status": a.status, "owner": a.owner, "count": a.count,
        "mitre": a.mitre, "first_seen": _iso(a.first_seen), "last_seen": _iso(a.last_seen), "closed_at": _iso(a.closed_at), "closed_by": a.closed_by,
        "detail": detail, "root_asset_id": a.root_asset_id, "root_name": a.root_name,
    }
    if full:
        out["note"] = a.note
        try:
            out["log"] = json.loads(a.log) if a.log else []
        except Exception:
            out["log"] = []
    return out


def list_alerts(*, status: str = "open", severity: Optional[str] = None, category: Optional[str] = None, source: Optional[str] = None,
                q: Optional[str] = None, limit: int = 300, offset: int = 0) -> dict:
    """status: open | all | closed | one of STATUSES. Open alerts: the worst and the most recent first."""
    stmt = select(SocAlert)
    if status == "open":
        stmt = stmt.where(SocAlert.status.in_(OPEN))
    elif status == "closed":
        stmt = stmt.where(SocAlert.status.in_(("closed", "false_positive")))
    elif status in STATUSES:
        stmt = stmt.where(SocAlert.status == status)
    if severity in RANK:
        stmt = stmt.where(SocAlert.severity == severity)
    if category:
        stmt = stmt.where(SocAlert.category == category)
    if source:
        stmt = stmt.where(SocAlert.source == source)
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(func.lower(func.coalesce(SocAlert.device_name, "")).like(like) | func.lower(SocAlert.rule).like(like)
                          | func.lower(func.coalesce(SocAlert.title, "")).like(like) | func.lower(func.coalesce(SocAlert.detail, "")).like(like))
    with SessionLocal() as db:
        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar() or 0
        order = (SocAlert.rank.desc(), SocAlert.last_seen.desc()) if status == "open" else (SocAlert.last_seen.desc(),)
        rows = db.execute(stmt.order_by(*order).limit(max(1, min(limit, 1000))).offset(max(0, offset))).scalars().all()
        items = [_row(r, full=False) for r in rows]
    return {"total": total, "items": items}


def get_alert(alert_id: int) -> Optional[dict]:
    with SessionLocal() as db:
        a = db.get(SocAlert, alert_id)
        return _row(a) if a else None


# ── Numbers ──────────────────────────────────────────────────────────────────

def stats(now: Optional[datetime] = None) -> dict:
    now = now or _now()
    day = now - timedelta(hours=24)
    week = now - timedelta(days=7)
    with SessionLocal() as db:
        opens = db.execute(select(SocAlert).where(SocAlert.status.in_(OPEN))).scalars().all()
        closed7 = db.execute(select(SocAlert).where(SocAlert.status == "closed", SocAlert.closed_at >= week)).scalars().all()
        opened7 = db.execute(select(SocAlert.first_seen).where(SocAlert.first_seen >= week)).scalars().all()
        fp7 = db.execute(select(func.count()).select_from(SocAlert).where(SocAlert.status == "false_positive", SocAlert.last_seen >= week)).scalar() or 0
    by_sev = {s: 0 for s in SEVERITIES}
    by_cat: Dict[str, int] = {}
    by_dev: Dict[str, int] = {}
    for a in opens:
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        by_cat[a.category] = by_cat.get(a.category, 0) + 1
        if a.device_name:
            by_dev[a.device_name] = by_dev.get(a.device_name, 0) + 1
    # time to resolve: only alerts an analyst closed - an alert that closed by itself (recovered / stale) says nothing about the analysts
    handled = [(a.closed_at - a.first_seen).total_seconds() for a in closed7 if a.closed_at and a.closed_by and not a.closed_by.startswith("auto")]
    daily = {}
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)
    for i in range(7):
        daily[start + timedelta(days=i)] = 0
    for ts in opened7:
        k = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        if k in daily:
            daily[k] += 1
    return {
        "open": len(opens), "new": sum(1 for a in opens if a.status == "new"), "in_progress": sum(1 for a in opens if a.status == "in_progress"),
        "by_severity": by_sev, "by_category": by_cat,
        "top_devices": [{"name": k, "n": v} for k, v in sorted(by_dev.items(), key=lambda kv: -kv[1])[:8]],
        "opened_24h": sum(1 for ts in opened7 if ts >= day), "closed_24h": sum(1 for a in closed7 if a.closed_at and a.closed_at >= day),
        "false_positive_7d": fp7,
        "mttr_hours": round(sum(handled) / len(handled) / 3600, 1) if handled else None,
        "opened_daily": [{"t": k.isoformat() + "Z", "n": n} for k, n in sorted(daily.items())],
        "oldest_new_hours": round(max(((now - a.first_seen).total_seconds() for a in opens if a.status == "new"), default=0) / 3600, 1) or None,
    }


def public_summary() -> dict:
    """What Central gets (plaintext metadata of the snapshot): the numbers and the open alerts, worst first, with a title, a device name and the
    few evidence fields an analyst needs - no internal address, no log text. Cut to PUBLIC_MAX."""
    now = _now()
    try:
        st = stats(now)
        with SessionLocal() as db:
            rows = db.execute(select(SocAlert).where(SocAlert.status.in_(OPEN)).order_by(SocAlert.rank.desc(), SocAlert.last_seen.desc()).limit(PUBLIC_MAX)).scalars().all()
        alerts = []
        for a in rows:
            r = _row(a, full=False)
            d = {k: v for k, v in r["detail"].items() if k in ("sources", "users", "rule_description", "rule_level", "service", "plugin_output", "message",
                                                                 "tunnel_name", "iface", "sensor_name", "description", "state_name", "groups", "mitre",
                                                                 "cve", "package", "vuln_severity", "src_ip", "user", "tactics", "exploited", "epss")}
            alerts.append({"id": a.id, "rule": a.rule, "source": a.source, "category": a.category, "severity": a.severity, "title": a.title,
                           "device": a.device_name, "asset": a.asset_id, "status": a.status, "owner": a.owner, "count": a.count, "first": r["first_seen"], "last": r["last_seen"],
                           "mitre": a.mitre, "detail": d, "root": a.root_name})
        st.pop("top_devices", None)
        return {"at": _iso(now), "stats": st, "alerts": alerts}
    except Exception as e:
        print(f"[soc] public summary error: {type(e).__name__}: {e}")
        return {"at": _iso(now), "stats": None, "alerts": []}
