"""
How fast vulnerabilities are fixed, and which ones are knowingly left: the evidence an audit asks for (NIS2 art. 21(2)(e), ISO 27001 A.8.8).

The SLA itself (days from first seen to due, per severity) and the overdue alert already existed in services/vuln_scan.py. This module adds what was missing to prove that
the process works:

  * exceptions    a risk accepted on purpose (status accepted_risk) has a reason, who approved it and a date until which it is valid; after that date it is an open finding again
                  (and, past its SLA, an overdue one), so an exception cannot be forgotten;
  * resolution    a finding that the scan no longer finds is marked resolved with the time - so the time to fix, the share fixed within the SLA and the oldest still open can be
                  measured; one that comes back is reopened;
  * report()      the numbers: open / overdue / due within a week per severity, the SLA met share and the mean time to fix over the last 90 days, the exceptions with the days left
                  (and the expired ones), the oldest overdue findings;
  * settings      the SLA days per severity, changeable in the application (kept in data/vuln_sla.json; the environment variables stay the defaults).

Nothing here changes a host; it reads the findings and writes the bookkeeping rows (VulnRemediation).
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, VulnRemediation, VulnHost
from services import vuln_scan

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vuln_sla.json")
DEFAULT_EXCEPTION_DAYS = 90
MAX_EXCEPTION_DAYS = 365
OPEN = ("open", "in_progress")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_DEFAULT_DAYS = dict(vuln_scan.SLA_DAYS)


def load_settings() -> Dict[str, int]:
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        for k in SEVERITIES:
            if isinstance(saved.get(k), int) and 1 <= saved[k] <= 730:
                vuln_scan.SLA_DAYS[k] = saved[k]
    except Exception:
        pass
    return dict(vuln_scan.SLA_DAYS)


def settings() -> Dict[str, int]:
    return {k: vuln_scan.SLA_DAYS.get(k, _DEFAULT_DAYS.get(k, 0)) for k in SEVERITIES}


def update_settings(days: Dict[str, int]) -> Dict[str, int]:
    new = settings()
    for k, v in (days or {}).items():
        k = k.upper()
        if k not in SEVERITIES:
            raise ValueError(f"unknown severity {k}")
        v = int(v)
        if not 1 <= v <= 730:
            raise ValueError("the SLA is between 1 and 730 days")
        new[k] = v
    if not (new["CRITICAL"] <= new["HIGH"] <= new["MEDIUM"] <= new["LOW"]):
        raise ValueError("a more severe finding must not get more time than a less severe one")
    vuln_scan.SLA_DAYS.update(new)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(new, f)
    os.replace(tmp, _PATH)
    return settings()


def exception_until(valid_until: Optional[datetime], now: Optional[datetime] = None) -> datetime:
    """The end of an exception: the date given (at most a year ahead, not in the past), or 90 days from now."""
    now = now or datetime.utcnow()
    if valid_until is None:
        return now + timedelta(days=DEFAULT_EXCEPTION_DAYS)
    if valid_until <= now:
        raise ValueError("an exception must be valid until a date in the future")
    if valid_until > now + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValueError(f"an exception is valid for at most {MAX_EXCEPTION_DAYS} days; review it, then extend it")
    return valid_until


def maintain(current: set, scan_ok: bool, now: Optional[datetime] = None) -> dict:
    """Bookkeeping after a scan. `current` is the set of (product, version, cve_id) the hosts have now; `scan_ok` says the scan data can be trusted (it ran recently and found hosts).
    Returns {"resolved": n, "reopened": n, "expired": n}."""
    now = now or datetime.utcnow()
    out = {"resolved": 0, "reopened": 0, "expired": 0}
    with SessionLocal() as db:
        rows = db.execute(select(VulnRemediation)).scalars().all()
        for r in rows:
            key = (r.product, r.version, r.cve_id)
            if r.status == "accepted_risk" and r.valid_until and r.valid_until < now:
                r.status, r.updated_by, r.updated_at = "open", "auto", now
                r.note = ((r.note + " ") if r.note else "") + f"[exception expired {r.valid_until.date().isoformat()}]"
                out["expired"] += 1
            elif scan_ok and r.status in OPEN and key not in current and (current or len(rows) <= 5):
                r.status, r.resolved_at, r.updated_by, r.updated_at = "resolved", now, "auto", now
                r.note = ((r.note + " ") if r.note else "") + "[no longer found by the scan]"
                out["resolved"] += 1
            elif r.status == "resolved" and r.updated_by == "auto" and key in current:
                r.status, r.resolved_at, r.updated_by, r.updated_at = "open", None, "auto", now
                r.note = ((r.note + " ") if r.note else "") + "[found again]"
                out["reopened"] += 1
        db.commit()
    return out


async def run_maintenance() -> dict:
    """Called with every inventory rebuild. Never raises."""
    try:
        hosts = await vuln_scan.hosts_with_findings()
        current = {(f["product"], f["version"], f["cve_id"]) for h in hosts for f in h["findings"]}
        with SessionLocal() as db:
            newest = max((h.last_scan_at for h in db.execute(select(VulnHost)).scalars().all() if h.last_scan_at), default=None)
        scan_ok = bool(newest and datetime.utcnow() - newest < timedelta(days=10))
        return maintain(current, scan_ok)
    except Exception as e:
        print(f"[vuln_sla] maintenance skipped: {type(e).__name__}: {e}")
        return {"resolved": 0, "reopened": 0, "expired": 0}


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def report(now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    days = settings()
    since = now - timedelta(days=90)
    with SessionLocal() as db:
        rows = db.execute(select(VulnRemediation)).scalars().all()
    per = {s: {"open": 0, "overdue": 0, "due_7d": 0, "resolved_90d": 0, "met": 0, "_ttf": []} for s in SEVERITIES}
    overdue_list: List[dict] = []
    exceptions: List[dict] = []
    for r in rows:
        sev = (r.severity or "LOW").upper()
        if sev not in per:
            sev = "LOW"
        due = vuln_scan.sla_due_date(sev, r.first_seen_at)
        if r.status in OPEN:
            per[sev]["open"] += 1
            if due and now > due:
                per[sev]["overdue"] += 1
                overdue_list.append({"product": r.product, "version": r.version, "cve_id": r.cve_id, "severity": sev, "days_overdue": (now - due).days, "status": r.status, "first_seen": _iso(r.first_seen_at)})
            elif due and due - now <= timedelta(days=7):
                per[sev]["due_7d"] += 1
        elif r.status == "resolved" and r.resolved_at and r.resolved_at >= since and r.first_seen_at:
            per[sev]["resolved_90d"] += 1
            per[sev]["_ttf"].append((r.resolved_at - r.first_seen_at).total_seconds() / 86400)
            if due and r.resolved_at <= due:
                per[sev]["met"] += 1
        elif r.status == "accepted_risk":
            exceptions.append({"product": r.product, "version": r.version, "cve_id": r.cve_id, "severity": sev, "reason": r.note, "approved_by": r.approved_by or r.updated_by,
                               "valid_until": _iso(r.valid_until), "days_left": round((r.valid_until - now).total_seconds() / 86400, 1) if r.valid_until else None,
                               "expired": bool(r.valid_until and r.valid_until < now), "no_reason": not (r.note or "").strip(), "since": _iso(r.updated_at)})
    rows_out = []
    tot = {"open": 0, "overdue": 0, "due_7d": 0, "resolved_90d": 0, "met": 0}
    ttf_all: List[float] = []
    for s in SEVERITIES:
        p = per[s]
        ttf = p.pop("_ttf")
        ttf_all += ttf
        rows_out.append({"severity": s, "sla_days": days[s], **p, "met_pct": round(100 * p["met"] / p["resolved_90d"], 1) if p["resolved_90d"] else None, "mttr_days": round(sum(ttf) / len(ttf), 1) if ttf else None})
        for k in tot:
            tot[k] += p[k]
    overdue_list.sort(key=lambda x: (-x["days_overdue"], SEVERITIES.index(x["severity"])))
    exceptions.sort(key=lambda x: (x["days_left"] is None, x["days_left"] if x["days_left"] is not None else 0))
    return {"settings": days, "by_severity": rows_out, "totals": {**tot, "met_pct": round(100 * tot["met"] / tot["resolved_90d"], 1) if tot["resolved_90d"] else None,
                                                                    "mttr_days": round(sum(ttf_all) / len(ttf_all), 1) if ttf_all else None},
            "overdue": overdue_list[:25], "exceptions": exceptions, "exceptions_expiring_30d": sum(1 for e in exceptions if e["days_left"] is not None and 0 <= e["days_left"] <= 30),
            "exceptions_no_reason": sum(1 for e in exceptions if e["no_reason"])}
