"""
Requirements of NIS2 (art. 21(2)) and ISO/IEC 27001:2022 mapped onto what the application actually measures - the evidence an auditor or a manager asks for.

Each requirement lists CHECKS; a check is one fact the application can read right now (a share, a count, an age), with a status:

  ok        the measured value meets the bar
  warn      it works but falls short (an overdue item, an old backup, a share under the bar)
  gap       the application measures it and it is clearly not met
  manual    the requirement needs a person or a document (a policy, a training record, a restore test) - the application cannot show it
  external  it is handled outside the application (the incident register in ServiceDesk)
  na        nothing to measure yet (no data)

A requirement's own status is the worst of its measured checks (ok / warn / gap); one with only manual or external checks is `manual`. The numbers are read from the data the application
already keeps; nothing is estimated, and a check that cannot be read says so (`error`) instead of passing. The thresholds are the ones used here (documented per check), not the law's:
NIS2 and the Polish KSC act do not give percentages, they require appropriate measures - the bar is a judgement, to be set by whoever is accountable.

This is a map of evidence, not an assessment of compliance: it does not replace the risk analysis, the policies, the audit of an accredited auditor or legal advice.
"""
import json
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import select, func

from models.database import (SessionLocal, Asset, AppAccount, AuditLog, ComplianceCheckResult, ConfigCheck, Device, DeviceBackup, WindowsHost, LinuxHost, BizService, SyslogEvent, SocAlert)

BAR_OK = 90.0                   # a share at or above this is ok
BAR_WARN = 60.0                 # between BAR_WARN and BAR_OK is a warning, below is a gap
BACKUP_DAYS = 14
CONFIG_CHECK_HOURS = 48
KEY_ROTATION_DAYS = 365
LOG_RETENTION_BAR = 90          # days of kept logs below which the retention is a warning


def _share(part: int, total: int) -> Optional[float]:
    return round(100.0 * part / total, 1) if total else None


def _by_share(pct: Optional[float]) -> str:
    if pct is None:
        return "na"
    return "ok" if pct >= BAR_OK else ("warn" if pct >= BAR_WARN else "gap")


def _c(key: str, status: str, link: Optional[str] = None, **params) -> dict:
    return {"key": key, "status": status, "params": params, "link": link}


def _safe(key: str, fn: Callable[[], Any]) -> List[dict]:
    try:
        r = fn()
        return r if isinstance(r, list) else [r]
    except Exception as e:
        return [{"key": key, "status": "na", "params": {}, "link": None, "error": f"{type(e).__name__}: {e}"[:160]}]


# ── the checks ───────────────────────────────────────────────────────────────

def _inventory() -> List[dict]:
    from services import asset_lifecycle
    with SessionLocal() as db:
        rows = [a for a in db.execute(select(Asset)).scalars().all() if not a.key.startswith(("mon:", "prt:"))]
    total = len(rows)
    owner = sum(1 for a in rows if a.owner)
    crit = sum(1 for a in rows if a.criticality)
    scanned = sum(1 for a in rows if a.scan_level in ("credentialed", "snmp"))
    eol = sum(1 for a in rows if a.os_name and asset_lifecycle.lifecycle(a.os_name, a.os_version).get("status") == "eol")
    out = [_c("inventory_total", "ok" if total else "gap", "/inventory/list", total=total),
           _c("owner_share", _by_share(_share(owner, total)), "/inventory/list", pct=_share(owner, total), n=owner, total=total),
           _c("criticality_share", _by_share(_share(crit, total)), "/inventory/list", pct=_share(crit, total), n=crit, total=total),
           _c("scan_depth", _by_share(_share(scanned, total)), "/inventory", pct=_share(scanned, total), n=scanned, total=total),
           _c("eol_systems", "ok" if eol == 0 else "warn", "/inventory", n=eol)]
    return out


def _vuln_checks() -> List[dict]:
    from services import vuln_sla
    r = vuln_sla.report()
    t = r["totals"]
    out = [_c("sla_overdue", "ok" if t["overdue"] == 0 else ("warn" if t["overdue"] <= 5 else "gap"), "/vulnerabilities/sla", n=t["overdue"], open=t["open"]),
           _c("sla_met", _by_share(t["met_pct"]), "/vulnerabilities/sla", pct=t["met_pct"], n=t["resolved_90d"]),
           _c("mttr", "na" if t["mttr_days"] is None else "ok", "/vulnerabilities/sla", days=t["mttr_days"]),
           _c("exceptions", "warn" if (r["exceptions_no_reason"] or r["exceptions_expiring_30d"]) else "ok", "/vulnerabilities/sla", n=len(r["exceptions"]), no_reason=r["exceptions_no_reason"], expiring=r["exceptions_expiring_30d"])]
    return out


async def _kev() -> List[dict]:
    from services import vuln_scan
    hosts = await vuln_scan.hosts_with_findings()
    kev = {(f["product"], f["version"], f["cve_id"]) for h in hosts for f in h["findings"] if f.get("kev") and (f.get("status") or "open") in ("open", "in_progress")}
    return [_c("kev_open", "ok" if not kev else "gap", "/vulnerabilities", n=len(kev))]


def _updates() -> List[dict]:
    with SessionLocal() as db:
        win = db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all()  # noqa: E712
        lin = db.execute(select(LinuxHost).where(LinuxHost.managed == True)).scalars().all()
    hosts = len(win) + len(lin)
    pending = sum(1 for h in win + lin if (h.upgradable_count or 0) > 0)
    reboot = sum(1 for h in win + lin if h.reboot_required)
    if hosts == 0:
        return [_c("patch_pending", "na", "/windows")]
    return [_c("patch_pending", _by_share(100.0 - (_share(pending, hosts) or 0)), "/windows", n=pending, total=hosts, reboot=reboot)]


def _coverage() -> List[dict]:
    from services import coverage
    s = coverage.report()["summary"]
    bad = s.get("stale", 0) + s.get("error", 0)
    return [_c("sources_reporting", "ok" if bad == 0 else ("warn" if bad <= 2 else "gap"), "/soc/coverage", bad=bad, ok=s.get("ok", 0))]


def _soc() -> List[dict]:
    from services import soc
    st = soc.stats()
    sev = st.get("by_severity", {})
    crit = sev.get("critical", 0) + sev.get("high", 0)
    return [_c("alerts_open", "ok" if crit == 0 else "warn", "/soc", open=st.get("open", 0), high=crit)]


def _servicedesk() -> List[dict]:
    from services import servicedesk_client
    return [_c("incident_register", "external", None, configured=bool(servicedesk_client.is_configured()))]


def _logging() -> List[dict]:
    from services import syslog_receiver
    sl = syslog_receiver.settings()
    keep = syslog_receiver.KEEP_DAYS
    with SessionLocal() as db:
        first = db.execute(select(func.min(AuditLog.ts))).scalar()
        n = db.execute(select(func.count()).select_from(AuditLog)).scalar() or 0
    age = int((datetime.utcnow() - first).total_seconds() / 86400) if first else 0
    return [_c("syslog_on", "ok" if sl.get("enabled") else "warn", "/soc/syslog", enabled=bool(sl.get("enabled"))),
            _c("log_retention", "ok" if keep >= LOG_RETENTION_BAR else "warn", "/soc/syslog", days=keep, bar=LOG_RETENTION_BAR),
            _c("audit_log", "ok" if n else "gap", "/audit", n=n, days=age),
            _c("time_sync", "manual")]


def _config() -> List[dict]:
    from services import config_history
    cutoff = datetime.utcnow() - timedelta(hours=CONFIG_CHECK_HOURS)
    with SessionLocal() as db:
        devs = [d for d in db.execute(select(Device)).scalars().all() if (d.vendor or "mikrotik") in config_history.SUPPORTED]
        checks = {c.device_id: c for c in db.execute(select(ConfigCheck)).scalars().all()}
        month = datetime.utcnow() - timedelta(days=30)
        changed = sum(1 for c in checks.values() if c.last_change_at and c.last_change_at >= month)
    fresh = sum(1 for d in devs if d.id in checks and checks[d.id].last_check_at and checks[d.id].last_check_at >= cutoff)
    return [_c("config_tracked", _by_share(_share(fresh, len(devs))), "/config-history", pct=_share(fresh, len(devs)), n=fresh, total=len(devs)),
            _c("config_changes", "ok", "/config-history", n=changed),
            _c("change_approval", "external")]


def _continuity() -> List[dict]:
    from services import drp_docs, agent_backup
    cutoff = datetime.utcnow() - timedelta(days=BACKUP_DAYS)
    with SessionLocal() as db:
        devs = db.execute(select(Device)).scalars().all()
        latest = {i: t for i, t in db.execute(select(DeviceBackup.device_id, func.max(DeviceBackup.created_at)).group_by(DeviceBackup.device_id)).all()}
        services = db.execute(select(func.count()).select_from(BizService)).scalar() or 0
    ok = sum(1 for d in devs if latest.get(d.id) and latest[d.id] >= cutoff)
    drp = drp_docs.status().get("last_generated_at")
    ab = agent_backup.status().get("last_backup_at")

    def age(v):
        try:
            return int((datetime.utcnow() - (v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "")))).total_seconds() / 86400) if v else None
        except (ValueError, TypeError):
            return None
    d_age, a_age = age(drp), age(ab)
    return [_c("device_backups", _by_share(_share(ok, len(devs))), "/mikrotik", pct=_share(ok, len(devs)), n=ok, total=len(devs), days=BACKUP_DAYS),
            _c("drp_doc", "na" if d_age is None else ("ok" if d_age <= 100 else "warn"), None, days=d_age),
            _c("agent_backup", "na" if a_age is None else ("ok" if a_age <= 14 else "warn"), None, days=a_age),
            _c("business_services", "ok" if services else "gap", "/services", n=services),
            _c("restore_test", "manual"), _c("rto_rpo", "manual")]


def _crypto() -> List[dict]:
    from services import tls_scan, crypto
    s = tls_scan.public_summary()
    ks = crypto.key_status().get("key_created_at")
    key_age = int((datetime.utcnow() - datetime.fromisoformat(ks)).total_seconds() / 86400) if ks else None
    return [_c("tls_certs", "na" if s["total"] == 0 else ("ok" if (s["expired"] + s["expiring"] + s["weak"]) == 0 else ("gap" if s["expired"] else "warn")), "/soc/tls", total=s["total"], expired=s["expired"], expiring=s["expiring"], weak=s["weak"]),
            _c("key_rotation", "na" if key_age is None else ("ok" if key_age <= KEY_ROTATION_DAYS else "warn"), "/security", days=key_age, bar=KEY_ROTATION_DAYS)]


def _access() -> List[dict]:
    with SessionLocal() as db:
        accounts = db.execute(select(AppAccount)).scalars().all()
    n = len(accounts)
    mfa = sum(1 for a in accounts if a.mfa_enabled)
    return [_c("mfa_accounts", "na" if n == 0 else ("ok" if mfa == n else "gap"), "/security", n=mfa, total=n),
            _c("rbac", "warn", None), _c("access_review", "manual"), _c("https", "manual")]


def _hardening() -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(ComplianceCheckResult)).scalars().all()
    total = len(rows)
    passed = sum(1 for r in rows if r.passed)
    wan = [r for r in rows if r.check_id == "mikrotik.wan_management_restricted"]
    wan_ok = sum(1 for r in wan if r.passed)
    return [_c("hardening_pass", _by_share(_share(passed, total)), "/compliance", pct=_share(passed, total), n=passed, total=total),
            _c("wan_management", _by_share(_share(wan_ok, len(wan))), "/compliance", pct=_share(wan_ok, len(wan)), n=wan_ok, total=len(wan))]


def _supply() -> List[dict]:
    from services import supply_chain
    last = supply_chain.status().get("last_run")
    age = None
    if last:
        try:
            age = int((datetime.utcnow() - (datetime.utcfromtimestamp(last) if isinstance(last, (int, float)) else datetime.fromisoformat(str(last).replace("Z", "")))).total_seconds() / 86400)
        except (ValueError, TypeError, OSError):
            age = None
    return [_c("supply_scan", "na" if age is None else ("ok" if age <= 14 else "warn"), None, days=age), _c("supplier_register", "manual")]


def _risk() -> List[dict]:
    with SessionLocal() as db:
        n = db.execute(select(func.count()).select_from(Asset)).scalar() or 0
    return [_c("risk_score", "ok" if n else "na", "/soc/risk", n=n), _c("risk_register", "manual"), _c("policies", "manual")]


# ── the requirements ─────────────────────────────────────────────────────────

# id, framework refs (NIS2 article part, ISO 27001:2022 clauses / Annex A controls), and the builders of its checks
REQUIREMENTS = [
    {"id": "risk", "nis2": "21(2)(a)", "iso": ["6.1.2", "A.5.1", "A.5.7"], "checks": [("risk", _risk)]},
    {"id": "incident", "nis2": "21(2)(b), 23", "iso": ["A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.5.28"], "checks": [("soc", _soc), ("incident_register", _servicedesk)]},
    {"id": "continuity", "nis2": "21(2)(c)", "iso": ["A.5.29", "A.5.30", "A.8.13", "A.8.14"], "checks": [("continuity", _continuity)]},
    {"id": "supply", "nis2": "21(2)(d)", "iso": ["A.5.19", "A.5.20", "A.5.21", "A.5.22"], "checks": [("supply", _supply)]},
    {"id": "vulnerability", "nis2": "21(2)(e)", "iso": ["A.8.8", "A.8.19", "A.8.32"], "checks": [("vuln", _vuln_checks), ("kev", _kev), ("updates", _updates)]},
    {"id": "effectiveness", "nis2": "21(2)(f)", "iso": ["9.1", "9.2", "A.5.35", "A.5.36"], "checks": [("coverage", _coverage)]},
    {"id": "hygiene", "nis2": "21(2)(g)", "iso": ["A.6.3", "A.8.9"], "checks": [("hardening", _hardening)]},
    {"id": "crypto", "nis2": "21(2)(h)", "iso": ["A.8.24", "A.5.14"], "checks": [("crypto", _crypto)]},
    {"id": "assets_access", "nis2": "21(2)(i)", "iso": ["A.5.9", "A.5.10", "A.5.15", "A.5.16", "A.5.18", "A.8.2"], "checks": [("inventory", _inventory), ("access", _access)]},
    {"id": "logging", "nis2": "21(2)(b), (f)", "iso": ["A.8.15", "A.8.16", "A.8.17"], "checks": [("logging", _logging)]},
    {"id": "change", "nis2": "21(2)(e)", "iso": ["A.8.9", "A.8.32"], "checks": [("config", _config)]},
]


def _status_of(checks: List[dict]) -> str:
    sts = {c["status"] for c in checks}
    if "gap" in sts:
        return "gap"
    if "warn" in sts:
        return "warn"
    if "ok" in sts:
        return "ok"
    return "manual" if (sts & {"manual", "external"}) else "na"


async def build() -> dict:
    """{"at", "requirements": [{id, nis2, iso, status, automated, checks}], "summary": {ok, warn, gap, manual}}."""
    out: List[dict] = []
    for req in REQUIREMENTS:
        checks: List[dict] = []
        for key, fn in req["checks"]:
            try:
                r = fn()
                if hasattr(r, "__await__"):
                    r = await r
                checks += r if isinstance(r, list) else [r]
            except Exception as e:
                checks.append({"key": key, "status": "na", "params": {}, "link": None, "error": f"{type(e).__name__}: {e}"[:160]})
        measured = [c for c in checks if c["status"] in ("ok", "warn", "gap")]
        out.append({"id": req["id"], "nis2": req["nis2"], "iso": req["iso"], "status": _status_of(checks), "checks": checks,
                    "automated": round(100.0 * len(measured) / len(checks)) if checks else 0})
    summary = {s: sum(1 for r in out if r["status"] == s) for s in ("ok", "warn", "gap", "manual", "na")}
    return {"at": datetime.utcnow().isoformat() + "Z", "requirements": out, "summary": summary,
            "bars": {"ok": BAR_OK, "warn": BAR_WARN, "backup_days": BACKUP_DAYS, "config_check_hours": CONFIG_CHECK_HOURS, "key_rotation_days": KEY_ROTATION_DAYS, "log_retention_days": LOG_RETENTION_BAR}}
