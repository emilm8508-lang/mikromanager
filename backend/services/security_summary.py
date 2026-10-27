"""
Numbers for the Security Summary dashboard — the agent's own page and Central's, which show the same
widgets from the same data. Almost everything on it is already collected and already travels to Central
(vulnerabilities, compliance, firewall, Wazuh, patch status, Hyper-V ...); this module adds only what
those summaries could not give:

  vuln        — ALL severities (the plaintext summary carries only critical/high), counted per host and per
                finding, the top CVEs, findings by host class and a risk score; accepted / resolved findings
                (VulnRemediation) are left out of the open counts;
  compliance  — the totals behind the failed-checks list: how many checks passed / failed, by severity and
                platform;
  events      — what the agent reported over time: every alert event is stored (SecurityEvent, 30 days) as a
                type, a device name and a count, and summarised as an hourly series, a by-type tally and the
                busiest devices.

Only counts, device names and CVE ids go out — no IPs, no log text, no check details. compute() is what the
uplink puts in the snapshot's plaintext envelope; agent_bundle() is the page's own endpoint and returns the
same sections Central receives plus these stats.
"""
import time
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select, delete

from models.database import (
    SessionLocal, SecurityEvent, VulnHost, Device, LinuxHost, WindowsHost, ComplianceCheckResult,
)

RETENTION_DAYS = 30
_WEIGHTS = {"CRITICAL": 5.0, "HIGH": 3.0, "MEDIUM": 1.0, "LOW": 0.5}   # SolarWinds' own risk weighting
_OPEN = ("open", "in_progress")
TOP_CVES = 10
TOP_DEVICES = 8


# ── Events ───────────────────────────────────────────────────────────────────

_seen: dict = {}                 # (type, device, detected_at, count) -> when it was taken in
_SEEN_KEEP_SEC = 4 * 3600


def record_events(events: List[dict]) -> None:
    """Stores the alert events of one snapshot build (type, device, count only) and trims old ones. The collectors that cache a scan (alerts.collect_alert_events
    hands the same events out on every cycle for an hour) give an event more than once: one with the same type, device, time of detection and count is stored once."""
    rows = []
    clock = time.time()
    for k in [k for k, v in _seen.items() if clock - v > _SEEN_KEEP_SEC]:
        del _seen[k]
    for e in events or []:
        if not isinstance(e, dict) or not e.get("type"):
            continue
        if e.get("detected_at"):
            key = (str(e["type"]), str(e.get("device_name") or ""), str(e["detected_at"]), str(e.get("count") or ""))
            if key in _seen:
                continue
            _seen[key] = clock
        try:
            n = max(1, int(e.get("count") or 1))
        except (TypeError, ValueError):
            n = 1
        rows.append(SecurityEvent(type=str(e["type"])[:64], device_name=(str(e["device_name"])[:128] if e.get("device_name") else None), count=n))
    with SessionLocal() as db:
        if rows:
            db.add_all(rows)
        db.execute(delete(SecurityEvent).where(SecurityEvent.ts < datetime.utcnow() - timedelta(days=RETENTION_DAYS)))
        db.commit()


def event_stats(now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    top_of_hour = now.replace(minute=0, second=0, microsecond=0)
    start24 = top_of_hour - timedelta(hours=23)
    with SessionLocal() as db:
        rows = db.execute(select(SecurityEvent).where(SecurityEvent.ts >= now - timedelta(days=7))).scalars().all()
    hourly = {start24 + timedelta(hours=i): 0 for i in range(24)}
    by_type_24h: dict = {}
    by_type_7d: dict = {}
    by_device: dict = {}
    daily = {(top_of_hour.replace(hour=0) - timedelta(days=d)): 0 for d in range(6, -1, -1)}
    for r in rows:
        by_type_7d[r.type] = by_type_7d.get(r.type, 0) + r.count
        day = r.ts.replace(hour=0, minute=0, second=0, microsecond=0)
        if day in daily:
            daily[day] += r.count
        if r.ts >= start24:
            hourly[r.ts.replace(minute=0, second=0, microsecond=0)] += r.count
            by_type_24h[r.type] = by_type_24h.get(r.type, 0) + r.count
            if r.device_name:
                by_device[r.device_name] = by_device.get(r.device_name, 0) + r.count
    devices = sorted(by_device.items(), key=lambda kv: -kv[1])[:TOP_DEVICES]
    return {
        "hourly": [{"t": t.isoformat() + "Z", "n": n} for t, n in sorted(hourly.items())],
        "daily": [{"t": t.isoformat() + "Z", "n": n} for t, n in sorted(daily.items())],
        "by_type_24h": by_type_24h, "by_type_7d": by_type_7d,
        "top_devices": [{"name": k, "n": v} for k, v in devices],
        "total_24h": sum(by_type_24h.values()), "total_7d": sum(by_type_7d.values()),
    }


# ── Vulnerabilities ──────────────────────────────────────────────────────────

def _host_classes(db) -> dict:
    """ip -> 'mikrotik' | 'cisco' | 'linux' | 'windows' | 'other', from what the agent knows about it."""
    cls: dict = {}
    for h in db.execute(select(LinuxHost)).scalars().all():
        cls[h.ip] = "linux"
    for h in db.execute(select(WindowsHost)).scalars().all():
        cls[h.ip] = "windows"
    for d in db.execute(select(Device)).scalars().all():
        v = (d.vendor or "mikrotik").lower()
        cls[d.ip] = v if v in ("mikrotik", "cisco") else "other"
    return cls


async def vuln_stats() -> dict:
    from services import vuln_scan
    hosts = await vuln_scan.hosts_with_findings()          # every severity, with remediation status
    with SessionLocal() as db:
        classes = _host_classes(db)
        scanned = {h.ip for h in db.execute(select(VulnHost)).scalars().all()}
        scanned |= {d.ip for d in db.execute(select(Device)).scalars().all() if d.ros_version}

    hosts_by_sev = {k: 0 for k in _WEIGHTS}
    findings_by_sev = {k: 0 for k in _WEIGHTS}
    by_class: dict = {}
    cves: dict = {}
    accepted = 0
    score_sum = 0.0
    vulnerable = 0
    for h in hosts:
        open_f = [f for f in h["findings"] if (f.get("status") or "open") in _OPEN]
        accepted += len(h["findings"]) - len(open_f)
        if not open_f:
            continue
        vulnerable += 1
        worst = min(open_f, key=lambda f: -_WEIGHTS.get(f["severity"], 0))["severity"]
        hosts_by_sev[worst] = hosts_by_sev.get(worst, 0) + 1
        score_sum += _WEIGHTS.get(worst, 0)
        k = classes.get(h["ip"], "other")
        for f in open_f:
            findings_by_sev[f["severity"]] = findings_by_sev.get(f["severity"], 0) + 1
            by_class[k] = by_class.get(k, 0) + 1
            c = cves.setdefault(f["cve_id"], {"cve_id": f["cve_id"], "severity": f["severity"], "cvss": f.get("cvss_score"), "hosts": 0})
            c["hosts"] += 1
    nodes = max(len(scanned | {h["ip"] for h in hosts}), 1)
    top = sorted(cves.values(), key=lambda c: (-_WEIGHTS.get(c["severity"], 0), -(c["cvss"] or 0), -c["hosts"]))[:TOP_CVES]
    return {
        "hosts_total": nodes, "hosts_vulnerable": vulnerable,
        "hosts_by_severity": hosts_by_sev, "findings_by_severity": findings_by_sev, "findings_by_class": by_class,
        "top_cves": top, "accepted": accepted,
        "risk_score": round(score_sum / nodes / _WEIGHTS["CRITICAL"] * 100, 1),
    }


# ── Compliance ───────────────────────────────────────────────────────────────

def compliance_stats() -> dict:
    with SessionLocal() as db:
        rows = db.execute(select(ComplianceCheckResult)).scalars().all()
    by_platform: dict = {}
    failed_by_sev = {"high": 0, "medium": 0, "low": 0}
    passed = failed = unknown = 0
    for r in rows:
        p = by_platform.setdefault(r.target_type, {"passed": 0, "failed": 0})
        if r.passed is True:
            passed += 1; p["passed"] += 1
        elif r.passed is False:
            failed += 1; p["failed"] += 1
            sev = (r.severity or "low").lower()
            failed_by_sev[sev if sev in failed_by_sev else "low"] += 1
        else:
            unknown += 1
    known = passed + failed
    return {"passed": passed, "failed": failed, "unknown": unknown, "failed_by_severity": failed_by_sev, "by_platform": by_platform,
            "score": round(passed / known * 100, 1) if known else None}


# ── Entry points ─────────────────────────────────────────────────────────────

async def compute() -> dict:
    """What goes in the snapshot's plaintext envelope as `security_stats`."""
    out = {"generated_at": datetime.utcnow().isoformat() + "Z", "vuln": None, "compliance": None, "events": None}
    try:
        out["vuln"] = await vuln_stats()
    except Exception as e:
        print(f"[security_summary] vuln stats error: {e}")
    try:
        out["compliance"] = compliance_stats()
    except Exception as e:
        print(f"[security_summary] compliance stats error: {e}")
    try:
        out["events"] = event_stats()
    except Exception as e:
        print(f"[security_summary] event stats error: {e}")
    return out


async def agent_bundle() -> dict:
    """The agent page's endpoint: the same sections Central gets in a snapshot, plus the stats."""
    from services import (vuln_scan, compliance, firewall_analysis, wazuh_monitor, linux_manage, windows_manage, hyperv_manage,
                          tunnel_monitor, edge_discovery, prtg_monitor, checkmk_monitor, dell_monitor, host_monitor, supply_chain,
                          fleet, firmware_status, resource_monitor)

    async def safe(fn, default):
        try:
            r = fn()
            if hasattr(r, "__await__"):
                r = await r
            return r
        except Exception as e:
            print(f"[security_summary] section error ({getattr(fn, '__name__', fn)}): {e}")
            return default

    return {
        "stats": await compute(),
        "vuln_findings_status": await safe(vuln_scan.public_summary, []),
        "compliance_status": await safe(compliance.public_summary, []),
        "firewall_status": await safe(firewall_analysis.public_summary, []),
        "wazuh_status": await safe(wazuh_monitor.public_summary, []),
        "linux_hosts_status": await safe(linux_manage.public_summary, []),
        "windows_hosts_status": await safe(windows_manage.public_summary, []),
        "hyperv_status": await safe(hyperv_manage.public_summary, []),
        "tunnel_status": await safe(tunnel_monitor.public_summary, []),
        "wan_link_status": await safe(edge_discovery.public_summary, []),
        "prtg_status": await safe(prtg_monitor.public_summary, []),
        "checkmk_status": await safe(checkmk_monitor.public_summary, {"services": [], "hosts": []}),
        "dell_servers_status": await safe(dell_monitor.public_summary, []),
        "hostmon_status": await safe(host_monitor.public_summary, []),
        "supply_chain_status": await safe(supply_chain.public_summary, None),
        "mikrotik_fleet": await safe(fleet.public_summary, None),
        "firmware_status": await safe(firmware_status.collect_firmware_status, None),
        "routers_status": await safe(resource_monitor.routers_public_summary, []),
    }
