"""
Risk profile of an asset: the signals the agent has about one device, put together into one number and the reasons behind it.

Every source on its own says little - a Wazuh alert, a vulnerability, a missing patch, a failed hardening check - and each lives on its own page. A SOC
asks the question the other way round: which devices are the worst off, and why? This module answers it from what is already collected:

  alerts       the open SOC alerts about the device (the weight follows their severity)
  vuln         open critical / high vulnerabilities
  lifecycle    an operating system out of support (or about to be)
  patches      pending updates and a reboot waiting (Windows / Linux hosts the agent manages)
  hardening    failed high / medium configuration checks
  exposure     risky services listening on it (RDP, SMB, Telnet, databases ...)
  hints        an embedded device that is often left on a factory password
  blind        only seen passively (no credentials: the agent cannot tell what is inside)

The score is the sum of the points (each factor capped, so one kind of problem cannot hide the rest), a little higher for servers and network gear, at most 100.
The factors are returned with their points, so the page can show *why*, and the same numbers are what Central gets for its own top list.
"""
from typing import Dict, List

from sqlalchemy import select

from models.database import SessionLocal, SocAlert, ComplianceCheckResult, VulnHost, VulnService, LinuxHost, WindowsHost
from services import soc
from services.soc_rules import RISKY_PORTS

LEVELS = (("critical", 60), ("high", 40), ("medium", 20), ("low", 0))
ALERT_POINTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
CAPS = {"alerts": 50, "vuln": 30, "lifecycle": 15, "patches": 12, "hardening": 12, "exposure": 9, "hints": 6, "blind": 2}
IMPORTANT = {"server", "network"}                 # asset types that matter more when they are in trouble
PUBLIC_TOP = 15


def level_of(score: float) -> str:
    for name, floor in LEVELS:
        if score >= floor:
            return name
    return "low"


def _factors(row: dict, alerts: List[str], failed_checks: int, risky: List[int], patch: dict) -> List[dict]:
    out: List[dict] = []

    def add(k: str, pts: float, n=None):
        pts = min(pts, CAPS[k])
        if pts > 0:
            out.append({"k": k, "pts": round(pts, 1), **({"n": n} if n is not None else {})})

    add("alerts", sum(ALERT_POINTS.get(s, 0) for s in alerts), len(alerts))
    v = row["vulns"]
    add("vuln", 8 * v["critical"] + 3 * v["high"], v["critical"] + v["high"])
    add("lifecycle", 15 if row["lifecycle"] == "eol" else 5 if row["lifecycle"] == "ending" else 0)
    up = patch.get("upgradable") or 0
    add("patches", (8 if up >= 20 else 4 if up >= 5 else 1 if up else 0) + (2 if patch.get("reboot") else 0), up)
    add("hardening", 3 * failed_checks, failed_checks)
    add("exposure", 3 * len(risky), len(risky))
    add("hints", 6 if row.get("hints") else 0)
    add("blind", 2 if row["scan_level"] == "passive" and row["type"] in ("windows", "linux", "server") else 0)
    return out


async def compute() -> List[dict]:
    """Every active asset with a score above zero, the worst first."""
    from services import assets as assets_svc
    rows = [r for r in await assets_svc.list_assets() if r["active"]]
    with SessionLocal() as db:
        open_alerts = db.execute(select(SocAlert.asset_id, SocAlert.device_name, SocAlert.severity).where(SocAlert.status.in_(soc.OPEN))).all()
        failed: Dict[tuple, int] = {}
        for r in db.execute(select(ComplianceCheckResult).where(ComplianceCheckResult.passed.is_(False))).scalars().all():
            if (r.severity or "").lower() in ("high", "medium"):
                failed[(r.target_type, r.target_id)] = failed.get((r.target_type, r.target_id), 0) + 1
        hosts = {h.id: h.ip for h in db.execute(select(VulnHost)).scalars().all()}
        risky_by_ip: Dict[str, List[int]] = {}
        for s in db.execute(select(VulnService)).scalars().all():
            if s.port in RISKY_PORTS and hosts.get(s.host_id):
                risky_by_ip.setdefault(hosts[s.host_id], []).append(s.port)
        lin = {h.id: {"upgradable": h.upgradable_count, "reboot": bool(h.reboot_required)} for h in db.execute(select(LinuxHost)).scalars().all()}
        win = {h.id: {"upgradable": h.upgradable_count, "reboot": bool(h.reboot_required)} for h in db.execute(select(WindowsHost)).scalars().all()}

    by_asset: Dict[int, List[str]] = {}
    by_name: Dict[str, List[str]] = {}
    for aid, dev, sev in open_alerts:
        if aid:
            by_asset.setdefault(aid, []).append(sev)
        elif dev:
            by_name.setdefault(dev.split(":")[0].strip().lower(), []).append(sev)

    out = []
    for r in rows:
        refs = r["refs"]
        alerts = by_asset.get(r["id"], []) + by_name.get((r["name"] or "").lower(), [])
        failed_n = (failed.get(("linux", refs["linux_host_id"]), 0) if "linux_host_id" in refs else 0) \
            + (failed.get(("windows", refs["windows_host_id"]), 0) if "windows_host_id" in refs else 0) \
            + (failed.get(("mikrotik", refs["device_id"]), 0) if "device_id" in refs else 0)
        patch = lin.get(refs.get("linux_host_id")) or win.get(refs.get("windows_host_id")) or {}
        factors = _factors(r, alerts, failed_n, risky_by_ip.get(r["ip"] or "", []), patch)
        if not factors:
            continue
        score = sum(f["pts"] for f in factors)
        if r["type"] in IMPORTANT or r.get("dclass") in ("gateway", "router", "switch"):
            score *= 1.15
        score = round(min(100.0, score), 1)
        out.append({"id": r["id"], "name": r["name"], "ip": r["ip"], "type": r["type"], "dclass": r.get("dclass"), "score": score,
                    "level": level_of(score), "factors": factors})
    out.sort(key=lambda x: -x["score"])
    return out


async def public_summary() -> dict:
    """What Central gets: the level counts and the worst few devices with their factors - names and points, no addresses."""
    rows = await compute()
    levels = {n: 0 for n, _ in LEVELS}
    for r in rows:
        levels[r["level"]] += 1
    return {
        "levels": levels, "scored": len(rows),
        "top": [{"id": r["id"], "name": r["name"], "type": r["type"], "score": r["score"], "level": r["level"],
                 "factors": [[f["k"], f["pts"], f.get("n")] for f in r["factors"]]} for r in rows[:PUBLIC_TOP]],
    }
