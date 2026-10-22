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
Every factor comes with its points AND what it is made of - which services, which checks, which CVEs, which alerts - so the page (and Central's drawer of the
device) can say *what* is wrong, not only that something is.
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
PUBLIC_TOP = 60                                   # devices Central gets the detail of (its list shows the worst few; the device drawer looks the rest up here)
MAX_ITEMS = 8
MAX_SERVICES = 25
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def level_of(score: float) -> str:
    for name, floor in LEVELS:
        if score >= floor:
            return name
    return "low"


def _cut(s, n: int = 90) -> str:
    return str(s)[:n]


def _factors(row: dict, alerts: List[dict], failed: List[dict], risky: List[int], patch: dict, cves: List[dict]) -> List[dict]:
    out: List[dict] = []

    def add(k: str, pts: float, n=None, items=None):
        pts = min(pts, CAPS[k])
        if pts > 0:
            f = {"k": k, "pts": round(pts, 1)}
            if n is not None:
                f["n"] = n
            if items:
                f["items"] = items[:MAX_ITEMS]
            out.append(f)

    alerts = sorted(alerts, key=lambda a: -soc.RANK.get(a["s"], 0))
    add("alerts", sum(ALERT_POINTS.get(a["s"], 0) for a in alerts), len(alerts), alerts)
    v = row["vulns"]
    cves = sorted(cves, key=lambda c: (_SEV_ORDER.get(c["severity"], 4), -(c.get("cvss_score") or 0)))
    add("vuln", 8 * v["critical"] + 3 * v["high"], v["critical"] + v["high"],
        [_cut(f"{c.get('cve_id') or '?'} · {c['severity']}" + (f" · {c['cvss_score']}" if c.get("cvss_score") else "")) for c in cves])
    lc = row["lifecycle"]
    add("lifecycle", 15 if lc == "eol" else 5 if lc == "ending" else 0, None,
        [_cut(" · ".join(x for x in (row.get("lifecycle_product"), ("EOL " + row["eol"]) if row.get("eol") else None) if x))] if lc in ("eol", "ending") else None)
    up = patch.get("upgradable") or 0
    add("patches", (8 if up >= 20 else 4 if up >= 5 else 1 if up else 0) + (2 if patch.get("reboot") else 0), up, ["reboot"] if patch.get("reboot") else None)
    failed = sorted(failed, key=lambda f: 0 if f["s"] == "high" else 1)
    add("hardening", 3 * len(failed), len(failed), [_cut(f["t"]) for f in failed])
    add("exposure", 3 * len(risky), len(risky), [f"{p} {RISKY_PORTS[p]}" for p in sorted(risky)])
    add("hints", 6 if row.get("hints") else 0, None, list(row.get("hints") or []))
    add("blind", 2 if row["scan_level"] == "passive" and row["type"] in ("windows", "linux", "server") else 0)
    return out


async def compute() -> List[dict]:
    """Every active asset with a score above zero, the worst first."""
    from services import assets as assets_svc
    rows = [r for r in await assets_svc.list_assets() if r["active"]]
    vulns_by_ip = await assets_svc._vulns_by_ip()
    with SessionLocal() as db:
        open_alerts = db.execute(select(SocAlert.asset_id, SocAlert.device_name, SocAlert.severity, SocAlert.rule, SocAlert.title).where(SocAlert.status.in_(soc.OPEN))).all()
        failed: Dict[tuple, List[dict]] = {}
        for r in db.execute(select(ComplianceCheckResult).where(ComplianceCheckResult.passed.is_(False))).scalars().all():
            if (r.severity or "").lower() in ("high", "medium"):
                failed.setdefault((r.target_type, r.target_id), []).append({"s": (r.severity or "").lower(), "t": r.title})
        hosts = {h.id: h.ip for h in db.execute(select(VulnHost)).scalars().all()}
        risky_by_ip: Dict[str, List[int]] = {}
        services_by_ip: Dict[str, List[str]] = {}
        for s in db.execute(select(VulnService).order_by(VulnService.port)).scalars().all():
            ip = hosts.get(s.host_id)
            if not ip:
                continue
            if s.port in RISKY_PORTS:
                risky_by_ip.setdefault(ip, []).append(s.port)
            services_by_ip.setdefault(ip, []).append(_cut(" ".join(str(x) for x in (s.port, s.service_name, s.product, s.version) if x)))
        lin = {h.id: {"upgradable": h.upgradable_count, "reboot": bool(h.reboot_required)} for h in db.execute(select(LinuxHost)).scalars().all()}
        win = {h.id: {"upgradable": h.upgradable_count, "reboot": bool(h.reboot_required)} for h in db.execute(select(WindowsHost)).scalars().all()}

    by_asset: Dict[int, List[dict]] = {}
    by_name: Dict[str, List[dict]] = {}
    for aid, dev, sev, rule, title in open_alerts:
        item = {"s": sev, "r": rule, "t": title}
        if aid:
            by_asset.setdefault(aid, []).append(item)
        elif dev:
            by_name.setdefault(dev.split(":")[0].strip().lower(), []).append(item)

    out = []
    for r in rows:
        refs = r["refs"]
        alerts = by_asset.get(r["id"], []) + by_name.get((r["name"] or "").lower(), [])
        failed_list = (failed.get(("linux", refs["linux_host_id"]), []) if "linux_host_id" in refs else []) \
            + (failed.get(("windows", refs["windows_host_id"]), []) if "windows_host_id" in refs else []) \
            + (failed.get(("mikrotik", refs["device_id"]), []) if "device_id" in refs else [])
        patch = lin.get(refs.get("linux_host_id")) or win.get(refs.get("windows_host_id")) or {}
        cves = [c for c in vulns_by_ip.get(r["ip"] or "", []) if (c.get("status") or "open") in ("open", "in_progress") and c.get("severity") in ("CRITICAL", "HIGH")]
        factors = _factors(r, alerts, failed_list, risky_by_ip.get(r["ip"] or "", []), patch, cves)
        if not factors:
            continue
        score = sum(f["pts"] for f in factors)
        if r["type"] in IMPORTANT or r.get("dclass") in ("gateway", "router", "switch"):
            score *= 1.15
        score = round(min(100.0, score), 1)
        out.append({"id": r["id"], "name": r["name"], "ip": r["ip"], "loc": r.get("location"), "type": r["type"], "dclass": r.get("dclass"), "score": score,
                    "level": level_of(score), "factors": factors, "services": services_by_ip.get(r["ip"] or "", [])[:MAX_SERVICES]})
    out.sort(key=lambda x: -x["score"])
    return out


async def public_summary() -> dict:
    """What Central gets: the level counts and the worst devices with their factors and what each is made of, where each is (address, location) so the list can
    say which host it means - the same the asset list in Central already carries - and the open ports of those devices."""
    rows = await compute()
    levels = {n: 0 for n, _ in LEVELS}
    for r in rows:
        levels[r["level"]] += 1
    return {
        "levels": levels, "scored": len(rows),
        "top": [{"id": r["id"], "name": r["name"], "ip": r["ip"], "loc": r["loc"], "type": r["type"], "score": r["score"], "level": r["level"],
                 "factors": [[f["k"], f["pts"], f.get("n"), f.get("items")] for f in r["factors"]], "services": r["services"]} for r in rows[:PUBLIC_TOP]],
    }
