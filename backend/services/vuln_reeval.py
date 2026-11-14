"""
One pass over the vulnerability findings this agent already has, with the matching of 3.58 (services/vuln_match.py).

Before 3.58 a CVE was tied to a product without its affected versions, and any version of a device marked "mikrotik" counted as RouterOS:
in production CVE-2018-14847 / CVE-2018-7445 (KEV, CVSS 9.8, fixed in 6.42.1 / 6.41.3) sat on RouterOS 7.25.1 routers, SwOS switches,
printers and a Linux kernel version. This pass, run once in the background after the update (and on demand), puts that right:

  1. every (product, version) pair in the cache is looked up again - NVD's range matching and the same check here - so a CVE the version
     is not affected by disappears and its remediation row is closed "[auto_closed: version_not_affected]"
  2. a pair no confirmed product uses any more (a printer's "RouterOS 1.37", SwOS "2.18" read as RouterOS) has its open rows closed
     "[auto_closed: product_not_confirmed]"
  3. an open "new vulnerability" SOC alert whose finding is gone, or is now only suspected, is closed with the reason
  4. the risk scores are recomputed from the corrected findings (the inventory's cache is dropped)

The counts are kept (data/vuln_reeval.json) for the report and the vulnerability status. Never raises.
"""
import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from models.database import SessionLocal, VulnFinding, VulnRemediation, VulnService, VulnPackage, Device, SocAlert

VERSION = 1
_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vuln_reeval.json")
PAUSE_SEC = 2.0                     # between NVD lookups: through Central they are cached and spaced anyway
_task: Optional[asyncio.Task] = None
_state: dict = {}


def _load() -> dict:
    try:
        with open(_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(tmp, _PATH)


def status() -> dict:
    return dict(_state or _load())


def _close_soc_alerts(current: dict, now: datetime) -> dict:
    """Open "new vulnerability" alerts whose (ip, CVE) is no longer a finding, or is only suspected now."""
    from services import soc
    out = {"gone": 0, "downgraded": 0}
    with SessionLocal() as db:
        for a in db.execute(select(SocAlert).where(SocAlert.rule == "rule.new_vuln", SocAlert.status.in_(soc.OPEN))).scalars().all():
            try:
                d = json.loads(a.detail or "{}")
            except ValueError:
                continue
            key = (d.get("ip") or a.ip, d.get("cve"))
            if not key[1]:
                continue
            conf = current.get(key)
            if conf is None:
                reason, out_key = "auto: version_not_affected", "gone"
            elif conf == "suspected" and a.severity in ("critical", "high"):
                reason, out_key = "auto: suspected (banner only, not confirmed)", "downgraded"
            else:
                continue
            a.status, a.closed_at, a.closed_by = "closed", now, reason
            out[out_key] += 1
        db.commit()
    return out


async def run(force: bool = False) -> dict:
    global _state
    prev = _load()
    if prev.get("version") == VERSION and prev.get("finished_at") and not force:
        _state = prev
        return prev
    from services import vuln_scan
    started = datetime.utcnow()
    _state = {"version": VERSION, "started_at": started.isoformat() + "Z", "finished_at": None, "pairs": 0, "pairs_failed": 0,
              "closed_version_not_affected": 0, "closed_product_not_confirmed": 0, "soc_alerts_closed": 0, "soc_alerts_downgraded": 0,
              # remediation rows (one per product, version, CVE) open before and after; findings per host after, and those counted as KEV
              "open_rows_before": 0, "open_rows_after": 0, "kev_rows_before": 0, "kev_rows_after": 0, "host_findings_after": 0, "host_kev_after": 0}
    try:
        with SessionLocal() as db:
            pairs = sorted({(p, v) for p, v in db.execute(select(VulnFinding.product, VulnFinding.version)).all()})
            pkg_pairs = {(p.name, p.version) for p in db.execute(select(VulnPackage)).scalars().all()}
            svc_pairs = {(s.product, s.version) for s in db.execute(select(VulnService)).scalars().all() if s.product and s.version}
            dev_pairs = {vuln_scan._device_version_pair(d) for d in db.execute(select(Device)).scalars().all()}
            dev_pairs.discard(None)
            open_before = db.execute(select(VulnRemediation).where(VulnRemediation.status.in_(["open", "in_progress"]))).scalars().all()
            _state["open_rows_before"] = len(open_before)
        from services import exploit_intel
        _state["kev_rows_before"] = sum(1 for r in open_before if exploit_intel.info(r.cve_id)["kev"])

        used = pkg_pairs | svc_pairs | dev_pairs
        # (2) pairs nothing confirmed uses any more
        with SessionLocal() as db:
            for product, version in pairs:
                if (product, version) in used:
                    continue
                ids = [r.cve_id for r in db.execute(select(VulnRemediation).where(VulnRemediation.product == product,
                                                                                   VulnRemediation.version == version)).scalars().all()]
                _state["closed_product_not_confirmed"] += vuln_scan._auto_close(db, product, version, ids, "product_not_confirmed")
            db.commit()

        # (1) the pairs still in use, looked up again (package-audit pairs come from the distribution and stay as they are)
        to_check = [pv for pv in pairs if pv in (svc_pairs | dev_pairs) and pv not in pkg_pairs]
        _state["pairs"] = len(to_check)
        for product, version in to_check:
            with SessionLocal() as db:
                before_open = {r.cve_id for r in db.execute(select(VulnRemediation).where(
                    VulnRemediation.product == product, VulnRemediation.version == version,
                    VulnRemediation.status.in_(["open", "in_progress"]))).scalars().all()}
                for f in db.execute(select(VulnFinding).where(VulnFinding.product == product, VulnFinding.version == version)).scalars().all():
                    f.queried_at = datetime(2000, 1, 1)                     # stale: the lookup below asks NVD again
                db.commit()
                try:
                    await vuln_scan._get_findings_for(db, product, version)
                except Exception as e:
                    _state["pairs_failed"] += 1
                    print(f"[vuln_reeval] {product} {version}: {type(e).__name__}: {e}")
                    continue
                after_open = {r.cve_id for r in db.execute(select(VulnRemediation).where(
                    VulnRemediation.product == product, VulnRemediation.version == version,
                    VulnRemediation.status.in_(["open", "in_progress"]))).scalars().all()}
                _state["closed_version_not_affected"] += len(before_open - after_open)
            await asyncio.sleep(PAUSE_SEC)

        # (3) SOC alerts, (4) risk
        hosts = await vuln_scan.hosts_with_findings()
        current = {(h["ip"], f["cve_id"]): f.get("confidence") for h in hosts for f in h["findings"]
                   if (f.get("status") or "open") in ("open", "in_progress")}
        closed = _close_soc_alerts(current, datetime.utcnow())
        _state["soc_alerts_closed"], _state["soc_alerts_downgraded"] = closed["gone"], closed["downgraded"]
        with SessionLocal() as db:
            open_after = db.execute(select(VulnRemediation).where(VulnRemediation.status.in_(["open", "in_progress"]))).scalars().all()
        _state["open_rows_after"] = len(open_after)
        _state["kev_rows_after"] = sum(1 for r in open_after if exploit_intel.info(r.cve_id)["kev"])
        _state["host_findings_after"] = len(current)
        _state["host_kev_after"] = sum(1 for h in hosts for f in h["findings"]
                                  if (f.get("status") or "open") in ("open", "in_progress") and f.get("kev") and f.get("confidence") != "suspected")
        try:
            from services import assets
            assets._vuln_cache["at"] = 0.0
        except Exception:
            pass
        _state["finished_at"] = datetime.utcnow().isoformat() + "Z"
        print(f"[vuln_reeval] done: {_state}")
    except Exception as e:
        _state["error"] = f"{type(e).__name__}: {e}"[:300]
        print(f"[vuln_reeval] failed: {_state['error']}")
    _save(_state)
    return _state


def start(delay_sec: float = 120.0) -> None:
    """Once after the update, a couple of minutes after the start (the uplink and the refresher come first)."""
    global _task
    if _load().get("version") == VERSION and _load().get("finished_at"):
        return

    async def later():
        await asyncio.sleep(delay_sec)
        await run()

    if _task is None or _task.done():
        _task = asyncio.get_event_loop().create_task(later())
