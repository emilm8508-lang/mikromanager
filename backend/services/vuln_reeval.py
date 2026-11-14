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

A pair NVD did not answer for (unreachable, an error) keeps its old rows - shown as suspected, as before - and is listed in "retry": the
start-up task looks those pairs up again, an hour apart, up to RETRY_ATTEMPTS times (3.65: on one router the old RouterOS CVEs stayed
because the one lookup of 3.58 found NVD unavailable and nothing asked again).

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
RETRY_ATTEMPTS = 5                  # further passes over the pairs NVD did not answer for
RETRY_PAUSE_SEC = 3600.0
_STALE = datetime(2000, 1, 1)       # queried_at of a row marked for the lookup again: still there after it = NVD did not answer
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


async def run(force: bool = False, retry: bool = False) -> dict:
    """retry: only the pairs the last pass listed in "retry" are looked up again; the counts are added to that pass's."""
    global _state
    prev = _load()
    if retry:
        if not prev.get("retry") or prev.get("version") != VERSION:
            _state = prev
            return prev
    elif prev.get("version") == VERSION and prev.get("finished_at") and not force:
        _state = prev
        return prev
    from services import vuln_scan
    started = datetime.utcnow()
    if retry:
        only = {tuple(x) for x in prev["retry"]}
        _state = dict(prev, retry=[], finished_at=None, retry_attempts=int(prev.get("retry_attempts") or 0) + 1,
                      last_retry_at=started.isoformat() + "Z", pairs_failed=0)
        _state.setdefault("closed_version_not_affected", 0)
    else:
        only = None
        _state = {"version": VERSION, "started_at": started.isoformat() + "Z", "finished_at": None, "pairs": 0, "pairs_failed": 0, "retry": [],
                  "retry_attempts": 0, "closed_version_not_affected": 0, "closed_product_not_confirmed": 0, "soc_alerts_closed": 0,
                  "soc_alerts_downgraded": 0,
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
        from services import exploit_intel
        if only is None:
            _state["open_rows_before"] = len(open_before)
            _state["kev_rows_before"] = sum(1 for r in open_before if exploit_intel.info(r.cve_id)["kev"])

        used = pkg_pairs | svc_pairs | dev_pairs
        # (2) pairs nothing confirmed uses any more
        with SessionLocal() as db:
            for product, version in pairs:
                if (product, version) in used or only is not None:
                    continue
                ids = [r.cve_id for r in db.execute(select(VulnRemediation).where(VulnRemediation.product == product,
                                                                                   VulnRemediation.version == version)).scalars().all()]
                _state["closed_product_not_confirmed"] += vuln_scan._auto_close(db, product, version, ids, "product_not_confirmed")
            db.commit()

        # (1) the pairs still in use, looked up again (package-audit pairs come from the distribution and stay as they are)
        to_check = [pv for pv in pairs if pv in (svc_pairs | dev_pairs) and pv not in pkg_pairs and (only is None or pv in only)]
        if only is None:
            _state["pairs"] = len(to_check)
        for product, version in to_check:
            with SessionLocal() as db:
                before_open = {r.cve_id for r in db.execute(select(VulnRemediation).where(
                    VulnRemediation.product == product, VulnRemediation.version == version,
                    VulnRemediation.status.in_(["open", "in_progress"]))).scalars().all()}
                for f in db.execute(select(VulnFinding).where(VulnFinding.product == product, VulnFinding.version == version)).scalars().all():
                    f.queried_at = _STALE                                   # stale: the lookup below asks NVD again
                db.commit()
                try:
                    await vuln_scan._get_findings_for(db, product, version)
                except Exception as e:
                    _state["pairs_failed"] += 1
                    _state["retry"].append([product, version])
                    print(f"[vuln_reeval] {product} {version}: {type(e).__name__}: {e}")
                    continue
                if db.execute(select(VulnFinding.id).where(VulnFinding.product == product, VulnFinding.version == version,
                                                           VulnFinding.queried_at <= _STALE).limit(1)).first():
                    # NVD did not answer: the old rows were kept as they were - asked again later
                    _state["pairs_failed"] += 1
                    _state["retry"].append([product, version])
                    print(f"[vuln_reeval] {product} {version}: NVD did not answer, old rows kept - retried later")
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
        _state["soc_alerts_closed"] = int(_state.get("soc_alerts_closed") or 0) + closed["gone"]                  # a retry adds to the first pass's counts
        _state["soc_alerts_downgraded"] = int(_state.get("soc_alerts_downgraded") or 0) + closed["downgraded"]
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


def _note_old_rows(prev: dict) -> dict:
    """A pass of 3.58-3.64 did not note the pairs NVD did not answer for: a row no lookup of 3.58+ wrote has no match_source."""
    if prev.get("version") == VERSION and prev.get("finished_at") and "retry" not in prev:
        try:
            with SessionLocal() as db:
                prev["retry"] = sorted([p, v] for p, v in db.execute(select(VulnFinding.product, VulnFinding.version)
                                                                     .where(VulnFinding.match_source.is_(None)).distinct()).all())
            prev["retry_attempts"] = 0
            _save(prev)
        except Exception as e:
            print(f"[vuln_reeval] retry list: {type(e).__name__}: {e}")
    return prev


def _retry_due(d: dict) -> bool:
    return bool(d.get("version") == VERSION and d.get("finished_at") and d.get("retry")
                and int(d.get("retry_attempts") or 0) < RETRY_ATTEMPTS)


def start(delay_sec: float = 120.0) -> None:
    """Once after the update, a couple of minutes after the start (the uplink and the refresher come first); then the pairs NVD did not
    answer for, an hour apart, up to RETRY_ATTEMPTS times (counted across restarts)."""
    global _task
    prev = _note_old_rows(_load())
    if prev.get("version") == VERSION and prev.get("finished_at") and not _retry_due(prev):
        return

    async def later():
        await asyncio.sleep(delay_sec)
        d = await run(retry=_retry_due(_load()))
        while _retry_due(d):
            await asyncio.sleep(RETRY_PAUSE_SEC)
            d = await run(retry=True)

    if _task is None or _task.done():
        _task = asyncio.get_event_loop().create_task(later())
