"""
The CVEs a Windows host is exposed to because of the updates it has not installed.

The agent already asks every managed Windows host, over WinRM, which updates Windows Update would install (services/windows_manage.py: a read-only
Search(), nothing is downloaded or installed). Windows Update describes each security update with the CVEs it fixes (IUpdate2.CveIDs) and Microsoft's
severity of it (IUpdate.MsrcSeverity) - so "7 updates pending" can become "these CVEs are not fixed on this host": exactly the missing-patch question, answered
from the patches themselves instead of a guess from the system's name (an NVD keyword search cannot tell that a CVE is already fixed by an installed KB) and
without a paid vulnerability service.

  sync()     keeps the pending updates of a host, makes a finding of every (update, CVE) - product "Windows Update", version "KB5037782" - so they show
             up on the Vulnerabilities page, in the remediation / SLA tracking, in Central, the SOC rules and the risk score like any other finding; a
             CVE disappears from the host when its update is installed (the list is the current one, not a history);
  enrich()   the severity of an update is the worst of its CVEs (one critical CVE makes a rollup of fifty "Critical"); the real CVSS score and severity of
             each CVE is fetched from NVD in the background (once per CVE for all hosts, rate-limited, with the NVD key when there is one) and replaces the
             update's severity. Until then - or when NVD cannot be reached - the update's severity stands.
"""
import asyncio
import hashlib
import json
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Set

from sqlalchemy import select, delete

from models.database import SessionLocal, WindowsHost, VulnFinding

PRODUCT = "Windows Update"
MAX_UPDATES = 60                    # updates kept per host
MAX_CVES_PER_UPDATE = 250           # a cumulative update lists dozens to a few hundred
ENRICH_PER_RUN = 400
RETRY_AFTER_SEC = 24 * 3600         # a CVE NVD did not answer for is asked again after this
_SEV = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_tried: Dict[str, float] = {}
_enriching = False


def parse(raw: list) -> List[dict]:
    """The script's JSON ([{Title, KB, Cves, Sev}]) -> [{kb, title, sev, cves}]; only updates that fix CVEs are kept (a definitions update fixes none)."""
    out: List[dict] = []
    for u in raw or []:
        if not isinstance(u, dict):
            continue
        cves = sorted({c.strip().upper() for c in str(u.get("Cves") or "").split(",") if _CVE_RE.match(c.strip())})[:MAX_CVES_PER_UPDATE]
        if not cves:
            continue
        title = str(u.get("Title") or "")[:200]
        m = re.search(r"\d{4,8}", str(u.get("KB") or ""))
        kb = f"KB{m.group()}" if m else "ID" + hashlib.sha1(title.encode("utf-8", "ignore")).hexdigest()[:8]
        out.append({"kb": kb, "title": title, "sev": _SEV.get(str(u.get("Sev") or "").strip().lower()), "cves": cves})
    return out[:MAX_UPDATES]


def pending(host: WindowsHost) -> List[dict]:
    """[{kb, title, sev, n}] the host was last found to be missing (without the CVE lists: those are the findings)."""
    try:
        v = json.loads(host.upgradable_updates) if host.upgradable_updates else []
    except Exception:
        return []
    return [u for u in v if isinstance(u, dict) and u.get("kb")]


def affected(db) -> Dict[str, List[dict]]:
    """kb -> [{ip, device_name}] of the Windows hosts that are missing it - what the finding lists are joined with."""
    out: Dict[str, List[dict]] = {}
    for h in db.execute(select(WindowsHost).where(WindowsHost.upgradable_updates.is_not(None))).scalars().all():
        for u in pending(h):
            out.setdefault(u["kb"], []).append({"ip": h.ip, "device_name": h.hostname})
    return out


def sync(host_id: int, updates: List[dict]) -> int:
    """Stores the pending updates of one host and makes sure each of their CVEs is a finding. Returns the number of CVEs. Never raises."""
    from services import vuln_scan
    n = 0
    try:
        with SessionLocal() as db:
            host = db.get(WindowsHost, host_id)
            if host is None:
                return 0
            host.upgradable_updates = json.dumps([{"kb": u["kb"], "title": u["title"], "sev": u["sev"], "n": len(u["cves"])} for u in updates], ensure_ascii=False)
            now = datetime.utcnow()
            for u in updates:
                have = {f.cve_id for f in db.execute(select(VulnFinding).where(VulnFinding.product == PRODUCT, VulnFinding.version == u["kb"])).scalars().all()}
                for cve in u["cves"]:
                    n += 1
                    if cve not in have:
                        db.add(VulnFinding(product=PRODUCT, version=u["kb"], cve_id=cve, cvss_score=None, severity=u["sev"] or "MEDIUM",
                                           summary=f"{u['title']}", published=None, ref_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}", queried_at=now))
                    vuln_scan._ensure_remediation_row(db, PRODUCT, u["kb"], cve, u["sev"] or "MEDIUM")
            db.commit()
            # findings of updates that no host is missing any more
            wanted: Set[str] = set(affected(db))
            if wanted:
                db.execute(delete(VulnFinding).where(VulnFinding.product == PRODUCT, VulnFinding.version.not_in(wanted)))
            else:
                db.execute(delete(VulnFinding).where(VulnFinding.product == PRODUCT))
            db.commit()
    except Exception as e:
        print(f"[windows_updates] sync error: {type(e).__name__}: {e}")
    return n


def clear(host_id: int) -> None:
    """The host installed its updates: nothing is pending."""
    sync(host_id, [])


def start_enrich() -> None:
    """Fetches the CVSS score / severity of the new CVEs from NVD in the background (one run at a time); safe to call after every sync."""
    global _enriching
    if _enriching:
        return
    try:
        asyncio.get_running_loop().create_task(enrich())
    except RuntimeError:
        pass


async def enrich(limit: int = ENRICH_PER_RUN) -> int:
    """Replaces the severity the update gave a CVE with NVD's own. Returns how many CVEs were refined."""
    global _enriching
    from services import vuln_scan
    _enriching = True
    done = 0
    try:
        with SessionLocal() as db:
            todo = sorted({f.cve_id for f in db.execute(select(VulnFinding).where(VulnFinding.product == PRODUCT, VulnFinding.cvss_score.is_(None))).scalars().all()})
        now = time.time()
        todo = [c for c in todo if now - _tried.get(c, 0) > RETRY_AFTER_SEC][:limit]
        for cve in todo:
            _tried[cve] = time.time()
            try:
                f = await vuln_scan.nvd_cve(cve)
            except vuln_scan.NvdUnavailable:
                break                                  # no point asking for the rest; the next sync tries again
            except Exception as e:
                print(f"[windows_updates] NVD lookup of {cve} failed: {e}")
                continue
            if not f:
                continue
            with SessionLocal() as db:
                rows = db.execute(select(VulnFinding).where(VulnFinding.product == PRODUCT, VulnFinding.cve_id == cve)).scalars().all()
                for r in rows:
                    if f.get("cvss_score") is not None:
                        r.cvss_score = f["cvss_score"]
                    if f.get("severity"):
                        r.severity = f["severity"]
                    if f.get("summary"):
                        r.summary = f["summary"]
                    if f.get("published"):
                        r.published = f["published"]
                    vuln_scan._ensure_remediation_row(db, PRODUCT, r.version, cve, r.severity)
                db.commit()
            done += 1
    except Exception as e:
        print(f"[windows_updates] enrich error: {type(e).__name__}: {e}")
    finally:
        _enriching = False
    return done
