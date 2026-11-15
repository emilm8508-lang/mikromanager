"""
A router's facts as it says them now (3.75, round 3 stage B of docs/plan-runda-3.md).

Before 3.75 the version, the identity, the model, the serial number and the RouterBOOT firmware were read once a day (services/refresher.py)
and a failed read left the old values with no date. Seen at sanmed: the AP R2-AP1 on 7.25.1 shown with 7.23.2, and its vulnerabilities
"confirmed". Now:

  apply()            every resource cycle (services/resource_monitor.py, over the API login 3.73 keeps open) writes them with the time
                     they were read (version_seen_at, facts_seen_at)
  a new version      the asset's history gets "RouterOS updated old -> new" (the proof of patching); the findings of the old version
                     that the new one does not have are closed "fixed_by_upgrade: old -> new" - remediation rows (when no other device is
                     still on the old version) and the "new vulnerability" alerts of this device
  routerboot()       RouterBOOT current < upgrade: one low alert with what to do; closed when equal
  freshness()        how sure a version is: read over the API in the last 24 h - confirmed; up to 7 days - likely; older - suspected,
                     stale_version (services/vuln_scan.hosts_with_findings)
  neighbors()        the MNDP / LLDP table of every router (/ip/neighbor) as a second source: a device whose version or identity there
                     differs is updated when the API has nothing fresher, else the difference goes to the data-quality report
"""
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Device, Asset

FRESH_H = 24
STALE_DAYS = 7
_MISMATCH_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mndp_mismatch.json")
PRODUCT = "MikroTik RouterOS"


def version_number(v: Optional[str]) -> Optional[str]:
    """"7.25.1 (stable)" -> "7.25.1"."""
    m = re.match(r"\s*(\d+(?:\.\d+)+)", str(v or ""))
    return m.group(1) if m else None


def _vt(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def freshness(seen_at: Optional[datetime], now: Optional[datetime] = None) -> Tuple[Optional[str], bool]:
    """(the most a finding on this version may be, stale_version). None = not known (before 3.75): no cap."""
    if seen_at is None:
        return None, False
    age = (now or datetime.utcnow()) - seen_at
    if age <= timedelta(hours=FRESH_H):
        return "confirmed", False
    if age <= timedelta(days=STALE_DAYS):
        return "likely", False
    return "suspected", True


def _asset_id(db, device_id: int) -> Optional[int]:
    for a in db.execute(select(Asset.id, Asset.refs)).all():
        try:
            if json.loads(a.refs or "{}").get("device_id") == device_id:
                return a.id
        except ValueError:
            continue
    return None


async def apply(device_id: int, info: dict, source: str = "routeros_api", now: Optional[datetime] = None) -> dict:
    """Writes what was just read from the router. info: identity, ros_version ("7.25.1 (stable)"), model, board_name, serial,
    current_firmware, upgrade_firmware. Returns {"changed": [...], "upgraded": (old, new) | None, "fixed": n}."""
    from services import identity
    now = now or datetime.utcnow()
    out = {"changed": [], "upgraded": None, "fixed": 0}
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        if d is None:
            return out
        old_v = d.ros_version
        for k in ("identity", "ros_version", "model", "board_name", "serial", "current_firmware", "upgrade_firmware"):
            v = info.get(k)
            if v and str(v) != str(getattr(d, k) or ""):
                setattr(d, k, str(v)[:120])
                out["changed"].append(k)
        if info.get("ros_version"):
            d.version_seen_at = now
            d.version_source = source
        if any(info.get(k) for k in ("identity", "serial", "current_firmware")):
            d.facts_seen_at = now
        d.online = True
        on, nn = version_number(old_v), version_number(info.get("ros_version"))
        aid = _asset_id(db, device_id)
        if on and nn and on != nn:
            out["upgraded"] = (on, nn)
            if aid:
                identity.history(db, aid, "os_version", old_v, info.get("ros_version"), f"{source}: RouterOS {'updated' if _vt(nn) > _vt(on) else 'changed'}", now)
        ip = d.ip
        cur, upg = d.current_firmware, d.upgrade_firmware
        name = d.identity or d.name or d.ip
        db.commit()
    if out["upgraded"]:
        out["fixed"] = await fixed_by_upgrade(device_id, ip, out["upgraded"][0], out["upgraded"][1], now)
    routerboot(name, ip, cur, upg, device_id)
    return out


async def fixed_by_upgrade(device_id: int, ip: str, old: str, new: str, now: Optional[datetime] = None) -> int:
    """The findings of `old` that `new` does not have: closed with the reason - the remediation rows of the old version when no other
    device runs it any more, and this device's open "new vulnerability" alerts."""
    from services import vuln_scan, soc
    from models.database import VulnFinding, SocAlert
    now = now or datetime.utcnow()
    reason = f"fixed_by_upgrade: {old} → {new}"
    with SessionLocal() as db:
        old_pairs = {(p, v) for p, v in db.execute(select(VulnFinding.product, VulnFinding.version).where(VulnFinding.product == PRODUCT)).all()
                     if version_number(v) == old}
        old_cves = {c for (c,) in db.execute(select(VulnFinding.cve_id).where(VulnFinding.product == PRODUCT,
                                                                            VulnFinding.version.in_([v for _p, v in old_pairs] or [""]))).all()}
        new_v = db.get(Device, device_id).ros_version if db.get(Device, device_id) else new
    new_cves: set = set()
    errors_before = vuln_scan._nvd_health.get("errors", 0)
    try:
        with SessionLocal() as db:
            new_cves = {f.cve_id for f in await vuln_scan._get_findings_for(db, PRODUCT, new_v)}
    except Exception as e:
        print(f"[device_facts] lookup of {new_v}: {type(e).__name__}: {e}")
        return 0                                                    # not known what the new version has: nothing closed on a guess
    if vuln_scan._nvd_health.get("errors", 0) > errors_before:
        print(f"[device_facts] NVD did not answer for {new_v}: nothing closed, the next read tries again")
        return 0                                                    # an unanswered lookup returns the cache - empty for a new version
    fixed = old_cves - new_cves
    n = 0
    with SessionLocal() as db:
        still = {version_number(d.ros_version) for d in db.execute(select(Device)).scalars().all() if d.id != device_id}
        if old not in still:
            for _p, v in old_pairs:
                n += vuln_scan._auto_close(db, PRODUCT, v, fixed, reason)
        for a in db.execute(select(SocAlert).where(SocAlert.rule == "rule.new_vuln", SocAlert.ip == ip, SocAlert.status.in_(soc.OPEN))).scalars().all():
            try:
                cve = json.loads(a.detail or "{}").get("cve")
            except ValueError:
                cve = None
            if cve in fixed:
                a.status, a.closed_at, a.closed_by = "closed", now, f"auto: {reason}"
                n += 1
        db.commit()
    return n


def routerboot(name: str, ip: str, current: Optional[str], upgrade: Optional[str], device_id: Optional[int] = None) -> Optional[str]:
    """One low alert while the RouterBOOT firmware is older than the one the installed RouterOS brings; closed when it is not."""
    from services import soc
    c, u = version_number(current), version_number(upgrade)
    if not c or not u:
        return None
    if _vt(c) < _vt(u):
        soc.raise_alert(rule="device.routerboot_outdated", device=name, ip=ip, title="RouterBOOT firmware not up to date", severity="low",
                        category="system", fp_detail="routerboot", count=0,
                        detail={"message": f"RouterBOOT {c}, the installed RouterOS brings {u}",
                                "advice": "/system routerboard upgrade, then a restart in a maintenance window", "state": f"{c} < {u}"})
        return "raised"
    soc.resolve(rule="device.routerboot_outdated", device=name, fp_detail="routerboot")
    return None


# ── MNDP / LLDP: the second source ────────────────────────────────────────────

def neighbors(router_id: int, rows: List[dict], now: Optional[datetime] = None) -> dict:
    """One router's /ip/neighbor rows: a known device (by its MAC, else its address) whose version or identity there differs from the
    inventory is updated when the API read is older than FRESH_H, else noted as a mismatch for the data-quality report."""
    from services import identity
    now = now or datetime.utcnow()
    upd, mism = 0, []
    with SessionLocal() as db:
        devs = db.execute(select(Device)).scalars().all()
        by_mac = {}
        for d in devs:
            for m in (identity.clean_mac(d.mac_physical), identity.clean_mac(d.mac)):
                if m:
                    by_mac.setdefault(m, d)
        by_ip = {d.ip: d for d in devs}
        for n in rows or []:
            if not isinstance(n, dict):
                continue
            d = by_mac.get(identity.clean_mac(n.get("mac-address"))) or by_ip.get(str(n.get("address") or n.get("address4") or ""))
            if d is None or d.id == router_id:
                continue
            seen = {"version": version_number(n.get("version")), "identity": (n.get("identity") or "").strip()[:64] or None,
                    "address": (n.get("address") or n.get("address4") or None), "board": (n.get("board") or None)}
            diff = {}
            if seen["version"] and version_number(d.ros_version) and seen["version"] != version_number(d.ros_version):
                diff["version"] = (d.ros_version, n.get("version"))
            if seen["identity"] and (d.identity or "") and identity.name_key(seen["identity"]) != identity.name_key(d.identity):
                diff["identity"] = (d.identity, seen["identity"])
            if seen["address"] and seen["address"] != d.ip:
                diff["address"] = (d.ip, seen["address"])
            if not diff:
                continue
            api_fresh = d.version_seen_at is not None and now - d.version_seen_at <= timedelta(hours=FRESH_H)
            if not api_fresh and ("version" in diff or "identity" in diff):
                if "version" in diff:
                    d.ros_version, d.version_seen_at, d.version_source = str(n.get("version"))[:40], now, "mndp"
                if "identity" in diff:
                    d.identity = seen["identity"]
                upd += 1
            mism.append({"device": d.identity or d.ip, "ip": d.ip, "seen_by": router_id, "differs": {k: list(v) for k, v in diff.items()},
                         "updated": not api_fresh and ("version" in diff or "identity" in diff)})
        db.commit()
    cur = _load_mismatch()
    cur["routers"][str(router_id)] = {"at": now.isoformat() + "Z", "items": mism[:100]}
    _save_mismatch(cur)
    return {"updated": upd, "mismatches": len(mism)}


def _load_mismatch() -> dict:
    try:
        with open(_MISMATCH_PATH, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d.get("routers"), dict) else {"routers": {}}
    except (OSError, ValueError):
        return {"routers": {}}


def _save_mismatch(d: dict) -> None:
    os.makedirs(os.path.dirname(_MISMATCH_PATH), exist_ok=True)
    tmp = _MISMATCH_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(tmp, _MISMATCH_PATH)


def mismatches() -> List[dict]:
    """What the routers' neighbor tables say differently from the inventory (the latest read of each router)."""
    out = []
    for r in _load_mismatch()["routers"].values():
        out.extend(r.get("items") or [])
    return out[:200]
