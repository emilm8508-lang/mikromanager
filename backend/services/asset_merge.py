"""
Two entries for one machine: finding them and joining them.

An asset is keyed by its address ("ip:10.0.0.5"). When a machine gets a new address, the inventory follows it by MAC address or by the managed object behind it (router, Windows /
Linux host, Hyper-V VM, and - since the server record of a BMC was added to that list - a Dell / HP / Fujitsu server), so no second entry appears. What it cannot follow is
a machine that is only known by its name from two sources, or an entry made before the rule existed. This module:

  * duplicates()    lists the entries that look like one machine: the same managed object behind two entries, the same MAC address, the same name (and no hardware that
                    contradicts it);
  * merge()         joins entries into one: the facts one of them lacks are taken over, tags are combined, notes are kept, and everything that points at an entry by its id
                    (alerts, availability history, metrics, syslog, rack items, peripherals, business services, maintenance windows, the monitors and printers that belong
                    to a computer) is pointed at the survivor, so nothing is lost and nothing dangles;
  * auto_merge()    called by every inventory rebuild: joins the cases that are certain - the same managed object, or the same name where one entry has not been seen for days
                    and the other is alive and their hardware does not disagree. Two entries that are both alive with the same name are only offered, never joined by themselves.
"""
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete

from models.database import (SessionLocal, Asset, AssetPeripheral, SocAlert, SyslogEvent, MetricSeries, AvailState, AvailEvent, RackItem, BizService, MaintenanceWindow, VulnHost, VulnService,
                             VulnPackage)

MANAGED_KEYS = ("linux_host_id", "windows_host_id", "device_id", "hyperv_vm_id", "dell_server_id")
STALE_DAYS = 2
GENERIC_NAMES = {"localhost", "unknown", "null", "none", "host", "server", "pc", "router", "switch", "printer", "default", "android", "iphone", "ipad", "laptop", "desktop"}


def _jl(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def norm_name(n: Optional[str]) -> Optional[str]:
    """The name as a comparison key, or None for names that say nothing (empty, too short, generic, or just an address)."""
    n = (n or "").strip().lower()
    if len(n) < 3 or n in GENERIC_NAMES or re.fullmatch(r"[\d.:]+", n):
        return None
    return n


def _norm_mac(m: Optional[str]) -> Optional[str]:
    m = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    return m if len(m) == 12 and m not in ("0" * 12, "f" * 12) else None


def _alive(a: Asset, now: datetime) -> bool:
    return bool(a.last_seen_at and now - a.last_seen_at < timedelta(days=STALE_DAYS))


def _freshness(a: Asset):
    return (a.last_seen_at or a.first_seen_at or datetime.min)


def _compatible(a: Asset, b: Asset) -> bool:
    """Whether two entries could be one machine: no two different MAC addresses, no two different serial numbers, no two different (real) types."""
    ma, mb = _norm_mac(a.mac), _norm_mac(b.mac)
    if ma and mb and ma != mb:
        return False
    sa, sb = (a.serial or "").strip().lower(), (b.serial or "").strip().lower()
    if sa and sb and sa != sb:
        return False
    ta, tb = a.asset_type or "other", b.asset_type or "other"
    if ta != tb and "other" not in (ta, tb):
        # a computer and its BMC are different machines even when they share a name
        return False
    return True


def _view(a: Asset, now: datetime) -> dict:
    refs = _jl(a.refs, {})
    return {"id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "mac": a.mac, "type": a.asset_type, "last_seen_at": (a.last_seen_at.isoformat() + "Z") if a.last_seen_at else None,
            "alive": _alive(a, now), "managed": [k for k in MANAGED_KEYS if refs.get(k)], "has_notes": bool(a.notes or a.manual_groups or a.place or a.location_override)}


def _groups(db, now: datetime) -> List[dict]:
    """Candidate groups: [{"reason": ref | mac | name, "ids": [...], "auto": bool}]; an entry can be in several groups of different reasons (the caller merges transitively)."""
    assets = db.execute(select(Asset)).scalars().all()
    out: List[dict] = []
    by_ref: Dict[tuple, List[Asset]] = {}
    by_mac: Dict[str, List[Asset]] = {}
    by_name: Dict[str, List[Asset]] = {}
    for a in assets:
        if a.key.startswith(("mon:", "prt:")):
            continue                                         # a monitor or printer attached to a computer is a thing of its own
        for k, v in _jl(a.refs, {}).items():
            if k in MANAGED_KEYS and isinstance(v, int):
                by_ref.setdefault((k, v), []).append(a)
        m = _norm_mac(a.mac)
        if m:
            by_mac.setdefault(m, []).append(a)
        n = norm_name(a.name)
        if n:
            by_name.setdefault(n, []).append(a)
    for (k, v), g in by_ref.items():
        if len(g) > 1:
            out.append({"reason": "ref", "ids": [a.id for a in g], "auto": True})
    for m, g in by_mac.items():
        if len(g) > 1 and all(_compatible(x, y) for i, x in enumerate(g) for y in g[i + 1:]):
            out.append({"reason": "mac", "ids": [a.id for a in g], "auto": sum(1 for a in g if _alive(a, now)) <= 1})
    for n, g in by_name.items():
        if len(g) < 2:
            continue
        ok = [a for a in g if all(_compatible(a, b) for b in g if b is not a)]
        if len(ok) < 2:
            continue
        # joined by themselves only when exactly one entry is alive and the others have been silent for days
        alive = [a for a in ok if _alive(a, now)]
        out.append({"reason": "name", "ids": [a.id for a in ok], "auto": len(alive) == 1})
    return out


def _components(groups: List[dict]) -> List[dict]:
    """Joins the groups that share an entry into components: [{"ids": [...], "reasons": [...], "auto": all groups auto}]."""
    comps: List[dict] = []
    for g in groups:
        hit = [c for c in comps if set(c["ids"]) & set(g["ids"])]
        merged = {"ids": set(g["ids"]), "reasons": {g["reason"]}, "auto": g["auto"]}
        for c in hit:
            merged["ids"] |= c["ids"]
            merged["reasons"] |= c["reasons"]
            merged["auto"] = merged["auto"] and c["auto"]
            comps.remove(c)
        comps.append(merged)
    return comps


def _survivor(db, ids: List[int], live_keys: Optional[set] = None) -> int:
    """Which entry stays: the one a current source still lists (its key), then the one seen most recently, then the oldest (it has the history)."""
    rows = [db.get(Asset, i) for i in ids]
    rows = [a for a in rows if a is not None]
    rows.sort(key=lambda a: (0 if (live_keys and a.key in live_keys) else 1, -(a.last_seen_at or datetime.min).timestamp() if a.last_seen_at else 0, a.first_seen_at or datetime.max))
    return rows[0].id


def duplicates(live_keys: Optional[set] = None) -> List[dict]:
    """The candidate groups for the page: [{"ids", "reasons", "auto", "keep", "assets": [...]}], the ones the next rebuild would join by itself marked auto."""
    now = datetime.utcnow()
    with SessionLocal() as db:
        out = []
        for c in _components(_groups(db, now)):
            ids = sorted(c["ids"])
            keep = _survivor(db, ids, live_keys)
            rows = [db.get(Asset, i) for i in ids]
            out.append({"ids": ids, "reasons": sorted(c["reasons"]), "auto": bool(c["auto"]), "keep": keep, "assets": [_view(a, now) for a in rows if a is not None]})
        out.sort(key=lambda g: (g["auto"], g["ids"][0]))
        return out


def merge(keep_id: int, drop_ids: List[int]) -> dict:
    """Joins the entries `drop_ids` into `keep_id`. Returns {"merged": n}. ValueError when an id is missing or the survivor is among the dropped ones."""
    drop_ids = [i for i in dict.fromkeys(drop_ids) if isinstance(i, int)]
    if not drop_ids or keep_id in drop_ids:
        raise ValueError("choose the entry to keep and at least one other")
    with SessionLocal() as db:
        keep = db.get(Asset, keep_id)
        if keep is None:
            raise ValueError("the entry to keep does not exist")
        n = 0
        for did in drop_ids:
            drop = db.get(Asset, did)
            if drop is None:
                raise ValueError(f"entry {did} does not exist")
            _merge_one(db, keep, drop)
            n += 1
        db.commit()
    return {"merged": n}


def _merge_one(db, keep: Asset, drop: Asset) -> None:
    kid, did = keep.id, drop.id
    # facts: what the survivor lacks is taken over, what it has stays
    for f in ("mac", "manufacturer", "model", "serial", "os_name", "os_version", "role", "place", "location_override", "name"):
        if not getattr(keep, f) and getattr(drop, f):
            setattr(keep, f, getattr(drop, f))
    if (not keep.asset_type or keep.asset_type == "other") and drop.asset_type:
        keep.asset_type = drop.asset_type
    keep.first_seen_at = min(filter(None, [keep.first_seen_at, drop.first_seen_at]), default=keep.first_seen_at)
    keep.last_seen_at = max(filter(None, [keep.last_seen_at, drop.last_seen_at]), default=keep.last_seen_at)
    keep.last_scan_at = max(filter(None, [keep.last_scan_at, drop.last_scan_at]), default=None)
    if keep.monitor is None:
        keep.monitor = drop.monitor
    tags = list(dict.fromkeys(_jl(keep.manual_groups, []) + _jl(drop.manual_groups, [])))
    keep.manual_groups = json.dumps(tags[:20]) if tags else keep.manual_groups
    if drop.notes and drop.notes != keep.notes:
        keep.notes = f"{keep.notes}\n[{drop.name or drop.ip or drop.key}] {drop.notes}" if keep.notes else drop.notes
    kref, dref = _jl(keep.refs, {}), _jl(drop.refs, {})
    for k, v in dref.items():
        if k not in kref and v:
            kref[k] = v
    dvuln = dref.get("vuln_host_id")
    keep.refs = json.dumps(kref)
    det, ddet = _jl(keep.details, {}), _jl(drop.details, {})
    for k, v in ddet.items():
        if k not in det:
            det[k] = v
    over = {**ddet.get("_over", {}), **det.get("_over", {})}
    if over:
        det["_over"] = over
    keep.details = json.dumps(det) if det else keep.details
    if keep.scan_level == "passive" and drop.scan_level and drop.scan_level != "passive":
        keep.scan_level = drop.scan_level
    # everything that points at the dropped entry by its id now points at the survivor
    db.execute(AssetPeripheral.__table__.update().where(AssetPeripheral.asset_id == did).values(asset_id=kid))
    db.execute(SocAlert.__table__.update().where(SocAlert.asset_id == did).values(asset_id=kid))
    db.execute(SocAlert.__table__.update().where(SocAlert.root_asset_id == did).values(root_asset_id=kid))
    db.execute(SyslogEvent.__table__.update().where(SyslogEvent.asset_id == did).values(asset_id=kid))
    db.execute(MetricSeries.__table__.update().where(MetricSeries.asset_id == did).values(asset_id=kid))
    db.execute(RackItem.__table__.update().where(RackItem.asset_id == did).values(asset_id=kid))
    db.execute(AvailEvent.__table__.update().where(AvailEvent.asset_id == did).values(asset_id=kid))
    st_drop, st_keep = db.get(AvailState, did), db.get(AvailState, kid)
    if st_drop is not None:
        if st_keep is None:                                   # the survivor was not monitored: it takes over the state and its history
            st_keep = AvailState(asset_id=kid, state=st_drop.state, since=st_drop.since, last_check=st_drop.last_check, first_check=st_drop.first_check, alerted=st_drop.alerted,
                                 root_asset_id=st_drop.root_asset_id, detail=st_drop.detail)
            db.add(st_keep)
        elif st_drop.first_check and st_keep.first_check and st_drop.first_check < st_keep.first_check:
            st_keep.first_check = st_drop.first_check
        db.delete(st_drop)
    db.execute(AvailState.__table__.update().where(AvailState.root_asset_id == did).values(root_asset_id=kid))
    for s in db.execute(select(BizService)).scalars().all():
        ids = [int(x) for x in _jl(s.members, [])]
        if did in ids:
            s.members = json.dumps(list(dict.fromkeys(kid if x == did else x for x in ids)))
    for w in db.execute(select(MaintenanceWindow)).scalars().all():
        ids = [int(x) for x in _jl(w.asset_ids, [])]
        if did in ids:
            w.asset_ids = json.dumps(list(dict.fromkeys(kid if x == did else x for x in ids)))
    for a in db.execute(select(Asset).where(Asset.refs.is_not(None))).scalars().all():
        if a.id in (kid, did):
            continue
        r = _jl(a.refs, {})
        changed = False
        for k in ("monitor_of", "printer_of"):
            if r.get(k) == did:
                r[k] = kid
                changed = True
        if changed:
            a.refs = json.dumps(r)
    # the dropped entry's port-scan result goes with it, unless the survivor stands on the same one
    if dvuln and dvuln != kref.get("vuln_host_id"):
        for m in (VulnService, VulnPackage):
            db.execute(delete(m).where(m.host_id == dvuln).execution_options(synchronize_session=False))
        db.execute(delete(VulnHost).where(VulnHost.id == dvuln).execution_options(synchronize_session=False))
    db.delete(drop)
    db.flush()


def auto_merge(live_keys: Optional[set] = None) -> int:
    """Joins the certain cases (see the module text). Returns how many entries went away. Never raises: a failure only skips this round."""
    try:
        now = datetime.utcnow()
        n = 0
        with SessionLocal() as db:
            comps = [c for c in _components(_groups(db, now)) if c["auto"]]
        for c in comps:
            ids = sorted(c["ids"])
            with SessionLocal() as db:
                keep = _survivor(db, ids, live_keys)
            rest = [i for i in ids if i != keep]
            try:
                n += merge(keep, rest)["merged"]
            except ValueError:
                continue
        if n:
            print(f"[assets] joined {n} duplicate entr{'y' if n == 1 else 'ies'}")
        return n
    except Exception as e:
        print(f"[assets] duplicate check skipped: {type(e).__name__}: {e}")
        return 0
