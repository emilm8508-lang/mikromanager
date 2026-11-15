"""
Who a device is, across new addresses and names (3.74, round 3 stage A of docs/plan-runda-3.md).

The address and the name of a device are attributes; its key is what does not change:
  RouterOS   /system/routerboard serial-number; a CHR (no serial) /system/license software-id; fallback ether1's own (orig-) MAC
  Windows    Win32_ComputerSystemProduct.UUID (SMBIOS); fallback the MAC
  Linux      /etc/machine-id; fallback the MAC
  the rest   the MAC from ARP / the bridge tables (services/assets.py already follows a MAC to a new address)

Before 3.74 the router table was keyed by the address: a router found at a new address was a new row and the old one stayed for good,
with whatever was last read from it. Seen at sanmed: "R2-ĄP1" at 192.168.2.94 - model cAP ac, RouterOS 7.23.1, nothing at the address
any more - next to "wAP" at 192.168.2.90, and both carrying the same vulnerabilities.

  reconcile_devices()  rows of `devices` sharing a key are one device: the one read most recently stays; the others' names, addresses,
                       models and versions go into its history (asset_history), their inventory entries are joined into its entry, their
                       rows are removed
  history(...)         one change of one field of an asset, with its source
  name_key / bare      names compared after Unicode NFC and case folding; "bare" also drops the diacritics, so R2-ĄP1 and R2-AP1 are
                       shown as a pair - never joined on that alone
  run_once()           the one-off pass after the update: counts before and after (data/identity_merge.json, to Central)
"""
import json
import os
import re
import time
import unicodedata
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Device, Asset, AssetHistory

VERSION = 1
_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "identity_merge.json")
_BAD_SERIALS = {"", "0", "none", "unknown", "n/a", "na", "default string", "to be filled by o.e.m.", "system serial number", "123456789"}
_BAD_UUIDS = re.compile(r"^(0{8}-0{4}-0{4}-0{4}-0{12}|f{8}-f{4}-f{4}-f{4}-f{12}|03000200-0400-0500-0006-000700080009)$", re.I)
_TRACKED = ("name", "ip", "model", "os_version", "serial", "manufacturer")
_EXTRA = str.maketrans({"ł": "l", "Ł": "L", "đ": "d", "Đ": "D", "ø": "o", "Ø": "O", "ß": "ss"})


# ── keys ──────────────────────────────────────────────────────────────────────

def clean_uuid(v) -> Optional[str]:
    s = str(v or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s) or _BAD_UUIDS.match(s):
        return None
    return s


def clean_serial(v) -> Optional[str]:
    s = re.sub(r"\s+", "", str(v or "")).upper()
    bad = {re.sub(r"\s+", "", b) for b in _BAD_SERIALS}
    return None if s.lower() in bad or len(s) < 4 else s[:40]


def clean_mac(v) -> Optional[str]:
    h = re.sub(r"[^0-9a-fA-F]", "", str(v or ""))
    if len(h) != 12 or h in ("000000000000", "FFFFFFFFFFFF") or int(h[1], 16) & 1:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def device_keys(d) -> List[Tuple[str, str]]:
    keys = []
    if clean_serial(getattr(d, "serial", None)):
        keys.append(("serial", clean_serial(d.serial)))
    if getattr(d, "software_id", None) and str(d.software_id).strip():
        keys.append(("software_id", str(d.software_id).strip().upper()))
    if clean_mac(getattr(d, "mac_physical", None)):
        keys.append(("mac", clean_mac(d.mac_physical)))
    return keys


# ── names ─────────────────────────────────────────────────────────────────────

def name_key(n: Optional[str]) -> Optional[str]:
    """A name for comparison: NFC, case folded, trimmed."""
    s = unicodedata.normalize("NFC", (n or "").strip()).casefold()
    return s or None


def bare(n: Optional[str]) -> Optional[str]:
    """The name without diacritics (R2-ĄP1 -> r2-ap1)."""
    s = name_key(n)
    if not s:
        return None
    s = unicodedata.normalize("NFKD", s.translate(_EXTRA))
    return "".join(c for c in s if not unicodedata.combining(c)) or None


def diacritic_pairs(names: Iterable[Tuple[int, Optional[str]]]) -> List[List[str]]:
    """Names that differ only in diacritics: [["R2-ĄP1", "R2-AP1"], ...] - for the data-quality report, never joined on that alone."""
    by_bare: Dict[str, set] = {}
    for _id, n in names:
        b, k = bare(n), name_key(n)
        if b and k:
            by_bare.setdefault(b, set()).add(n.strip())
    out = []
    for b, ns in by_bare.items():
        keys = {name_key(x) for x in ns}
        if len(keys) > 1:
            out.append(sorted(ns))
    return sorted(out)


# ── history ───────────────────────────────────────────────────────────────────

def history(db, asset_id: int, field: str, old, new, source: str, at: Optional[datetime] = None) -> None:
    """One change of one field of an asset (the caller commits). Values are text, cut to 200."""
    if asset_id is None or str(old or "") == str(new or ""):
        return
    db.add(AssetHistory(asset_id=asset_id, field=field[:32], old=(str(old)[:200] if old is not None else None),
                        new=(str(new)[:200] if new is not None else None), at=at or datetime.utcnow(), source=(source or "")[:80]))


def tracked_values(a: Asset) -> dict:
    return {f: getattr(a, f, None) for f in _TRACKED}


def record_changes(db, a: Asset, before: dict, source: str = "inventory") -> int:
    """The tracked fields of an asset that changed since `before` (a value replaced, not one filled for the first time)."""
    n = 0
    for f in _TRACKED:
        old, new = before.get(f), getattr(a, f, None)
        if old and new and str(old) != str(new):
            history(db, a.id, f, old, new, source)
            n += 1
    return n


def asset_history(asset_id: int, limit: int = 50) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(AssetHistory).where(AssetHistory.asset_id == asset_id).order_by(AssetHistory.at.desc()).limit(limit)).scalars().all()
    return [{"field": r.field, "old": r.old, "new": r.new, "at": r.at.isoformat() + "Z", "source": r.source} for r in rows]


def previously(asset_id: int) -> Dict[str, List[str]]:
    """{"name": [earlier names], "ip": [earlier addresses]} - "R2-AP1, earlier: wAP / R2-ĄP1, 192.168.2.94"."""
    out: Dict[str, List[str]] = {}
    for h in asset_history(asset_id, 200):
        if h["field"] in ("name", "ip", "model") and h["old"] and h["old"] not in out.setdefault(h["field"], []):
            out[h["field"]].append(h["old"])
    return {k: v[:6] for k, v in out.items() if v}


# ── one device, one row ───────────────────────────────────────────────────────

def _asset_of_device(db, device_id: int) -> Optional[Asset]:
    for a in db.execute(select(Asset)).scalars().all():
        try:
            if json.loads(a.refs or "{}").get("device_id") == device_id:
                return a
        except ValueError:
            continue
    return None


def reconcile_devices(now: Optional[datetime] = None) -> dict:
    """Rows of `devices` that share a key (serial, software-id, ether1's MAC) are one device: the row read most recently stays, the others
    are absorbed into it. Returns {"groups", "absorbed", "details": [...]}."""
    from services import asset_merge
    now = now or datetime.utcnow()
    with SessionLocal() as db:
        devs = db.execute(select(Device)).scalars().all()
        parent = {d.id: d.id for d in devs}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        first: Dict[Tuple[str, str], int] = {}
        for d in devs:
            for k in device_keys(d):
                if k in first:
                    parent[find(d.id)] = find(first[k])
                else:
                    first[k] = d.id
        groups: Dict[int, List[Device]] = {}
        for d in devs:
            groups.setdefault(find(d.id), []).append(d)
        plan = []
        for g in groups.values():
            if len(g) < 2:
                continue
            g.sort(key=lambda d: (bool(d.online), d.last_seen or datetime.min, d.id), reverse=True)
            keep, rest = g[0], g[1:]
            key = next((f"{k}: {v}" for k, v in device_keys(keep) if any((k, v) in device_keys(o) for o in rest)), "key")
            plan.append((keep.id, [o.id for o in rest], key))
    absorbed, details = 0, []
    for keep_id, rest_ids, key in plan:
        for oid in rest_ids:
            r = _absorb(keep_id, oid, f"identity {key}", now)
            if r:
                absorbed += 1
                details.append(r)
    return {"groups": len(plan), "absorbed": absorbed, "details": details[:50]}


def _absorb(keep_id: int, other_id: int, source: str, now: datetime) -> Optional[dict]:
    from services import asset_merge
    with SessionLocal() as db:
        keep, other = db.get(Device, keep_id), db.get(Device, other_id)
        if keep is None or other is None:
            return None
        ka, oa = _asset_of_device(db, keep_id), _asset_of_device(db, other_id)
        target = ka or oa
        if target is not None:
            for field, old, new in (("name", other.identity or other.name, keep.identity or keep.name), ("ip", other.ip, keep.ip),
                                    ("model", other.model, keep.model), ("os_version", other.ros_version, keep.ros_version)):
                history(db, target.id, field, old, new, source, now)
            if ka is None and oa is not None:                   # the kept row has no entry yet: the old one follows it
                refs = json.loads(oa.refs or "{}")
                refs["device_id"] = keep_id
                oa.refs = json.dumps(refs)
        info = {"kept": keep.identity or keep.ip, "kept_ip": keep.ip, "absorbed": other.identity or other.ip, "absorbed_ip": other.ip, "by": source}
        db.delete(other)
        db.commit()
        ka_id, oa_id = (ka.id if ka else None), (oa.id if oa else None)
    if ka_id and oa_id and ka_id != oa_id:
        try:
            asset_merge.merge(ka_id, [oa_id])                  # alerts, availability, notes, criticality ... move to the kept entry
        except ValueError as e:
            info["merge_error"] = str(e)
    return info


# ── the one-off pass ──────────────────────────────────────────────────────────

def _counts() -> dict:
    from services import asset_merge
    with SessionLocal() as db:
        assets = db.execute(select(Asset)).scalars().all()
        devs = db.execute(select(Device)).scalars().all()
    names: Dict[str, int] = {}
    for a in assets:
        k = asset_merge.norm_name(a.name)
        if k:
            names[k] = names.get(k, 0) + 1
    return {"assets": len(assets), "devices": len(devs), "same_name": sum(n for n in names.values() if n > 1),
            "virtual_monitors": sum(1 for a in assets if a.asset_type == "monitor" and virtual_monitor(a.manufacturer, a.model, a.name))}


def virtual_monitor(maker: Optional[str], model: Optional[str], name: Optional[str]) -> bool:
    """A monitor that is not a screen: the virtual display of a Hyper-V VM ("HyperVMonitor", maker code MSH) or of a remote desktop
    session (seen at sanmed: 143 "HyperVMonitor" entries - 143 of its 155 names used by several entries)."""
    text = f"{name or ''} {model or ''}"
    return (maker or "").strip().upper() == "MSH" or bool(re.search(r"hyper-?v|remote ?desktop|\brdp\b|virtual display|microsoft basic", text, re.I))


def load() -> dict:
    try:
        with open(_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


async def run_once(force: bool = False) -> dict:
    """After the update, once: the counts before, the device rows joined by key, the inventory rebuilt (virtual monitors out, entries of
    one key joined), the counts after, and the join proposals left for the operator."""
    from services import assets, asset_merge
    prev = load()
    if prev.get("version") == VERSION and prev.get("finished_at") and not force:
        return prev
    st = {"version": VERSION, "started_at": datetime.utcnow().isoformat() + "Z", "finished_at": None}
    try:
        st["before"] = _counts()
        st["devices"] = reconcile_devices()
        await assets.refresh(directory=False)
        st["joined_by_key"] = asset_merge.auto_merge()
        st["after"] = _counts()
        dups = asset_merge.duplicates()
        st["proposed"] = sum(1 for g in dups if not g["auto"])
        st["proposed_by_reason"] = {}
        for g in dups:
            if not g["auto"]:
                for r in g["reasons"]:
                    st["proposed_by_reason"][r] = st["proposed_by_reason"].get(r, 0) + 1
        st["finished_at"] = datetime.utcnow().isoformat() + "Z"
        print(f"[identity] one-off pass: {st}")
    except Exception as e:
        st["error"] = f"{type(e).__name__}: {e}"[:300]
        print(f"[identity] one-off pass failed: {st['error']}")
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, default=str)
    os.replace(tmp, _PATH)
    return st


def start(delay_sec: float = 180.0) -> None:
    import asyncio
    if load().get("version") == VERSION and load().get("finished_at"):
        return

    async def later():
        await asyncio.sleep(delay_sec)
        await run_once()
    asyncio.get_event_loop().create_task(later())


def previously_many(asset_ids: Iterable[int]) -> Dict[int, dict]:
    """previously() for many assets in one query: {asset_id: {"n": [names], "ip": [addresses]}} (only those that have one)."""
    ids = [i for i in asset_ids if isinstance(i, int)]
    if not ids:
        return {}
    out: Dict[int, dict] = {}
    with SessionLocal() as db:
        for i in range(0, len(ids), 500):
            for r in db.execute(select(AssetHistory).where(AssetHistory.asset_id.in_(ids[i:i + 500]), AssetHistory.field.in_(("name", "ip")))
                                .order_by(AssetHistory.at.desc())).scalars().all():
                if not r.old:
                    continue
                e = out.setdefault(r.asset_id, {})
                k = "n" if r.field == "name" else "ip"
                lst = e.setdefault(k, [])
                if r.old not in lst and len(lst) < 5:
                    lst.append(r.old)
    return out
