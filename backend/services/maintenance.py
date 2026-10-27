"""
Maintenance windows: planned work is not an incident.

Rebooting a switch at night for a firmware upgrade makes it - and everything behind it - fail, and the SOC layer, Central and the Telegram channels dutifully report
all of it. A maintenance window says "this is planned": the devices it covers (or the whole network) are muted for its duration:

  * their alert events are not sent to Central and no ServiceDesk ticket is opened for them (the alerts still appear in the agent's own SOC queue, marked as
    "in maintenance", so nothing is hidden from the people who work there), and they are not escalated;
  * a business service whose missing members are all in maintenance does not alert either.

A window is either one-off (from - to) or weekly (days of the week, a start time, a length - in the agent's local time, e.g. "Sunday 02:00-04:00"). A "mute for 2 hours"
shortcut makes a one-off window for chosen devices. Windows are stored in `maintenance_windows`; nothing is deleted when one ends, and the number of events a window
suppressed is counted for the page.
"""
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete, func

from models.database import SessionLocal, MaintenanceWindow, Asset

_stats: Dict[int, int] = {}              # window id -> events suppressed since the agent started
_cache = {"at": 0.0, "windows": []}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _ids(w: MaintenanceWindow) -> List[int]:
    try:
        return [int(x) for x in json.loads(w.asset_ids or "[]")]
    except Exception:
        return []


def _days(w: MaintenanceWindow) -> List[int]:
    return [int(x) for x in (w.days or "").split(",") if x.strip().isdigit() and 0 <= int(x) <= 6]


def _minutes(hhmm: Optional[str]) -> Optional[int]:
    try:
        h, m = (hhmm or "").split(":")
        h, m = int(h), int(m)
        return h * 60 + m if 0 <= h < 24 and 0 <= m < 60 else None
    except ValueError:
        return None


def is_active(w: MaintenanceWindow, now_utc: Optional[datetime] = None, now_local: Optional[datetime] = None) -> bool:
    if not w.enabled:
        return False
    now_utc = now_utc or _now()
    if w.kind == "once":
        return bool(w.starts_at and w.ends_at and w.starts_at <= now_utc < w.ends_at)
    now_local = now_local or datetime.now()
    start, dur = _minutes(w.start_time), int(w.duration_min or 0)
    if start is None or dur <= 0:
        return False
    days = _days(w)
    cur = now_local.hour * 60 + now_local.minute
    # the window that began today, and the one that began yesterday and runs past midnight
    if now_local.weekday() in days and start <= cur < start + dur:
        return True
    return (now_local.weekday() - 1) % 7 in days and start + dur > 24 * 60 and cur < start + dur - 24 * 60


def active_windows(now_utc: Optional[datetime] = None, now_local: Optional[datetime] = None) -> List[dict]:
    """The windows in force now: [{id, name, all, assets: set(ids)}] (cached for 20 s)."""
    if now_utc is None and time.time() - _cache["at"] < 20:
        return _cache["windows"]
    with SessionLocal() as db:
        out = [{"id": w.id, "name": w.name, "all": bool(w.scope_all), "assets": set(_ids(w))} for w in db.execute(select(MaintenanceWindow)).scalars().all() if is_active(w, now_utc, now_local)]
    if now_utc is None:
        _cache.update(at=time.time(), windows=out)
    return out


def invalidate() -> None:
    _cache["at"] = 0.0


def covers_asset(asset_id: Optional[int], windows: Optional[List[dict]] = None) -> Optional[dict]:
    """The window that mutes this asset now, or None."""
    for w in (windows if windows is not None else active_windows()):
        if w["all"] or (asset_id is not None and asset_id in w["assets"]):
            return w
    return None


def _asset_by_name(db, name: Optional[str]) -> Optional[int]:
    if not name:
        return None
    r = db.execute(select(Asset.id).where(func.lower(Asset.name) == name.split(":")[0].strip().lower()).limit(1)).first()
    return r[0] if r else None


def covers_alert(asset_id: Optional[int], device: Optional[str], ip: Optional[str]) -> Optional[str]:
    """The name of the window that mutes an alert about this device, or None (used to mark alerts in the SOC queue)."""
    ws = active_windows()
    if not ws:
        return None
    if any(w["all"] for w in ws):
        return next(w["name"] for w in ws if w["all"])
    with SessionLocal() as db:
        aid = asset_id
        if aid is None and ip:
            r = db.execute(select(Asset.id).where(Asset.ip == ip).limit(1)).first()
            aid = r[0] if r else None
        if aid is None:
            aid = _asset_by_name(db, device)
    w = covers_asset(aid, ws)
    return w["name"] if w else None


def _event_covered(db, e: dict, ws: List[dict]) -> Optional[dict]:
    if any(w["all"] for w in ws):
        return next(w for w in ws if w["all"])
    aid = e.get("asset_id") if isinstance(e.get("asset_id"), int) else None
    if aid is None and (e.get("ip") or e.get("device_ip")):
        r = db.execute(select(Asset.id).where(Asset.ip == (e.get("ip") or e.get("device_ip"))).limit(1)).first()
        aid = r[0] if r else None
    if aid is None:
        aid = _asset_by_name(db, e.get("device_name") or e.get("server_name") or e.get("host_name"))
    w = covers_asset(aid, ws)
    if w:
        return w
    # an event about something that depends on devices (a business service, a failed device with others behind it): muted when everything it lists is muted
    names = e.get("affected")
    if e.get("type") in ("bizservice_problem", "bizservice_ok") and isinstance(names, list) and names:
        found = []
        for n in names:
            x = covers_asset(_asset_by_name(db, str(n)), ws)
            if not x:
                return None
            found.append(x)
        return found[0]
    return None


def filter_events(events: List[dict]) -> List[dict]:
    """The alert events without those of devices in maintenance (counted per window)."""
    ws = active_windows()
    if not ws or not events:
        return events
    kept = []
    with SessionLocal() as db:
        for e in events:
            if not isinstance(e, dict):
                continue
            w = _event_covered(db, e, ws)
            if w is None:
                kept.append(e)
            else:
                _stats[w["id"]] = _stats.get(w["id"], 0) + 1
    return kept


# ── Windows ──────────────────────────────────────────────────────────────────

def _clean(body: dict) -> dict:
    name = str(body.get("name") or "").strip()
    if not name or len(name) > 80:
        raise ValueError("name required (80 characters at most)")
    kind = body.get("kind")
    if kind not in ("once", "weekly"):
        raise ValueError("kind must be once or weekly")
    scope_all = bool(body.get("scope_all"))
    ids = [int(x) for x in (body.get("asset_ids") or [])]
    if not scope_all and not ids:
        raise ValueError("choose the devices or the whole network")
    out = {"name": name, "kind": kind, "scope_all": scope_all, "asset_ids": json.dumps(ids[:500]), "enabled": bool(body.get("enabled", True)),
           "starts_at": None, "ends_at": None, "days": None, "start_time": None, "duration_min": None}
    if kind == "once":
        try:
            a = datetime.fromisoformat(str(body.get("starts_at")).replace("Z", "")[:19])
            b = datetime.fromisoformat(str(body.get("ends_at")).replace("Z", "")[:19])
        except ValueError:
            raise ValueError("starts_at and ends_at are required (ISO time, UTC)")
        if b <= a or b - a > timedelta(days=60):
            raise ValueError("the window must end after it starts and last at most 60 days")
        out.update(starts_at=a, ends_at=b)
    else:
        days = sorted({int(d) for d in (body.get("days") or []) if 0 <= int(d) <= 6})
        if not days or _minutes(body.get("start_time")) is None:
            raise ValueError("choose the days of the week and a start time (HH:MM)")
        dur = int(body.get("duration_min") or 0)
        if not (5 <= dur <= 24 * 60):
            raise ValueError("the length is between 5 minutes and 24 hours")
        out.update(days=",".join(str(d) for d in days), start_time=body["start_time"], duration_min=dur)
    return out


def _view(w: MaintenanceWindow, names: Dict[int, str]) -> dict:
    return {"id": w.id, "name": w.name, "kind": w.kind, "scope_all": bool(w.scope_all), "asset_ids": _ids(w), "assets": [names.get(i, str(i)) for i in _ids(w)][:20],
            "starts_at": _iso(w.starts_at), "ends_at": _iso(w.ends_at), "days": _days(w), "start_time": w.start_time, "duration_min": w.duration_min, "enabled": bool(w.enabled),
            "active": is_active(w), "suppressed": _stats.get(w.id, 0), "created_by": w.created_by, "created_at": _iso(w.created_at)}


def list_windows() -> List[dict]:
    with SessionLocal() as db:
        names = {a.id: a.name or a.ip or str(a.id) for a in db.execute(select(Asset)).scalars().all()}
        rows = [_view(w, names) for w in db.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.id.desc())).scalars().all()]
    rows.sort(key=lambda r: (not r["active"], r["kind"] == "once" and r["ends_at"] is not None and r["ends_at"] < _iso(_now()), r["name"].lower()))
    return rows


def save(wid: Optional[int], body: dict, user: str) -> int:
    f = _clean(body)
    with SessionLocal() as db:
        w = db.get(MaintenanceWindow, wid) if wid else None
        if wid and w is None:
            raise LookupError("window not found")
        if w is None:
            w = MaintenanceWindow(created_by=user, **f)
            db.add(w)
        else:
            for k, v in f.items():
                setattr(w, k, v)
        db.commit()
        out = w.id
    invalidate()
    return out


def delete_window(wid: int) -> bool:
    with SessionLocal() as db:
        w = db.get(MaintenanceWindow, wid)
        if w is None:
            return False
        db.delete(w)
        db.commit()
    invalidate()
    return True


def quick(asset_ids: List[int], minutes: int, name: Optional[str], user: str, scope_all: bool = False) -> int:
    """Mutes the devices (or everything) for the next `minutes`."""
    minutes = max(5, min(int(minutes), 7 * 24 * 60))
    now = _now()
    return save(None, {"name": (name or "").strip() or f"Quick mute {now.strftime('%d.%m %H:%M')}", "kind": "once", "starts_at": now.isoformat(), "ends_at": (now + timedelta(minutes=minutes)).isoformat(),
                       "scope_all": scope_all, "asset_ids": asset_ids}, user)
