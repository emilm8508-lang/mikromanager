"""
Grouped, scheduled RouterOS upgrades — the "Aktualizacje" tab.

A group is an ordered list of Mikrotik devices plus the rules for upgrading
them: which update channel to pin them to, when to run (manual / every week /
once), whether to stop or carry on when a device fails, and whether to back
each one up first. A run is an ordinary fleet_actions upgrade run (strictly
one device at a time, in the group's order, devices already on the latest
version are skipped without a reboot), tagged with the group.

The scheduler wakes every minute. Two deliberate rules protect production:
  - a scheduled time the agent MISSED (it was down) is only honoured within a
    grace window; later than that the occurrence is skipped and the next one
    is scheduled — a router must not start upgrading at an arbitrary hour just
    because the agent happened to come back up;
  - a group that already has a run in flight is never started twice.
Times are the agent's local time.
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, FleetUpgradeGroup, FleetActionRun
from services import fleet_actions

TICK_SEC = 60
GRACE = timedelta(minutes=60)
SCHEDULE_KINDS = ("manual", "weekly", "once")

_task: Optional[asyncio.Task] = None


# ── Pure schedule logic ──────────────────────────────────────────────────────

def next_occurrence(kind: str, weekday: Optional[int], hour: Optional[int], minute: Optional[int],
                    once_at: Optional[datetime], after: datetime) -> Optional[datetime]:
    """First scheduled moment strictly after `after`, or None (manual, or a
    one-off that is already in the past)."""
    if kind == "weekly":
        cand = after.replace(hour=hour or 0, minute=minute or 0, second=0, microsecond=0)
        cand += timedelta(days=(weekday - cand.weekday()) % 7)
        return cand if cand > after else cand + timedelta(days=7)
    if kind == "once":
        return once_at if once_at and once_at > after else None
    return None


def _validated(p: dict) -> dict:
    out = {}
    name = (p.get("name") or "").strip()
    if not name:
        raise ValueError("name required")
    out["name"] = name
    ids = [int(i) for i in (p.get("device_ids") or [])]
    if not ids:
        raise ValueError("pick at least one device")
    if len(set(ids)) != len(ids):
        raise ValueError("a device can appear only once")
    if len(ids) > fleet_actions.MAX_DEVICES:
        raise ValueError(f"at most {fleet_actions.MAX_DEVICES} devices per group")
    out["device_ids"] = ids
    channel = p.get("channel") or None
    if channel is not None and channel not in fleet_actions.UPDATE_CHANNELS:
        raise ValueError("unknown update channel")
    out["channel"] = channel
    kind = p.get("schedule_kind", "manual")
    if kind not in SCHEDULE_KINDS:
        raise ValueError("unknown schedule kind")
    out["schedule_kind"] = kind
    out["weekday"] = out["hour"] = out["once_at"] = None
    out["minute"] = 0
    if kind == "weekly":
        wd, hh, mm = p.get("weekday"), p.get("hour"), p.get("minute", 0)
        if not (isinstance(wd, int) and 0 <= wd <= 6 and isinstance(hh, int) and 0 <= hh <= 23 and isinstance(mm, int) and 0 <= mm <= 59):
            raise ValueError("weekly schedule needs weekday 0-6, hour 0-23, minute 0-59")
        out["weekday"], out["hour"], out["minute"] = wd, hh, mm
    elif kind == "once":
        try:
            at = datetime.fromisoformat(str(p.get("once_at")))
        except ValueError:
            raise ValueError("one-off schedule needs a valid date and time")
        if at <= datetime.now():
            raise ValueError("the scheduled time is in the past")
        out["once_at"] = at
    for key in ("enabled", "stop_on_failure", "backup"):
        out[key] = bool(p.get(key, True))
    return out


def _recompute_next(g: FleetUpgradeGroup, after: datetime) -> None:
    g.next_run_at = next_occurrence(g.schedule_kind, g.weekday, g.hour, g.minute, g.once_at, after) if g.enabled else None


# ── CRUD ─────────────────────────────────────────────────────────────────────

def _run_info(db, run_id: Optional[int]) -> Optional[dict]:
    if not run_id:
        return None
    run = db.get(FleetActionRun, run_id)
    if not run:
        return None
    d = fleet_actions._to_dict(run, False)
    return {"id": d["id"], "status": d["status"], "counts": d["counts"], "devices": d["devices"],
            "created_at": d["created_at"], "finished_at": d["finished_at"]}


def _to_dict(db, g: FleetUpgradeGroup) -> dict:
    iso = lambda d: d.isoformat() if d else None
    return {
        "id": g.id, "name": g.name, "device_ids": json.loads(g.device_ids or "[]"), "channel": g.channel,
        "schedule_kind": g.schedule_kind, "weekday": g.weekday, "hour": g.hour, "minute": g.minute or 0,
        "once_at": iso(g.once_at), "enabled": g.enabled, "stop_on_failure": g.stop_on_failure, "backup": g.backup,
        "next_run_at": iso(g.next_run_at), "last_run_at": iso(g.last_run_at), "last_note": g.last_note,
        "last_run": _run_info(db, g.last_run_id),
    }


def list_groups() -> List[dict]:
    with SessionLocal() as db:
        return [_to_dict(db, g) for g in db.execute(select(FleetUpgradeGroup).order_by(FleetUpgradeGroup.name)).scalars().all()]


def _check_devices(db, ids: List[int]) -> None:
    found = {d.id for d in db.execute(select(Device).where(Device.id.in_(ids))).scalars().all()}
    missing = [i for i in ids if i not in found]
    if missing:
        raise ValueError(f"unknown device ids: {missing}")


def create_group(p: dict) -> dict:
    v = _validated(p)
    with SessionLocal() as db:
        _check_devices(db, v["device_ids"])
        if db.execute(select(FleetUpgradeGroup).where(FleetUpgradeGroup.name == v["name"])).scalar_one_or_none():
            raise ValueError("a group with this name already exists")
        g = FleetUpgradeGroup(**{**v, "device_ids": json.dumps(v["device_ids"])})
        _recompute_next(g, datetime.now())
        db.add(g)
        db.commit()
        return _to_dict(db, g)


def update_group(group_id: int, p: dict) -> dict:
    v = _validated(p)
    with SessionLocal() as db:
        g = db.get(FleetUpgradeGroup, group_id)
        if not g:
            raise LookupError("group not found")
        _check_devices(db, v["device_ids"])
        clash = db.execute(select(FleetUpgradeGroup).where(FleetUpgradeGroup.name == v["name"])).scalar_one_or_none()
        if clash and clash.id != group_id:
            raise ValueError("a group with this name already exists")
        for k, val in v.items():
            setattr(g, k, json.dumps(val) if k == "device_ids" else val)
        g.last_note = None
        _recompute_next(g, datetime.now())
        db.commit()
        return _to_dict(db, g)


def delete_group(group_id: int) -> dict:
    with SessionLocal() as db:
        g = db.get(FleetUpgradeGroup, group_id)
        if not g:
            raise LookupError("group not found")
        db.delete(g)
        db.commit()
    return {"ok": True}


def _group_running(group_id: int) -> bool:
    with SessionLocal() as db:
        for run in db.execute(select(FleetActionRun).where(FleetActionRun.action == "upgrade",
                                                           FleetActionRun.status == "running")).scalars().all():
            if run.id in fleet_actions._active and (json.loads(run.options or "{}").get("group_id") == group_id):
                return True
    return False


def run_group(group_id: int, created_by: str, reason: Optional[str] = None, trigger: str = "manual") -> int:
    """Starts the group's upgrade run now (manual button or the scheduler)."""
    with SessionLocal() as db:
        g = db.get(FleetUpgradeGroup, group_id)
        if not g:
            raise LookupError("group not found")
        ids, channel, stop, backup, name = json.loads(g.device_ids or "[]"), g.channel, g.stop_on_failure, g.backup, g.name
    if _group_running(group_id):
        raise ValueError("this group already has a run in progress")
    run_id = fleet_actions.start_run(
        "upgrade", ids, (reason or "").strip() or f"Grupa „{name}”" + (" (harmonogram)" if trigger == "schedule" else " (ręcznie)"),
        None, backup, created_by, channel=channel, stop_on_failure=stop, group_id=group_id, trigger=trigger)
    with SessionLocal() as db:
        g = db.get(FleetUpgradeGroup, group_id)
        if g:
            g.last_run_at, g.last_run_id, g.last_note = datetime.now(), run_id, None
            db.commit()
    return run_id


# ── Scheduler ────────────────────────────────────────────────────────────────

def tick(now: Optional[datetime] = None) -> List[int]:
    """One scheduler pass; returns the ids of groups started. Sync and
    side-effect-explicit so it can be tested without waiting for a minute."""
    now = now or datetime.now()
    started = []
    with SessionLocal() as db:
        due = [g.id for g in db.execute(select(FleetUpgradeGroup).where(
            FleetUpgradeGroup.enabled.is_(True), FleetUpgradeGroup.schedule_kind != "manual")).scalars().all()]
    for gid in due:
        with SessionLocal() as db:
            g = db.get(FleetUpgradeGroup, gid)
            if g.next_run_at is None:
                _recompute_next(g, now)
                db.commit()
                continue
            if g.next_run_at > now:
                continue
            scheduled_for, late = g.next_run_at, now - g.next_run_at
            kind = g.schedule_kind
            # roll the schedule forward first, so a failure below can never make it fire again and again
            if kind == "once":
                g.next_run_at, g.enabled = None, False
            else:
                _recompute_next(g, now)
            if late > GRACE:
                g.last_note = f"missed:{scheduled_for.isoformat()}"
                db.commit()
                continue
            db.commit()
        try:
            run_group(gid, "harmonogram", trigger="schedule")
            started.append(gid)
        except Exception as e:
            print(f"[fleet_schedule] could not start group {gid}: {e}")
            with SessionLocal() as db:
                g = db.get(FleetUpgradeGroup, gid)
                if g:
                    g.last_note = f"error:{e}"[:200]
                    db.commit()
    return started


async def _loop():
    await asyncio.sleep(30)
    while True:
        try:
            tick()
        except Exception as e:
            print(f"[fleet_schedule] tick error: {e}")
        await asyncio.sleep(TICK_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None


def public_list() -> List[dict]:
    """Redacted for Central: schedule and last result per group, no device ids."""
    out = []
    for g in list_groups():
        lr = g["last_run"]
        out.append({"name": g["name"], "devices": len(g["device_ids"]), "channel": g["channel"], "enabled": g["enabled"],
                    "schedule_kind": g["schedule_kind"], "weekday": g["weekday"], "hour": g["hour"], "minute": g["minute"],
                    "once_at": g["once_at"], "next_run_at": g["next_run_at"], "last_run_at": g["last_run_at"],
                    "last_status": lr["status"] if lr else None, "last_counts": lr["counts"] if lr else None,
                    "last_note": (g["last_note"] or "").split(":")[0] or None})
    return out
