from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from services import fleet, fleet_actions, fleet_schedule

router = APIRouter(prefix="/api/fleet", tags=["fleet"])


@router.get("/overview")
async def overview():
    """Everything the Mikrotik tab shows, from the database only. If some
    paired device has never been collected yet (fresh install/upgrade) one
    background pass is started so the next refresh has the full picture."""
    data = fleet.build_overview()
    if data["never_collected"]:
        fleet.maybe_refresh_in_background()
    return data


@router.post("/refresh")
async def refresh(background_tasks: BackgroundTasks):
    background_tasks.add_task(fleet.refresh_all_devices)
    return {"started": True}


# ── Bulk actions ─────────────────────────────────────────────────────────────

class RunActionIn(BaseModel):
    action: str                       # script | reboot | upgrade
    device_ids: List[int]
    reason: str
    script: Optional[str] = None
    backup: bool = True               # upgrade only: back the device up first


@router.post("/actions/run")
async def run_action(body: RunActionIn, request: Request):
    session = getattr(request.state, "session", None) or {}
    try:
        run_id = fleet_actions.start_run(body.action, body.device_ids, body.reason, body.script,
                                         body.backup, session.get("username") or "?")
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"run_id": run_id}


@router.get("/actions/runs")
async def list_runs(limit: int = 30):
    return {"runs": fleet_actions.list_runs(limit), "enabled": fleet_actions.ENABLED}


@router.get("/actions/runs/{run_id}")
async def get_run(run_id: int):
    try:
        return fleet_actions.get_run(run_id)
    except LookupError as e:
        raise HTTPException(404, str(e))

# ── Upgrade groups ───────────────────────────────────────────────────────────

class GroupIn(BaseModel):
    name: str
    device_ids: List[int]                 # the order is the upgrade order
    channel: Optional[str] = None         # stable | long-term | testing | development; None = leave as is
    schedule_kind: str = "manual"         # manual | weekly | once
    weekday: Optional[int] = None         # 0=Monday .. 6=Sunday
    hour: Optional[int] = None
    minute: int = 0
    once_at: Optional[str] = None         # ISO local datetime
    enabled: bool = True
    stop_on_failure: bool = True
    backup: bool = True


class RunGroupIn(BaseModel):
    reason: Optional[str] = None


@router.get("/groups")
async def list_groups():
    return {"groups": fleet_schedule.list_groups()}


@router.post("/groups")
async def create_group(body: GroupIn):
    try:
        return fleet_schedule.create_group(body.model_dump())
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/groups/{group_id}")
async def update_group(group_id: int, body: GroupIn):
    try:
        return fleet_schedule.update_group(group_id, body.model_dump())
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/groups/{group_id}")
async def delete_group(group_id: int):
    try:
        return fleet_schedule.delete_group(group_id)
    except LookupError as e:
        raise HTTPException(404, str(e))


@router.post("/groups/{group_id}/run")
async def run_group(group_id: int, request: Request, body: Optional[RunGroupIn] = None):
    session = getattr(request.state, "session", None) or {}
    try:
        run_id = fleet_schedule.run_group(group_id, session.get("username") or "?", reason=(body.reason if body else None))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"run_id": run_id}
