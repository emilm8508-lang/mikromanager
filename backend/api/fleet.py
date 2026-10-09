from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from services import fleet, fleet_actions

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
