from fastapi import APIRouter, BackgroundTasks

from services import fleet

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
