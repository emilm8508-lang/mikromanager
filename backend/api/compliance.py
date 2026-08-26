from fastapi import APIRouter, BackgroundTasks, HTTPException

from services import compliance

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

_RUNNERS = {
    "linux": compliance.run_linux_checks,
    "windows": compliance.run_windows_checks,
    "mikrotik": compliance.run_mikrotik_checks,
}


@router.get("/results")
async def get_results(target_type: str | None = None, target_id: int | None = None):
    return compliance.list_results(target_type, target_id)


@router.get("/summary")
async def get_summary():
    return compliance.summary()


@router.post("/run/{target_type}/{target_id}")
async def run_checks(target_type: str, target_id: int, background_tasks: BackgroundTasks):
    runner = _RUNNERS.get(target_type)
    if not runner:
        raise HTTPException(400, f"unknown target_type: {target_type}")
    background_tasks.add_task(runner, target_id)
    return {"queued": True, "target_type": target_type, "target_id": target_id}
