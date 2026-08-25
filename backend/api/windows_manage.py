import asyncio
import json
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from services import windows_manage

router = APIRouter(prefix="/api/windows", tags=["windows"])


class ManagedIn(BaseModel):
    managed: bool


class SettingsIn(BaseModel):
    credential_id: int | None = None


class ReasonIn(BaseModel):
    reason: str


class BulkUpgradeIn(BaseModel):
    ids: list[int]
    reason: str


@router.get("/hosts")
async def list_hosts():
    return {"hosts": windows_manage.list_hosts(), "enabled": windows_manage.MANAGE_ENABLED}


@router.post("/hosts/{host_id}/managed")
async def set_managed(host_id: int, payload: ManagedIn):
    return windows_manage.set_managed(host_id, payload.managed)


@router.post("/hosts/{host_id}/check")
async def check_updates(host_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(windows_manage.check_updates, host_id)
    return {"queued": True, "host_id": host_id}


@router.post("/hosts/{host_id}/upgrade")
async def upgrade_host(host_id: int, payload: ReasonIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(windows_manage.upgrade_host, host_id, payload.reason)
    return {"queued": True, "host_id": host_id}


@router.post("/hosts/{host_id}/restart")
async def restart_host(host_id: int, payload: ReasonIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(windows_manage.restart_host, host_id, payload.reason)
    return {"queued": True, "host_id": host_id}


@router.get("/hosts/{host_id}/status")
async def host_status(host_id: int):
    return windows_manage.get_job_status(host_id)


@router.post("/hosts/upgrade-bulk")
async def upgrade_bulk(payload: BulkUpgradeIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(windows_manage.upgrade_bulk, payload.ids, payload.reason)
    return {"queued": len(payload.ids), "ids": payload.ids}


@router.post("/discover")
async def discover(background_tasks: BackgroundTasks):
    background_tasks.add_task(windows_manage.full_network_scan_and_discover)
    return {"started": True}


@router.get("/discover-stream")
async def discover_stream():
    """Same scan as POST /discover, but as an SSE stream reporting live
    progress — mirrors /api/linux/discover-stream exactly."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def emit(event: dict):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def _run():
        try:
            result = await windows_manage.full_network_scan_and_discover(on_event=emit)
            emit({"type": "result", **result})
        except Exception as e:
            emit({"type": "error", "message": str(e)})
        finally:
            queue.put_nowait(None)  # sentinel = end stream

    async def event_generator():
        task = asyncio.create_task(_run())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/settings")
async def get_settings():
    return windows_manage.get_settings()


@router.put("/settings")
async def set_settings(payload: SettingsIn):
    return windows_manage.set_settings(payload.credential_id)
