import asyncio
import json
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from services import linux_manage

router = APIRouter(prefix="/api/linux", tags=["linux"])


class ManagedIn(BaseModel):
    managed: bool


class SettingsIn(BaseModel):
    credential_id: int | None = None


class BulkUpgradeIn(BaseModel):
    ids: list[int]


class RunScriptIn(BaseModel):
    script: str
    use_sudo: bool = False
    reason: str


class RunScriptBulkIn(BaseModel):
    ids: list[int]
    script: str
    use_sudo: bool = False
    reason: str


@router.get("/hosts")
async def list_hosts():
    return {"hosts": linux_manage.list_hosts(), "enabled": linux_manage.MANAGE_ENABLED}


@router.post("/hosts/{host_id}/managed")
async def set_managed(host_id: int, payload: ManagedIn):
    return linux_manage.set_managed(host_id, payload.managed)


@router.post("/hosts/{host_id}/check")
async def check_updates(host_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.check_updates, host_id)
    return {"queued": True, "host_id": host_id}


@router.post("/hosts/{host_id}/upgrade")
async def upgrade_host(host_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.upgrade_host, host_id)
    return {"queued": True, "host_id": host_id}


@router.get("/hosts/{host_id}/status")
async def host_status(host_id: int):
    return linux_manage.get_job_status(host_id)


@router.post("/hosts/upgrade-bulk")
async def upgrade_bulk(payload: BulkUpgradeIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.upgrade_bulk, payload.ids)
    return {"queued": len(payload.ids), "ids": payload.ids}


@router.post("/hosts/{host_id}/run-script")
async def run_script(host_id: int, payload: RunScriptIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.run_script, host_id, payload.script, payload.use_sudo, payload.reason)
    return {"queued": True, "host_id": host_id}


@router.post("/hosts/run-script-bulk")
async def run_script_bulk(payload: RunScriptBulkIn, background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.run_script_bulk, payload.ids, payload.script, payload.use_sudo, payload.reason)
    return {"queued": len(payload.ids), "ids": payload.ids}


@router.post("/discover")
async def discover(background_tasks: BackgroundTasks):
    # Full network scan first, not just a re-read of the last one — see
    # full_network_scan_and_discover()'s docstring for why the plain
    # discover_linux_hosts() alone would silently miss a host that only
    # just started listening on port 22.
    background_tasks.add_task(linux_manage.full_network_scan_and_discover)
    return {"started": True}


@router.get("/discover-stream")
async def discover_stream():
    """Same scan as POST /discover, but as an SSE stream reporting live
    progress — added because the fire-and-forget POST gave zero visible
    feedback for however long the scan takes (confirmed: clicking "Skanuj
    sieć teraz" and seeing nothing happen for minutes). Event shape:
    {"type": "phase", "phase": ..., "total": ...} announcing a new stage
    ("probing", "rechecking", "credentials", "persisting", "package_audit",
    "findings", "linux_discovery", "linux_identify", "linux_refresh"), or
    {"type": "progress", "phase": ..., "completed": ..., "total": ...,
    "ip": ...} per host within a stage, or {"type": "done", ...} at the end."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def emit(event: dict):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def _run():
        try:
            result = await linux_manage.full_network_scan_and_discover(on_event=emit)
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
    return linux_manage.get_settings()


@router.put("/settings")
async def set_settings(payload: SettingsIn):
    return linux_manage.set_settings(payload.credential_id)
