import asyncio
import json

from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from services import dell_monitor

router = APIRouter(prefix="/api/dell", tags=["dell"])


class ServerIn(BaseModel):
    name: str | None = None
    vendor: str | None = None  # "dell" | "hp" | "fujitsu" | "lenovo" | None (-> "dell")
    idrac_ip: str | None = None
    idrac_port: int = 443
    windows_host_id: int | None = None
    credential_id: int | None = None


class ServerUpdateIn(BaseModel):
    name: str | None = None
    vendor: str | None = None
    idrac_ip: str | None = None
    idrac_port: int | None = None
    windows_host_id: int | None = None
    credential_id: int | None = None


@router.get("/servers")
async def list_servers():
    return {"servers": dell_monitor.list_servers()}


@router.post("/servers")
async def add_server(payload: ServerIn):
    return dell_monitor.add_server(
        payload.name, payload.idrac_ip, payload.idrac_port,
        payload.windows_host_id, payload.credential_id, payload.vendor,
    )


@router.put("/servers/{server_id}")
async def update_server(server_id: int, payload: ServerUpdateIn):
    fields = payload.model_dump(exclude_none=True)
    return dell_monitor.update_server(server_id, **fields)


@router.delete("/servers/{server_id}")
async def delete_server(server_id: int):
    return dell_monitor.delete_server(server_id)


@router.post("/servers/{server_id}/check")
async def check_server(server_id: int, background_tasks: BackgroundTasks):
    background_tasks.add_task(dell_monitor.check_server, server_id)
    return {"queued": True, "server_id": server_id}


@router.get("/servers/{server_id}/sel")
async def sel_entries(server_id: int, limit: int = 50):
    return {"entries": dell_monitor.list_sel_entries(server_id, limit)}


@router.post("/discover")
async def discover(background_tasks: BackgroundTasks):
    # Mirrors /api/linux/discover, /api/windows/discover — one button
    # covering both access paths (network Redfish + WinRM-local), per the
    # user's explicit ask that this be discoverable the same way as the
    # other scanners ("miało się to skanowac z centrali samo").
    background_tasks.add_task(dell_monitor.discover_servers)
    return {"started": True}


@router.get("/discover-stream")
async def discover_stream():
    """Same scan as POST /discover, but as an SSE stream reporting live
    progress — mirrors /api/linux/discover-stream and
    /api/windows/discover-stream exactly."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def emit(event: dict):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def _run():
        try:
            result = await dell_monitor.discover_servers(on_event=emit)
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
