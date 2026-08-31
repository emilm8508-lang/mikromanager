from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from services import dell_monitor

router = APIRouter(prefix="/api/dell", tags=["dell"])


class ServerIn(BaseModel):
    name: str | None = None
    idrac_ip: str | None = None
    idrac_port: int = 443
    windows_host_id: int | None = None
    credential_id: int | None = None


class ServerUpdateIn(BaseModel):
    name: str | None = None
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
        payload.windows_host_id, payload.credential_id,
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
