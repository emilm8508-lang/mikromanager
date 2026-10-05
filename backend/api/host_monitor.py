import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import host_monitor

router = APIRouter(prefix="/api/hostmon", tags=["hostmon"])


class HostIn(BaseModel):
    name: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    note: Optional[str] = None
    probe_port: Optional[int] = None   # None = ICMP ping, otherwise TCP connect
    enabled: bool = True


def _bad(e: Exception) -> HTTPException:
    return HTTPException(404 if isinstance(e, LookupError) else 400, str(e))


@router.get("/search")
async def search(q: str = "", refresh: bool = False):
    return await host_monitor.search_hosts(q, refresh=refresh)


@router.get("/hosts")
async def list_hosts():
    return {"hosts": host_monitor.list_hosts()}


@router.post("/hosts")
async def create_host(body: HostIn):
    try:
        res = host_monitor.create_host(body.name, body.ip, body.mac, body.note, body.probe_port)
    except ValueError as e:
        raise _bad(e)
    # First collection right away (probe + backfill from the devices' log
    # buffers) instead of waiting for the next cycle — in the background so
    # adding a host stays instant.
    asyncio.create_task(host_monitor.run_cycle(force_collect=True, only_host_id=res["id"]))
    return res


@router.put("/hosts/{host_id}")
async def update_host(host_id: int, body: HostIn):
    try:
        return host_monitor.update_host(host_id, body.name, body.ip, body.mac, body.note,
                                        body.probe_port, body.enabled)
    except (ValueError, LookupError) as e:
        raise _bad(e)


@router.delete("/hosts/{host_id}")
async def delete_host(host_id: int):
    try:
        return host_monitor.delete_host(host_id)
    except LookupError as e:
        raise _bad(e)


@router.post("/hosts/{host_id}/refresh")
async def refresh_host(host_id: int):
    await host_monitor.run_cycle(force_collect=True, only_host_id=host_id)
    return {"ok": True}


@router.get("/hosts/{host_id}/report")
async def report(host_id: int, hours: int = 72):
    try:
        return host_monitor.get_report(host_id, hours)
    except LookupError as e:
        raise _bad(e)
