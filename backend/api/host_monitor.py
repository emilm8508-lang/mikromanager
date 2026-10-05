import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from services import host_monitor, host_report

router = APIRouter(prefix="/api/hostmon", tags=["hostmon"])


class HostIn(BaseModel):
    name: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    note: Optional[str] = None
    probe_port: Optional[int] = None   # None = ICMP ping, otherwise TCP connect
    enabled: bool = True


class ExportIn(BaseModel):
    format: str = "docx"                # docx | csv | json
    hours: int = 72
    host_ids: Optional[List[int]] = None  # None/empty = every monitored host
    labels: Dict[str, str] = {}         # the UI's hostmon.* texts, so the file is in the user's language


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


@router.post("/export")
async def export_report(body: ExportIn):
    if body.format not in ("docx", "csv", "json"):
        raise HTTPException(400, "format must be docx, csv or json")
    labels = host_report.clean_labels(body.labels)
    data = host_report.collect(body.host_ids, max(1, min(body.hours, 720)))
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    if body.format == "csv":
        content, media = "\ufeff" + host_report.render_csv(data, labels), "text/csv; charset=utf-8"   # BOM: Excel reads UTF-8 correctly
    elif body.format == "json":
        content, media = json.dumps(data, ensure_ascii=False, indent=2), "application/json"
    else:
        content, media = host_report.render_docx(data, labels), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return Response(content=content, media_type=media,
                    headers={"Content-Disposition": f"attachment; filename=host-monitoring-{stamp}.{body.format}"})
