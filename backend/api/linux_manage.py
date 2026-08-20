from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from services import linux_manage

router = APIRouter(prefix="/api/linux", tags=["linux"])


class ManagedIn(BaseModel):
    managed: bool


class SettingsIn(BaseModel):
    credential_id: int | None = None


class BulkUpgradeIn(BaseModel):
    ids: list[int]


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


@router.post("/discover")
async def discover(background_tasks: BackgroundTasks):
    background_tasks.add_task(linux_manage.discover_linux_hosts)
    return {"started": True}


@router.get("/settings")
async def get_settings():
    return linux_manage.get_settings()


@router.put("/settings")
async def set_settings(payload: SettingsIn):
    return linux_manage.set_settings(payload.credential_id)
