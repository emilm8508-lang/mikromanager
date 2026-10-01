from fastapi import APIRouter

from services import hyperv_manage

router = APIRouter(prefix="/api/hyperv", tags=["hyperv"])


@router.get("/hosts")
async def list_hosts():
    return {"hosts": hyperv_manage.list_hosts()}


@router.get("/hosts/{hyperv_host_id}/vms")
async def list_vms(hyperv_host_id: int):
    return {"vms": hyperv_manage.list_vms(hyperv_host_id)}


@router.post("/hosts/{host_id}/refresh")
async def refresh_host(host_id: int):
    """host_id here is the owning WindowsHost.id (matches windows_manage's
    own id space, since that's what the UI already has at hand — the
    HypervHost row, if any, is found/created inside check_hyperv_host())."""
    return await hyperv_manage.check_hyperv_host(host_id)
