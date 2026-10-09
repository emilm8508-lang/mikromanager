from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from services import hyperv_manage, hyperv_actions

router = APIRouter(prefix="/api/hyperv", tags=["hyperv"])


@router.get("/overview")
async def overview():
    """Everything the dashboard shows, from the database only."""
    data = hyperv_manage.overview()
    data["actions_enabled"] = hyperv_actions.enabled()
    return data


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


@router.post("/refresh")
async def refresh_all(background_tasks: BackgroundTasks):
    background_tasks.add_task(hyperv_manage.refresh_managed_hyperv_hosts, True)
    return {"started": True}


@router.get("/vms/{vm_id}")
async def get_vm(vm_id: int):
    vm = hyperv_manage.get_vm(vm_id)
    if not vm:
        raise HTTPException(404, "VM not found")
    return vm


@router.get("/history")
async def history(kind: str, id: int, hours: int = 24):
    if kind not in ("host", "vm"):
        raise HTTPException(400, "kind must be host or vm")
    return {"points": hyperv_manage.history(kind, id, hours=hours)}


# ── VM actions (write; gated, see services/hyperv_actions.py) ────────────────

class VmActionIn(BaseModel):
    action: str                           # start | shutdown | poweroff | restart | checkpoint
    reason: str
    snapshot_name: Optional[str] = None   # checkpoint only


@router.post("/vms/{vm_id}/actions")
async def vm_action(vm_id: int, body: VmActionIn, request: Request):
    session = getattr(request.state, "session", None) or {}
    try:
        action_id = hyperv_actions.start_action(vm_id, body.action, body.reason, session.get("username") or "?", body.snapshot_name)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"action_id": action_id}


@router.get("/actions")
async def list_actions(limit: int = 50, vm_name: Optional[str] = None):
    return {"actions": hyperv_actions.list_actions(limit, vm_name), "enabled": hyperv_actions.enabled()}


@router.get("/actions/{action_id}")
async def get_action(action_id: int):
    try:
        return hyperv_actions.get_action(action_id)
    except LookupError as e:
        raise HTTPException(404, str(e))
