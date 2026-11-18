from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import host_processes

router = APIRouter(prefix="/api/host-processes", tags=["host-processes"])


class ServiceAction(BaseModel):
    name: str
    action: str
    reason: str


class KillBody(BaseModel):
    pid: int
    name: str
    reason: str
    force: bool = False


def _who(user: dict) -> str:
    return str(user.get("username") or user.get("source") or "?")


@router.get("/{platform}/{host_id}")
async def processes(platform: str, host_id: int):
    """The processes using the most CPU and memory on the host now (read on demand)."""
    try:
        return await host_processes.processes(platform, host_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/{platform}/{host_id}/history")
def history(platform: str, host_id: int, limit: int = 30):
    return {"actions": host_processes.history(platform, host_id, limit)}


@router.post("/{platform}/{host_id}/service")
async def service_action(platform: str, host_id: int, body: ServiceAction, user: dict = Depends(require_login)):
    try:
        return await host_processes.service_action(platform, host_id, body.name, body.action, body.reason, _who(user))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{platform}/{host_id}/kill")
async def kill(platform: str, host_id: int, body: KillBody, user: dict = Depends(require_login)):
    try:
        return await host_processes.kill_process(platform, host_id, body.pid, body.name, body.reason, _who(user), body.force)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
