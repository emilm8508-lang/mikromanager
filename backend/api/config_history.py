from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from api.auth import require_login
from services import config_history

router = APIRouter(prefix="/api/config-history", tags=["config-history"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    interval_hours: Optional[float] = None


@router.get("")
def overview():
    """The MikroTik devices with the state of their configuration history: versions, last check, last change and what it touched."""
    return config_history.overview()


@router.put("/settings")
def settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return config_history.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/run")
async def run_all(user: dict = Depends(require_login)):
    return await config_history.run_cycle(force=True)


@router.get("/{device_id}")
def versions(device_id: int):
    return {"versions": config_history.versions(device_id)}


@router.post("/{device_id}/snapshot")
async def snapshot(device_id: int, user: dict = Depends(require_login)):
    r = await config_history.snapshot_device(device_id)
    if "error" in r:
        raise HTTPException(502, r["error"])
    return r


@router.get("/{device_id}/diff")
def diff(device_id: int, a: int, b: int):
    d = config_history.compare(device_id, a, b)
    if d is None:
        raise HTTPException(404, "version not found")
    return d


@router.get("/{device_id}/version/{snap_id}", response_class=PlainTextResponse)
def version_text(device_id: int, snap_id: int):
    t = config_history.get_text(device_id, snap_id)
    if t is None:
        raise HTTPException(404, "version not found")
    return t


@router.delete("/{device_id}")
def delete(device_id: int, user: dict = Depends(require_login)):
    return {"deleted": config_history.delete_history(device_id)}
