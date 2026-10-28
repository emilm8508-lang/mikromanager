from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import tls_scan

router = APIRouter(prefix="/api/tls", tags=["tls"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    warn_days: Optional[int] = None
    crit_days: Optional[int] = None


class TargetBody(BaseModel):
    ip: str
    port: int


@router.get("")
def overview():
    """The certificates and protocols of the TLS services, soonest expiry first."""
    return tls_scan.overview()


@router.put("/settings")
def set_settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return tls_scan.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/run")
async def run(user: dict = Depends(require_login)):
    r = await tls_scan.run_all()
    if not r.get("ok"):
        raise HTTPException(409, r.get("error") or "failed")
    return r


@router.post("/targets")
def add_target(body: TargetBody, user: dict = Depends(require_login)):
    try:
        return {"id": tls_scan.add_target(body.ip, body.port)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/targets/{check_id}")
def remove_target(check_id: int, user: dict = Depends(require_login)):
    if not tls_scan.remove_target(check_id):
        raise HTTPException(404, "target not found")
    return {"ok": True}
