from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import host_logs

router = APIRouter(prefix="/api/host-logs", tags=["host-logs"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    interval_min: Optional[int] = None


@router.get("")
def status():
    """The managed Windows / Linux hosts whose security events are read: when they were last read, the last error, how many events were seen."""
    return host_logs.status()


@router.put("/settings")
def settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return host_logs.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await host_logs.run_cycle()
