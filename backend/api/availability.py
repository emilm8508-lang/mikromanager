from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import availability

router = APIRouter(prefix="/api/availability", tags=["availability"])


class MonitorBody(BaseModel):
    mode: Optional[int] = None        # 1 on, 0 off, null = automatic


@router.get("")
def overview():
    """Every watched asset: state, since when, uptime of 24 h / 7 d / 30 d, and the device that is the cause when it is unreachable."""
    return availability.overview()


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await availability.run_cycle()


@router.get("/{asset_id}")
def outages(asset_id: int, days: int = 30):
    """The outages of one asset (when, how long, what caused them) and what is unreachable behind it now."""
    return {**availability.outages(asset_id, days), "affected": availability.affected_by(asset_id)}


@router.put("/{asset_id}/monitor")
def set_monitor(asset_id: int, body: MonitorBody, user: dict = Depends(require_login)):
    if body.mode not in (None, 0, 1):
        raise HTTPException(400, "mode must be 1, 0 or null")
    if not availability.set_monitor(asset_id, body.mode):
        raise HTTPException(404, "asset not found")
    return {"ok": True}
