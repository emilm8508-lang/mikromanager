from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import net_quality

router = APIRouter(prefix="/api/net-quality", tags=["net-quality"])


class Target(BaseModel):
    name: Optional[str] = None
    ip: str


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    auto: Optional[bool] = None
    count: Optional[int] = None
    targets: Optional[List[Target]] = None
    limits: Optional[dict] = None


@router.get("")
def overview():
    """Latency, jitter and packet loss of every target: the last measurement and the last 24 hours; and the settings."""
    return net_quality.overview()


@router.put("/settings")
def set_settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return net_quality.save_settings(body.model_dump(exclude_none=True))
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await net_quality.run_cycle()
