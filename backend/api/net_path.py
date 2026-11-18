from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.auth import require_login
from services import net_path

router = APIRouter(prefix="/api/net-path", tags=["net-path"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None


@router.get("")
def overview():
    """Per link-quality target of your own: the last trace hop by hop (latency, jitter, loss), the hop where a problem starts, the path changes of 24 h."""
    return net_path.overview()


@router.get("/history")
def history(ip: str, limit: int = 50):
    return {"traces": net_path.history(ip, limit)}


@router.put("/settings")
def set_settings(body: SettingsBody, user: dict = Depends(require_login)):
    return net_path.save_settings(body.model_dump(exclude_none=True))


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await net_path.run_cycle()
