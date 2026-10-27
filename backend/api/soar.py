from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import soar, soc

router = APIRouter(prefix="/api/soar", tags=["soar"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    central_approval: Optional[bool] = None


class ProposeBody(BaseModel):
    kind: str = "block_ip"                      # block_ip | install_rule
    target: Optional[str] = None
    device_ids: List[int] = []
    ttl_min: int = soar.DEFAULT_TTL
    reason: str = ""
    alert_id: Optional[int] = None
    allow_internal: bool = False


class DecideBody(BaseModel):
    approve: bool


class UnblockBody(BaseModel):
    target: str


def _who(user: dict) -> str:
    return str(user.get("username") or "?")


def _admin(user: dict) -> None:
    if user.get("role") not in (None, "admin"):
        raise HTTPException(403, "only an administrator can approve response actions")


@router.get("")
def overview():
    """The settings, the proposals waiting, the blocks in force, the history and the routers an address can be blocked on."""
    return soar.overview()


@router.put("/settings")
def set_settings(body: SettingsBody, user: dict = Depends(require_login)):
    _admin(user)
    return soar.update_settings(body.model_dump(exclude_unset=True))


@router.get("/candidates/{alert_id}")
def alert_candidates(alert_id: int):
    """The addresses of this alert that may be blocked."""
    alert = soc.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    return {"addresses": soar.candidates(alert)}


@router.post("/propose")
def propose(body: ProposeBody, user: dict = Depends(require_login)):
    try:
        return {"id": soar.propose(body.kind, body.target, body.device_ids, ttl_min=body.ttl_min, reason=body.reason, alert_id=body.alert_id, user=_who(user),
                                   allow_internal=body.allow_internal)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{action_id}/decide")
async def decide(action_id: int, body: DecideBody, user: dict = Depends(require_login)):
    _admin(user)
    try:
        return await soar.decide(action_id, body.approve, _who(user))
    except LookupError:
        raise HTTPException(404, "action not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/unblock")
async def unblock(body: UnblockBody, user: dict = Depends(require_login)):
    _admin(user)
    try:
        soar.validate_target(body.target, allow_internal=True)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return await soar.unblock(body.target.strip(), _who(user))
