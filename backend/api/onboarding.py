from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import onboarding

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


class AssignBody(BaseModel):
    device_ids: List[int]


def _admin(user: dict) -> None:
    # a live test logs in with stored credentials, and an assignment changes which one a device uses
    if user.get("role") not in (None, "admin"):
        raise HTTPException(403, "this requires the admin role")


@router.get("")
def overview():
    """Per device what is known without touching the network, the scan ranges and the networks the agent's computer is in that no range covers."""
    return onboarding.overview()


@router.post("/test/{device_id}")
async def test_device(device_id: int, user: dict = Depends(require_login)):
    """Live test of one device with its own credential and, when that does not give full access, the other stored ones."""
    _admin(user)
    r = await onboarding.diagnose(device_id)
    if r is None:
        raise HTTPException(404, "device not found")
    return r


@router.post("/assign")
async def assign(body: AssignBody, user: dict = Depends(require_login)):
    """Tests the devices and assigns the best working credential to the ones that have none or whose own gives less."""
    _admin(user)
    if not body.device_ids or len(body.device_ids) > 100:
        raise HTTPException(400, "choose between 1 and 100 devices")
    return {"results": await onboarding.assign_best(body.device_ids)}
