from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import maintenance, escalation

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])


class WindowBody(BaseModel):
    name: str
    kind: str                                   # once | weekly
    starts_at: Optional[str] = None             # once: ISO time, UTC
    ends_at: Optional[str] = None
    days: Optional[List[int]] = None            # weekly: Monday = 0, agent local time
    start_time: Optional[str] = None            # weekly: HH:MM
    duration_min: Optional[int] = None
    scope_all: bool = False
    asset_ids: List[int] = []
    enabled: bool = True


class QuickBody(BaseModel):
    asset_ids: List[int] = []
    minutes: int = 120
    name: Optional[str] = None
    scope_all: bool = False


class EscalationBody(BaseModel):
    enabled: Optional[bool] = None
    levels: Optional[Dict[str, List[int]]] = None


@router.get("")
def overview():
    """The maintenance windows (active ones first, with how many events each muted) and the escalation settings."""
    return {"windows": maintenance.list_windows(), "escalation": escalation.settings()}


@router.post("")
def create(body: WindowBody, user: dict = Depends(require_login)):
    try:
        return {"id": maintenance.save(None, body.model_dump(), str(user.get("username") or "?"))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/escalation")
def set_escalation(body: EscalationBody, user: dict = Depends(require_login)):
    try:
        return escalation.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/quick")
def quick(body: QuickBody, user: dict = Depends(require_login)):
    try:
        return {"id": maintenance.quick(body.asset_ids, body.minutes, body.name, str(user.get("username") or "?"), body.scope_all)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{window_id}")
def update(window_id: int, body: WindowBody, user: dict = Depends(require_login)):
    try:
        return {"id": maintenance.save(window_id, body.model_dump(), str(user.get("username") or "?"))}
    except LookupError:
        raise HTTPException(404, "window not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{window_id}")
def delete(window_id: int, user: dict = Depends(require_login)):
    if not maintenance.delete_window(window_id):
        raise HTTPException(404, "window not found")
    return {"ok": True}
