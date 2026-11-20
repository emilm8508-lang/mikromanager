from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import cmdb

router = APIRouter(prefix="/api/cmdb", tags=["cmdb"])


class RelationBody(BaseModel):
    src: int
    dst: int
    kind: str
    note: Optional[str] = None


class HideBody(BaseModel):
    src: int
    dst: Optional[int] = None
    kind: str
    service_id: Optional[int] = None


def _who(user: dict) -> str:
    return str(user.get("username") or user.get("source") or "?")


@router.get("")
def overview():
    """Every configuration item with its class (set or suggested), counts per class, and how many relations there are."""
    return cmdb.overview()


@router.get("/asset/{asset_id}")
def for_asset(asset_id: int):
    """The relations of one CI, what is affected when it fails (impact) and what it needs (dependencies)."""
    return cmdb.for_asset(asset_id)


@router.post("/relations")
def add(body: RelationBody, user: dict = Depends(require_login)):
    try:
        return {"id": cmdb.add_relation(body.src, body.dst, body.kind, body.note, _who(user))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/relations/{rel_id}")
def remove(rel_id: int, user: dict = Depends(require_login)):
    if not cmdb.remove_relation(rel_id):
        raise HTTPException(404, "relation not found")
    return {"ok": True}


@router.post("/relations/hide")
def hide(body: HideBody, user: dict = Depends(require_login)):
    try:
        cmdb.hide_auto(body.src, body.dst, body.kind, body.service_id, _who(user))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}
