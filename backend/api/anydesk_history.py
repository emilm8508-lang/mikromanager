from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import anydesk_history

router = APIRouter(prefix="/api/anydesk", tags=["anydesk"])


class LabelIn(BaseModel):
    cid: str
    label: str


class ClassifyIn(BaseModel):
    category: str | None = None
    note: str | None = None


@router.get("/status")
async def get_status():
    return anydesk_history.status()


@router.post("/sync")
async def sync():
    return anydesk_history.sync()


@router.get("/sessions")
async def sessions(cid: str | None = None, q: str | None = None,
                    from_date: str | None = None, to_date: str | None = None):
    return {"sessions": anydesk_history.list_sessions(cid=cid, q=q, from_date=from_date, to_date=to_date)}


@router.get("/labels")
async def labels():
    return {"labels": anydesk_history.list_labels()}


@router.put("/labels")
async def set_label(payload: LabelIn):
    return anydesk_history.set_label(payload.cid, payload.label)


@router.delete("/labels/{cid}")
async def delete_label(cid: str):
    return anydesk_history.delete_label(cid)


@router.put("/sessions/{session_id}/classify")
async def classify(session_id: int, payload: ClassifyIn):
    try:
        return anydesk_history.classify(session_id, payload.category, payload.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/summary")
async def summary(from_date: str | None = None, to_date: str | None = None):
    return {"summary": anydesk_history.summary(from_date=from_date, to_date=to_date)}
