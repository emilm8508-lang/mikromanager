from typing import Any, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.auth import require_login
from services import procurement as pc

router = APIRouter(prefix="/api/procurement", tags=["procurement"])


def _who(user: dict) -> str:
    return str(user.get("username") or user.get("source") or "?")


def _run(fn, *a):
    try:
        return fn(*a)
    except ValueError as e:
        raise HTTPException(400, str(e))


class VendorBody(BaseModel):
    name: str
    contact: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    notes: Optional[str] = None


class ContractBody(BaseModel):
    title: str
    kind: str = "support"
    number: Optional[str] = None
    vendor_id: Optional[int] = None
    start_at: Optional[str] = None
    end_at: Optional[str] = None
    notice_days: Optional[int] = None
    value: Optional[Any] = None
    currency: Optional[str] = None
    auto_renew: bool = False
    owner: Optional[str] = None
    notes: Optional[str] = None
    asset_ids: List[int] = []
    license_ids: List[int] = []


class OrderBody(BaseModel):
    number: str
    vendor_id: Optional[int] = None
    items: List[dict]
    currency: Optional[str] = None
    notes: Optional[str] = None


class StatusBody(BaseModel):
    status: str
    received_at: Optional[str] = None


@router.get("/vendors")
def vendors():
    return {"vendors": pc.vendors()}


@router.post("/vendors")
def add_vendor(body: VendorBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_vendor, body.model_dump(), None)}


@router.put("/vendors/{vid}")
def edit_vendor(vid: int, body: VendorBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_vendor, body.model_dump(), vid)}


@router.delete("/vendors/{vid}")
def del_vendor(vid: int, user: dict = Depends(require_login)):
    if not _run(pc.delete_vendor, vid):
        raise HTTPException(404, "vendor not found")
    return {"ok": True}


@router.get("/contracts")
def contracts(asset_id: Optional[int] = None):
    """Every contract with its status (future / active / expiring / expired / renewing), vendor, covered assets and licenses, attachments."""
    return {"contracts": pc.contracts_for_asset(asset_id) if asset_id else pc.contracts()}


@router.post("/contracts")
def add_contract(body: ContractBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_contract, body.model_dump(), None, _who(user))}


@router.put("/contracts/{cid}")
def edit_contract(cid: int, body: ContractBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_contract, body.model_dump(), cid, _who(user))}


@router.delete("/contracts/{cid}")
def del_contract(cid: int, user: dict = Depends(require_login)):
    if not pc.delete_contract(cid):
        raise HTTPException(404, "contract not found")
    return {"ok": True}


@router.get("/orders")
def orders():
    return {"orders": pc.orders()}


@router.post("/orders")
def add_order(body: OrderBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_order, body.model_dump(), None, _who(user))}


@router.put("/orders/{oid}")
def edit_order(oid: int, body: OrderBody, user: dict = Depends(require_login)):
    return {"id": _run(pc.save_order, body.model_dump(), oid, _who(user))}


@router.post("/orders/{oid}/status")
def order_status(oid: int, body: StatusBody, user: dict = Depends(require_login)):
    """Moves an order along its flow; "received" creates the asset items as assets in stock and adds license items to their seats."""
    return _run(pc.set_order_status, oid, body.status, _who(user), body.received_at)


@router.delete("/orders/{oid}")
def del_order(oid: int, user: dict = Depends(require_login)):
    if not _run(pc.delete_order, oid):
        raise HTTPException(404, "order not found")
    return {"ok": True}


@router.get("/attachments")
def list_attachments(owner_kind: str, owner_id: int):
    return {"attachments": pc.attachments_of(owner_kind, owner_id)}


@router.post("/attachments")
async def upload(owner_kind: str = Form(...), owner_id: int = Form(...), file: UploadFile = File(...), user: dict = Depends(require_login)):
    data = await file.read(pc.MAX_FILE + 1)
    return {"id": _run(pc.add_attachment, owner_kind, owner_id, file.filename or "file", data, _who(user))}


@router.get("/attachments/{att_id}")
def download(att_id: int):
    a = pc.attachment(att_id)
    if not a:
        raise HTTPException(404, "attachment not found")
    # always a download: never rendered by the browser as a page of this application
    return FileResponse(a["path"], media_type=a["content_type"] or "application/octet-stream", filename=a["filename"],
                        headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox"},
                        content_disposition_type="attachment")


@router.delete("/attachments/{att_id}")
def del_attachment(att_id: int, user: dict = Depends(require_login)):
    if not pc.delete_attachment(att_id):
        raise HTTPException(404, "attachment not found")
    return {"ok": True}
