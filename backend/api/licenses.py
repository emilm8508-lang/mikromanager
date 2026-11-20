from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import require_login
from services import licenses, audit as audit_svc

router = APIRouter(prefix="/api/licenses", tags=["licenses"])


class LicenseBody(BaseModel):
    product: str
    vendor: Optional[str] = None
    kind: str = "per_device"
    seats: Optional[int] = None
    match: Union[List[str], str]
    exclude: Optional[Union[List[str], str]] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    cost: Optional[Union[float, str]] = None
    currency: Optional[str] = None
    supplier: Optional[str] = None
    reference: Optional[str] = None
    notes: Optional[str] = None
    key: Optional[str] = None                     # absent keeps the stored key, "" clears it


def _who(user: dict) -> str:
    return str(user.get("username") or user.get("source") or "?")


@router.get("")
def overview():
    """Every license with its compliance (installs, in use, reclaimable, over, unused, status) and the programs no license covers yet."""
    return {"licenses": licenses.compliance(), "suggestions": licenses.suggestions()}


@router.get("/{lic_id}")
def detail(lic_id: int):
    for l in licenses.compliance(with_installs=True):
        if l["id"] == lic_id:
            return l
    raise HTTPException(404, "license not found")


@router.get("/asset/{asset_id}")
def for_asset(asset_id: int):
    return {"licenses": licenses.for_asset(asset_id)}


@router.post("")
def create(body: LicenseBody, user: dict = Depends(require_login)):
    try:
        return {"id": licenses.save(body.model_dump(exclude_unset=True), None, _who(user))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{lic_id}")
def update(lic_id: int, body: LicenseBody, user: dict = Depends(require_login)):
    try:
        return {"id": licenses.save(body.model_dump(exclude_unset=True), lic_id, _who(user))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{lic_id}")
def remove(lic_id: int, user: dict = Depends(require_login)):
    if not licenses.delete(lic_id):
        raise HTTPException(404, "license not found")
    return {"ok": True}


@router.get("/{lic_id}/key")
def key(lic_id: int, request: Request, user: dict = Depends(require_login)):
    """The license key - an admin only, and the reading is recorded in the audit log."""
    if user.get("role") != "admin":
        raise HTTPException(403, "admin role required (license keys)")
    try:
        k = licenses.read_key(lic_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    audit_svc.record(username=user.get("username") or "?", role=user.get("role") or "?", source=user.get("source") or "?",
                     method="GET", path=f"/api/licenses/{lic_id}/key", status_code=200, ip=request.client.host if request.client else None)
    return {"key": k}
