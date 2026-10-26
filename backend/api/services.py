from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import business_services

router = APIRouter(prefix="/api/services", tags=["business-services"])


class ServiceBody(BaseModel):
    name: str
    description: Optional[str] = None
    mode: str = "all"                 # all | any | min
    min_up: Optional[int] = None
    target: Optional[float] = None    # SLA target, % of the month
    members: List[int]


@router.get("")
def services():
    """The business services with their state, the missing members and the SLA numbers."""
    return business_services.list_services()


@router.get("/{service_id}")
def service(service_id: int, days: int = 30):
    s = business_services.get_service(service_id, days)
    if s is None:
        raise HTTPException(404, "service not found")
    return s


@router.post("")
def create(body: ServiceBody, user: dict = Depends(require_login)):
    try:
        return {"id": business_services.save(None, **body.model_dump())}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{service_id}")
def update(service_id: int, body: ServiceBody, user: dict = Depends(require_login)):
    try:
        return {"id": business_services.save(service_id, **body.model_dump())}
    except LookupError:
        raise HTTPException(404, "service not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{service_id}")
def delete(service_id: int, user: dict = Depends(require_login)):
    if not business_services.delete_service(service_id):
        raise HTTPException(404, "service not found")
    return {"ok": True}
