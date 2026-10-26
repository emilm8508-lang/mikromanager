from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import syslog_receiver

router = APIRouter(prefix="/api/syslog", tags=["syslog"])


class RuleBody(BaseModel):
    name: str
    pattern: str
    severity: str = "medium"
    source: str = "any"
    threshold: int = 1
    window_sec: int = 300
    enabled: bool = True


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    syslog_port: Optional[int] = None
    trap_port: Optional[int] = None
    accept_unknown: Optional[bool] = None
    store_info: Optional[bool] = None
    communities: Optional[List[str]] = None
    rules: Optional[List[RuleBody]] = None
    disabled: Optional[List[str]] = None


@router.get("/status")
def status():
    """Whether the receiver listens, what came in, from which devices and which unknown sources were turned away; the detections."""
    return syslog_receiver.status()


@router.put("/settings")
async def settings(body: SettingsBody, user: dict = Depends(require_login)):
    data = body.model_dump(exclude_unset=True)
    try:
        return await syslog_receiver.update_settings(data)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/events")
def events(limit: int = 200, offset: int = 0, kind: Optional[str] = None, ip: Optional[str] = None, max_severity: Optional[int] = None, q: Optional[str] = None):
    return syslog_receiver.events(limit=limit, offset=offset, kind=kind, source_ip=ip, max_severity=max_severity, q=q)
