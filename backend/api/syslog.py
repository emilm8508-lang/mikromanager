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
    from services import onboarding
    return {**syslog_receiver.status(), "agent_ip": onboarding.agent_ip()}


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


# ── router logs (services/router_logs.py): do the routers send their log here, and the rules' settings ──

@router.get("/router-logging")
def router_logging():
    """Per MikroTik: its remote logging actions, whether one points at this agent, with which topics (read over its API, every 6 h)."""
    from services import router_logs
    return {**router_logs.logging_status(), "summary": router_logs.public_summary(), "settings": router_logs.settings()}


@router.post("/router-logging/check")
async def router_logging_check(user: dict = Depends(require_login)):
    from services import router_logs
    return {"routers": await router_logs.check_logging()}


class RouterRulesBody(BaseModel):
    mgmt_nets: Optional[List[str]] = None       # the management networks: a login from outside them is an alert
    rdap: Optional[bool] = None                 # look up the owners of public addresses in RDAP


@router.put("/router-rules/settings")
def router_rules_settings(body: RouterRulesBody, user: dict = Depends(require_login)):
    from services import router_logs
    try:
        return router_logs.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))
