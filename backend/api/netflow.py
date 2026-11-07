from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import netflow, wazuh_features

router = APIRouter(prefix="/api/netflow", tags=["netflow"])


class SettingsBody(BaseModel):
    enabled: Optional[bool] = None
    port: Optional[int] = None
    accept_unknown: Optional[bool] = None
    local_nets: Optional[List[str]] = None
    scan_ports: Optional[int] = None
    scan_hosts: Optional[int] = None
    lateral_hosts: Optional[int] = None
    beacon: Optional[bool] = None
    external_scans: Optional[bool] = None
    max_hosts: Optional[int] = None


@router.get("/status")
def status():
    """Whether the collector listens, the exporters, the last windows (busiest hosts, conversations), the detections; the Wazuh series state."""
    from services import onboarding
    return {**netflow.status(), "agent_ip": onboarding.agent_ip(), "wazuh": wazuh_features.status()}


@router.put("/settings")
async def settings(body: SettingsBody, user: dict = Depends(require_login)):
    try:
        return await netflow.update_settings(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))
