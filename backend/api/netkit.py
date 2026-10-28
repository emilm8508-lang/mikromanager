from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import netkit, activity

router = APIRouter(prefix="/api/netkit", tags=["netkit"])


class WolBody(BaseModel):
    mac: str


class SnmpBody(BaseModel):
    ip: str
    op: str = "get"                     # get | walk
    oid: str
    community: Optional[str] = None
    port: int = 161


class QueryBody(BaseModel):
    query: str


@router.get("/hosts")
def hosts():
    """The hosts of the inventory the tools can be pointed at."""
    return {"hosts": netkit.hosts()}


@router.post("/wol")
def wol(body: WolBody, user: dict = Depends(require_login)):
    try:
        r = netkit.wake(body.mac)
    except ValueError as e:
        raise HTTPException(400, str(e))
    activity.record("wake_on_lan", mac=r["mac"], by=str(user.get("username") or "?"))
    return r


@router.post("/snmp")
async def snmp(body: SnmpBody, user: dict = Depends(require_login)):
    try:
        return await netkit.snmp_query(body.ip, body.op, body.oid, body.community, body.port)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/rdap")
async def rdap(body: QueryBody, user: dict = Depends(require_login)):
    try:
        return await netkit.rdap(body.query)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/path")
async def path(body: QueryBody, user: dict = Depends(require_login)):
    try:
        return await netkit.path(body.query)
    except ValueError as e:
        raise HTTPException(400, str(e))
