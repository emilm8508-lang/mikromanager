import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import traffic

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


class SampleIn(BaseModel):
    device_id: int
    interface: str
    seconds: int = 3


@router.get("/devices")
async def devices():
    """The routers that can be asked for their traffic (a MikroTik with a stored credential)."""
    return {"devices": traffic.mikrotik_devices()}


@router.get("/interfaces/{device_id}")
async def interfaces(device_id: int):
    try:
        return {"interfaces": await traffic.interfaces(device_id)}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except (asyncio.TimeoutError, Exception) as e:
        raise HTTPException(502, f"the router did not answer: {type(e).__name__}: {e}")


@router.post("/sample")
async def sample(body: SampleIn):
    """One Torch run (a few seconds) on an interface of the router: the flows and their aggregation. Read-only on the router."""
    try:
        return await traffic.sample(body.device_id, body.interface, body.seconds)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"the router did not answer Torch: {type(e).__name__}: {e}")
