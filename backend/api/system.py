"""
System endpoints — refresher status and manual trigger.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from services import refresher

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/refresh/status")
async def get_refresh_status():
    return refresher.status()


@router.post("/refresh/run")
async def trigger_refresh():
    """Fire-and-forget — kick off a full refresh now. 409 if one is already running."""
    if refresher._in_progress:
        raise HTTPException(409, "Odświeżanie jest już w toku")
    asyncio.create_task(refresher.refresh_all_devices())
    return {"status": "started"}
