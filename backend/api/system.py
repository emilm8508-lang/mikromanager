"""
System endpoints — refresher status, manual trigger, topology.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from services import refresher
from services import topology as topo_svc

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


@router.get("/topology")
async def get_topology():
    """Return graph data for the network map: {nodes:[...], links:[...]}."""
    return topo_svc.get_topology()


@router.post("/topology/discover")
async def trigger_topology_discover():
    """Re-discover topology now (independently of full refresh)."""
    result = await topo_svc.discover_all()
    return result
