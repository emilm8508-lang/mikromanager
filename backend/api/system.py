"""
System endpoints — refresher status, manual trigger, topology.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from services import refresher
from services import topology as topo_svc
from services import versions as ver_svc
from models.database import SessionLocal, Device
from sqlalchemy import select

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


@router.get("/versions/latest")
async def get_latest_versions():
    """Latest available RouterOS versions per channel from upgrade.mikrotik.com."""
    data = await ver_svc.fetch_latest()
    return data


@router.get("/versions/status")
async def get_version_status():
    """For every device — returns its current version and upgrade recommendation."""
    latest = await ver_svc.fetch_latest()
    cache_info = ver_svc.cache_info()
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        result = []
        for d in devices:
            target = ver_svc.pick_target(d.ros_version or "", latest)
            result.append({
                "id": d.id,
                "ip": d.ip,
                "name": d.name,
                "identity": d.identity,
                "current": d.ros_version,
                "target": target,
            })
    return {
        "latest": latest,
        "devices": result,
        "fetch_status": cache_info,
    }


@router.post("/versions/refresh")
async def force_refresh_versions():
    """Force re-fetch of latest versions from upgrade.mikrotik.com (bypass cache)."""
    data = await ver_svc.fetch_latest(force=True)
    return {"latest": data, "fetch_status": ver_svc.cache_info()}
