from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import asyncio

from services import assets, asset_scan, lan_sweep

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("/summary")
async def summary():
    """Dashboard numbers: totals, new in 7 days, by type / location / OS lifecycle / scan level, vulnerabilities."""
    return await assets.summary()


@router.get("/vuln-history")
async def vuln_history(days: int = 90):
    """Open vulnerabilities per severity and vulnerable assets, one point per day."""
    return {"points": assets.vuln_history(days)}


@router.get("")
async def list_assets():
    return {"assets": await assets.list_assets()}


@router.get("/discover")
async def discover_status():
    return lan_sweep.status()


@router.post("/discover")
async def discover():
    """Looks for the computers of the scan ranges (TCP pokes + ARP + NetBIOS/DNS names) and rebuilds the inventory with them."""
    sweep = await lan_sweep.sweep_all()
    inv = await assets.refresh()
    return {"sweep": sweep, "inventory": inv}


@router.post("/refresh")
async def refresh():
    return await assets.refresh()


@router.post("/scan-all")
async def scan_all():
    """Scan every active device now - credentialed where a credential works, SNMP basics otherwise (the scheduler does the stale ones by itself)."""
    ids = [a["id"] for a in await assets.list_assets() if a["ip"] and a["active"]]
    asyncio.create_task(asset_scan.scan_all(ids))
    return {"started": len(ids)}


@router.post("/{asset_id}/scan")
async def scan_one(asset_id: int):
    """Hardware scan of this device (credentialed if possible, else SNMP); runs in the background, the card shows `scan.running` meanwhile."""
    if not asset_scan.can_scan(asset_id):
        raise HTTPException(400, "this device has no address to scan")
    if asset_id in asset_scan.running_ids():
        return {"started": False, "running": True}
    asyncio.create_task(asset_scan.scan_asset(asset_id))
    return {"started": True}


@router.get("/{asset_id}")
async def get_asset(asset_id: int):
    a = await assets.get_asset(asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    return a


@router.get("/{asset_id}/vulnerabilities")
async def vulnerabilities(asset_id: int):
    v = await assets.asset_vulnerabilities(asset_id)
    if v is None:
        raise HTTPException(404, "asset not found")
    return {"findings": v}


@router.get("/{asset_id}/software")
async def software(asset_id: int):
    s = assets.asset_software(asset_id)
    if s is None:
        raise HTTPException(404, "asset not found")
    return {"software": s}


class AssetEdit(BaseModel):
    asset_type: Optional[str] = None
    role: Optional[str] = None
    name: Optional[str] = None
    location_override: Optional[str] = None
    notes: Optional[str] = None
    manual_groups: Optional[List[str]] = None


@router.put("/{asset_id}")
async def update(asset_id: int, body: AssetEdit):
    r = assets.update_asset(asset_id, body.model_dump(exclude_unset=True))
    if r is None:
        raise HTTPException(404, "asset not found")
    return r


@router.delete("/{asset_id}")
async def delete(asset_id: int):
    if not assets.delete_asset(asset_id):
        raise HTTPException(404, "asset not found")
    return {"ok": True}
