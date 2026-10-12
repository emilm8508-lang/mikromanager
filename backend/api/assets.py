from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import assets

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("/summary")
async def summary():
    """Dashboard numbers: totals, new in 7 days, by type / location / OS lifecycle / scan level, vulnerabilities."""
    return await assets.summary()


@router.get("")
async def list_assets():
    return {"assets": await assets.list_assets()}


@router.post("/refresh")
async def refresh():
    return await assets.refresh()


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
