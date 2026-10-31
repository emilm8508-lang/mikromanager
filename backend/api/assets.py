from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import asyncio

from services import assets, asset_scan, lan_sweep, net_tools

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


class ScanSettingsIn(BaseModel):
    computers_hours: Optional[float] = None
    devices_hours: Optional[float] = None


@router.get("/scan-settings")
async def scan_settings():
    """How often the scheduler repeats the scans: computers (WinRM / SSH) and the other devices (SNMP), in hours."""
    return asset_scan.get_settings()


@router.put("/scan-settings")
async def set_scan_settings(body: ScanSettingsIn):
    return asset_scan.set_settings(body.computers_hours, body.devices_hours)


@router.get("/discover")
async def discover_status():
    return lan_sweep.status()


@router.post("/discover")
async def discover():
    """Looks for the computers of the scan ranges (TCP pokes + ARP + NetBIOS/DNS names) and rebuilds the inventory with them."""
    sweep = await lan_sweep.sweep_all()
    inv = await assets.refresh(fresh=True)
    return {"sweep": sweep, "inventory": inv}


@router.post("/refresh")
async def refresh():
    return await assets.refresh(fresh=True)


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


class ToolIn(BaseModel):
    tool: str                       # ping | traceroute | portscan
    ports: Optional[str] = None     # portscan only: "80,443,8000-8100" (the common ports when empty)


@router.post("/{asset_id}/tools")
async def run_tool(asset_id: int, body: ToolIn):
    """Ping / traceroute / TCP port scan of this asset's address, started now; read the output with GET /tools/{job}."""
    a = await assets.get_asset(asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    try:
        return net_tools.start(body.tool, a.get("ip") or "", body.ports)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(429, str(e))


@router.get("/tools/{job}")
async def tool_output(job: str, since: int = 0):
    r = net_tools.poll(job, since)
    if r is None:
        raise HTTPException(404, "no such job (it may have expired)")
    return r


@router.get("/duplicates")
async def duplicates():
    """The entries that look like one machine (same managed object, MAC address or name): [{ids, reasons, auto, keep, assets}]. `auto` ones are joined by the next inventory rebuild."""
    from services import asset_merge
    return {"groups": asset_merge.duplicates()}


class MergeIn(BaseModel):
    keep_id: int
    drop_ids: List[int]


@router.post("/merge")
async def merge(body: MergeIn):
    """Joins the entries `drop_ids` into `keep_id`: facts, tags and notes are combined and everything that pointed at a dropped entry (alerts, availability, metrics, syslog, racks ...) points at the survivor."""
    from services import asset_merge
    try:
        return asset_merge.merge(body.keep_id, body.drop_ids)
    except ValueError as e:
        raise HTTPException(400, str(e))


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


@router.get("/{asset_id}/playbook")
async def playbook(asset_id: int, lang: str = "pl"):
    """A remediation plan for the asset as a Markdown document ({filename, markdown}); Polish or English."""
    from services import playbook as pb
    r = await pb.build(asset_id, lang if lang in ("pl", "en") else "en")
    if r is None:
        raise HTTPException(404, "asset not found")
    return r


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
    place: Optional[str] = None
    notes: Optional[str] = None
    manual_groups: Optional[List[str]] = None


@router.put("/{asset_id}")
async def update(asset_id: int, body: AssetEdit):
    r = assets.update_asset(asset_id, body.model_dump(exclude_unset=True))
    if r is None:
        raise HTTPException(404, "asset not found")
    return r


class BulkIn(BaseModel):
    ids: List[int]
    action: str                       # delete | type
    asset_type: Optional[str] = None  # for "type": one of assets.TYPES, or "auto"


@router.post("/bulk")
async def bulk(body: BulkIn):
    if not body.ids or len(body.ids) > 5000:
        raise HTTPException(400, "select between 1 and 5000 assets")
    if body.action == "delete":
        return assets.delete_assets(body.ids)
    if body.action == "type":
        if body.asset_type != "auto" and body.asset_type not in assets.TYPES:
            raise HTTPException(400, "unknown asset type")
        n = assets.set_types(body.ids, body.asset_type)
        if body.asset_type == "auto":
            await assets.refresh(directory=False)          # the automatic classification applies at once
        return {"changed": n}
    raise HTTPException(400, "unknown action")


@router.delete("/{asset_id}")
async def delete(asset_id: int):
    if not assets.delete_asset(asset_id):
        raise HTTPException(404, "asset not found")
    return {"ok": True}
