"""
System endpoints — refresher status, manual trigger, topology, version checks,
critical-logs aggregator.
"""
import asyncio
import time
from fastapi import APIRouter, HTTPException
from services import refresher
from services import topology as topo_svc
from services import versions as ver_svc
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient
from models.database import SessionLocal, Device, Credential
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


# ── Critical log aggregator ──────────────────────────────────────────────────
# Live view — never stored. Cached in-memory 60s to avoid flooding devices.
_crit_cache: dict = {"data": [], "fetched_at": 0}
_CRIT_TTL = 60


@router.get("/critical-logs")
async def get_critical_logs(limit: int = 20):
    """Aggregate latest critical log entries across all devices with credentials.
    Live read — nothing stored. Cached server-side for 60s."""
    now = time.time()
    if (now - _crit_cache["fetched_at"]) < _CRIT_TTL:
        return _crit_cache["data"][:limit]

    with SessionLocal() as db:
        rows = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
        ).all()
        devices_creds = [(d, c) for d, c in rows]

    results = []
    sem = asyncio.Semaphore(8)  # avoid hammering many devices at once

    async def fetch_one(device, cred):
        async with sem:
            try:
                client = MikrotikClient(
                    device.ip, cred.username, decrypt(cred.password_enc),
                    api_port=device.api_port, web_port=device.web_port,
                    snmp_community=decrypt(cred.snmp_community_enc) if cred.snmp_community_enc else None,
                    snmp_port=device.snmp_port or 161,
                )
                logs = await asyncio.wait_for(client.get_logs(limit=200), timeout=5)
            except Exception:
                return
            device_label = device.identity or device.name or device.ip
            for entry in logs:
                topics = (entry.get("topics") or "").lower()
                if "critical" in topics or "error" in topics:
                    results.append({
                        "device_id": device.id,
                        "device_ip": device.ip,
                        "device_label": device_label,
                        "time": entry.get("time"),
                        "topics": entry.get("topics"),
                        "message": entry.get("message"),
                    })

    await asyncio.gather(*[fetch_one(d, c) for d, c in devices_creds])

    # Sort newest first by time string. Mikrotik time may be "HH:MM:SS" (today)
    # or "MMM/DD HH:MM:SS" (older). Sorting lexicographically reverse gives
    # roughly correct ordering for entries in the same day; dated entries get
    # mixed but that's acceptable for a 20-entry summary.
    results.sort(key=lambda x: (x.get("time") or ""), reverse=True)

    _crit_cache["data"] = results
    _crit_cache["fetched_at"] = now
    return results[:limit]
