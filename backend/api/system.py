"""
System endpoints — refresher status, manual trigger, topology, version checks,
critical-logs aggregator.
"""
import asyncio
import os
import time
from fastapi import APIRouter, HTTPException, Request
from services import refresher
from services import topology as topo_svc
from services import versions as ver_svc
from services import uplink as uplink_svc
from services import updater as updater_svc
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient
from models.database import SessionLocal, Device, Credential
from sqlalchemy import select
from pydantic import BaseModel

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
    """Re-discover topology now (independently of full refresh).
    409 if a discovery pass (this one, or the one the scheduled refresher
    runs automatically) is already in progress — prevents doubled-up REST
    call bursts against the same device."""
    if topo_svc._in_progress:
        raise HTTPException(409, "Wykrywanie topologii jest już w toku")
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
# TTL long enough that uplink cycles (every 2 min) don't refetch — otherwise
# every heartbeat generates login/logout entries in every device's log.
# Manual refresh from viewer's Dashboard still bypasses via the refresh button
# (it invalidates the query but hits the same cache; devices only get polled
# when this window elapses).
_CRIT_TTL = int(os.environ.get("MIKROMANAGER_CRIT_LOGS_TTL", "3600"))


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


# ── Uplink (central server integration) ──────────────────────────────────────

class UplinkConfig(BaseModel):
    url: str
    tenant: str
    api_key: str
    interval_sec: int = 120
    enc_key: str = ""  # base64 32 bytes; empty = no E2E (NOT recommended)


@router.get("/uplink/status")
async def uplink_status():
    return uplink_svc.status()


@router.post("/uplink/config")
async def uplink_configure(cfg: UplinkConfig):
    return uplink_svc.configure(
        url=cfg.url.rstrip("/"),
        tenant=cfg.tenant,
        api_key=cfg.api_key,
        interval_sec=cfg.interval_sec,
        enc_key=cfg.enc_key,
    )


@router.post("/uplink/generate-enc-key")
async def uplink_generate_enc_key():
    """Generate a fresh AES-256-GCM key (base64). Show ONCE to user — they
    must save it manually and configure the viewer with the same key."""
    return {"enc_key": uplink_svc.generate_enc_key()}


# ── Self-version + self-updater ──────────────────────────────────────────────

@router.get("/self-version")
async def self_version():
    """Return local git info so the viewer can compare against tenant agents."""
    return updater_svc.read_git_info()


@router.get("/updater/status")
async def updater_status():
    return updater_svc.status()


@router.post("/updater/run")
async def updater_run(restart: bool = True):
    """Manually trigger update on THIS agent (dev/testing).
    In production, updates should be initiated from the central viewer."""
    import asyncio as _a
    _a.create_task(updater_svc.perform_update(restart_supervisor=restart))
    return {"started": True}


# ── Central proxy (viewer → localhost → OVH) ─────────────────────────────────
# Browsers may fail to fetch the OVH API directly when:
#   - Corporate antivirus (Norton, Kaspersky, ESET) does TLS interception and
#     breaks CORS preflight responses.
#   - Custom DNS / proxy injects errors into cross-origin requests.
# Proxying through our local backend sidesteps both — the browser only talks
# to localhost, and Python's aiohttp does clean TLS to OVH.

_CENTRAL_PROXY_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "central_proxy.json"
)


def _load_allowed_host() -> str:
    import json
    if not os.path.exists(_CENTRAL_PROXY_CONFIG_PATH):
        return ""
    try:
        with open(_CENTRAL_PROXY_CONFIG_PATH) as f:
            return (json.load(f) or {}).get("allowed_host", "")
    except Exception:
        return ""


def _save_allowed_host(host: str) -> None:
    import json
    os.makedirs(os.path.dirname(_CENTRAL_PROXY_CONFIG_PATH), exist_ok=True)
    with open(_CENTRAL_PROXY_CONFIG_PATH, "w") as f:
        json.dump({"allowed_host": host}, f)


@router.get("/central-proxy/allowed-host")
async def central_proxy_get_allowed_host():
    return {"allowed_host": _load_allowed_host()}


class AllowedHostIn(BaseModel):
    host: str


@router.post("/central-proxy/allowed-host")
async def central_proxy_set_allowed_host(data: AllowedHostIn):
    """Explicitly (re)pin the central proxy to a hostname — used when
    switching to a different central server."""
    host = data.host.strip().lower()
    if not host or "/" in host or ":" in host:
        raise HTTPException(400, "host must be a bare hostname (no scheme/port/path)")
    _save_allowed_host(host)
    return {"allowed_host": host}


@router.delete("/central-proxy/allowed-host")
async def central_proxy_clear_allowed_host():
    """Clear the pin — next proxied request re-pins via trust-on-first-use."""
    _save_allowed_host("")
    return {"allowed_host": ""}


async def _central_proxy_forward(request: Request, upstream: str, method: str):
    if not upstream.startswith("https://"):
        raise HTTPException(400, "upstream must be HTTPS")

    from urllib.parse import urlparse
    hostname = (urlparse(upstream).hostname or "").lower()
    if not hostname:
        raise HTTPException(400, "upstream must include a hostname")

    allowed_host = _load_allowed_host()
    if not allowed_host:
        _save_allowed_host(hostname)
    elif hostname != allowed_host:
        raise HTTPException(
            403,
            f"upstream host '{hostname}' is not the pinned central host "
            f"('{allowed_host}') — clear it via DELETE /api/system/central-proxy/allowed-host "
            "if you intentionally switched central servers",
        )

    import aiohttp
    params = {k: v for k, v in request.query_params.items() if k != "upstream"}
    auth = request.headers.get("authorization", "")
    body = None
    headers = {"Authorization": auth}
    totp = request.headers.get("x-totp")
    if totp:
        headers["X-Totp"] = totp
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        body = await request.body()
        ct = request.headers.get("content-type")
        if ct:
            headers["Content-Type"] = ct

    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                method, upstream, params=params, headers=headers, data=body,
            ) as resp:
                data = await resp.read()
                from fastapi.responses import Response
                return Response(
                    content=data,
                    status_code=resp.status,
                    media_type=resp.content_type or "application/json",
                )
    except aiohttp.ClientError as e:
        raise HTTPException(502, f"Proxy upstream error: {type(e).__name__}: {e}")
    except asyncio.TimeoutError:
        raise HTTPException(504, "Upstream timeout")


@router.get("/central-proxy")
async def central_proxy_get(request: Request, upstream: str):
    return await _central_proxy_forward(request, upstream, "GET")


@router.post("/central-proxy")
async def central_proxy_post(request: Request, upstream: str):
    return await _central_proxy_forward(request, upstream, "POST")


@router.delete("/central-proxy")
async def central_proxy_delete(request: Request, upstream: str):
    return await _central_proxy_forward(request, upstream, "DELETE")


@router.post("/uplink/send-now")
async def uplink_send_now():
    """Force one snapshot send right now (for testing)."""
    return await uplink_svc.send_now()
