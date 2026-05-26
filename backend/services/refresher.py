"""
Periodic device refresher — polls all known devices on a fixed interval
to update online status and metadata (identity, model, ROS version).

Runs as a single asyncio task started from FastAPI lifespan. State is held
in module-level globals so /api/system endpoints can report progress.
"""
import asyncio
import os
from datetime import datetime
from typing import Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.crypto import decrypt
from services import scanner as scan_svc
from services import topology as topo_svc


# ── State (read by /api/system endpoint) ──────────────────────────────────────
_last_run: Optional[datetime] = None
_last_duration_sec: Optional[float] = None
_in_progress: bool = False
_devices_checked: int = 0
_devices_updated: int = 0
_task: Optional[asyncio.Task] = None

INTERVAL_MIN = int(os.environ.get("MIKROTIK_REFRESH_MIN", "30"))


def status() -> dict:
    return {
        "interval_min": INTERVAL_MIN,
        "in_progress": _in_progress,
        "last_run": _last_run.isoformat() if _last_run else None,
        "last_duration_sec": round(_last_duration_sec, 1) if _last_duration_sec else None,
        "devices_checked_last": _devices_checked,
        "devices_updated_last": _devices_updated,
        "next_run_estimated": (
            _last_run.timestamp() + INTERVAL_MIN * 60 if _last_run else None
        ),
    }


async def _refresh_one(dev_id: int) -> bool:
    """Refresh single device. Returns True if anything was updated."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .outerjoin(Credential, Device.credential_id == Credential.id)
            .where(Device.id == dev_id)
        ).one_or_none()
        if not row:
            return False
        device, cred = row
        ip = device.ip
        web_port = device.web_port
        snmp_port = device.snmp_port or 161

        username = cred.username if cred else None
        password = decrypt(cred.password_enc) if cred else None
        community = decrypt(cred.snmp_community_enc) if (cred and cred.snmp_community_enc) else None

    updated = False
    online_now = False
    new_fields = {}

    if username and password:
        # Full enrichment via REST → API → SNMP fallback
        try:
            info = await scan_svc.enrich_device(
                ip, username, password,
                web_port=web_port,
                snmp_community=community,
                snmp_port=snmp_port,
            )
            if info.get("identity") or info.get("model") or info.get("ros_version"):
                online_now = True
                if info.get("identity"):
                    new_fields["identity"] = info["identity"]
                if info.get("model"):
                    new_fields["model"] = info["model"]
                if info.get("ros_version"):
                    new_fields["ros_version"] = info["ros_version"]
        except Exception:
            online_now = False
    else:
        # No credentials → just TCP-probe a few common ports for liveness
        for port in (8728, 80, 22, 443):
            if await scan_svc._tcp_open(ip, port):
                online_now = True
                break

    # Persist
    with SessionLocal() as db:
        device = db.execute(select(Device).where(Device.id == dev_id)).scalar_one_or_none()
        if not device:
            return False
        device.online = online_now
        device.last_seen = datetime.utcnow()
        for k, v in new_fields.items():
            if getattr(device, k, None) != v:
                setattr(device, k, v)
                updated = True
        db.commit()

    return updated or online_now


async def refresh_all_devices() -> None:
    """Iterate over every device and refresh it. Errors per-device are swallowed
    so one bad device doesn't stop the loop."""
    global _last_run, _last_duration_sec, _in_progress, _devices_checked, _devices_updated

    _in_progress = True
    _devices_checked = 0
    _devices_updated = 0
    start = datetime.utcnow()

    try:
        with SessionLocal() as db:
            ids = [d.id for d in db.execute(select(Device.id)).all()]

        # Limit concurrency so a /24 with 50 devices doesn't open 200 sockets at once
        sem = asyncio.Semaphore(10)

        async def _bounded(did):
            global _devices_checked, _devices_updated
            async with sem:
                try:
                    changed = await _refresh_one(did)
                    _devices_checked += 1
                    if changed:
                        _devices_updated += 1
                except Exception:
                    _devices_checked += 1

        await asyncio.gather(*(_bounded(i) for i in ids))

        # After per-device refresh, rediscover topology (LLDP/CDP/MNDP + tunnels).
        # This is cheap relative to the refresh itself.
        try:
            await topo_svc.discover_all()
        except Exception as e:
            print(f"[refresher] topology error: {e}")
    finally:
        _last_run = datetime.utcnow()
        _last_duration_sec = (_last_run - start).total_seconds()
        _in_progress = False


async def _loop():
    """Background loop. Waits one interval before first run so app startup is fast."""
    while True:
        try:
            await asyncio.sleep(INTERVAL_MIN * 60)
            await refresh_all_devices()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[refresher] error: {e}")


def start():
    global _task
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None
