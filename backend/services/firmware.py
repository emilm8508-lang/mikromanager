"""
Mikrotik firmware upgrade orchestration.
Supports single-device and sequential bulk upgrades. Uses REST when available,
falls back to binary API. Devices without a MikrotikClient (Cisco SB, SNMP-only)
are rejected — SNMP is read-only and Cisco SB uses a different upgrade path.

Flow per device:
  1. Optional backup on device (/system/backup/save)
  2. Trigger /system/package/update/download-install (reboots the device)
  3. Poll for device to come back online (max 5 min)
  4. Read new version, update DB

State is held in _jobs (in-memory) so the UI can poll status.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential, DeviceBackup
from services.device_client import build_client
from services.mikrotik_client import MikrotikClient


# device_id → job status dict
_jobs: dict = {}


def get_job_status(device_id: int) -> dict:
    return _jobs.get(device_id, {"status": "no_job"})


def _load_client(device_id: int):
    """Return (device, cred, client) tuple or raise."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return None, None, None
        device, cred = row

    client = build_client(device, cred)
    return device, cred, client


async def check_updates(device_id: int) -> dict:
    """Trigger an update check on the device and read the result."""
    device, cred, client = _load_client(device_id)
    if not client:
        return {"error": "device or credential missing"}
    if not isinstance(client, MikrotikClient):
        return {"error": "firmware upgrade only supported for Mikrotik devices"}

    result = await client.get_package_update_status()
    if not result:
        return {"error": "check failed or timed out"}
    return result


async def backup_device(device_id: int, trigger: str = "manual") -> dict:
    """Ask device to save a backup file locally. Records in our DB.
    The actual file content is NOT downloaded to us in this version — the
    backup lives on the device and can be pulled manually via Winbox/FTP."""
    device, cred, client = _load_client(device_id)
    if not client:
        return {"error": "device or credential missing"}
    if not isinstance(client, MikrotikClient):
        return {"error": "backup only supported for Mikrotik"}

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    name = f"mm-{trigger}-{ts}"

    try:
        await client._rest_request("POST", "system/backup/save", {"name": name})
    except Exception:
        # Legacy API path
        try:
            loop = asyncio.get_event_loop()
            import librouteros
            def _run():
                api = librouteros.connect(
                    device.ip, username=cred.username,
                    password=client.password, port=device.api_port, timeout=8)
                try:
                    tuple(api("/system/backup/save", **{"name": name}))
                finally:
                    api.close()
            await loop.run_in_executor(None, _run)
        except Exception as e:
            return {"error": f"backup save failed: {type(e).__name__}: {e}"}

    filename = f"{name}.backup"
    with SessionLocal() as db:
        b = DeviceBackup(
            device_id=device_id,
            created_at=datetime.utcnow(),
            filename=filename,
            trigger=trigger,
            size_bytes=0,
            content_b64=None,
        )
        db.add(b)
        db.commit()
        db.refresh(b)
        backup_id = b.id

    return {"ok": True, "id": backup_id, "filename": filename, "downloaded_locally": False}


async def upgrade_device(device_id: int, do_backup: bool = True) -> dict:
    """Backup + download-install + wait for reboot + verify new version.
    This function blocks for up to ~7 minutes (backup + install + reboot).
    Called via BackgroundTasks so HTTP request returns immediately."""

    # Deduplicate concurrent triggers
    in_progress = _jobs.get(device_id, {}).get("status")
    if in_progress in ("queued", "backing_up", "downloading", "rebooting"):
        return {"error": f"upgrade already in state '{in_progress}'"}

    _jobs[device_id] = {
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "log": ["Starting upgrade"],
    }

    device, cred, client = _load_client(device_id)
    if not client:
        _jobs[device_id] = {"status": "error", "error": "device or credential missing"}
        return {"error": "device or credential missing"}
    if not isinstance(client, MikrotikClient):
        _jobs[device_id] = {"status": "error", "error": "only Mikrotik supported"}
        return {"error": "only Mikrotik supported"}

    _jobs[device_id]["old_version"] = device.ros_version or "unknown"
    _jobs[device_id]["ip"] = device.ip
    _jobs[device_id]["identity"] = device.identity or device.name or device.ip

    # 1. Backup
    if do_backup:
        _jobs[device_id]["status"] = "backing_up"
        _jobs[device_id]["log"].append("Creating backup on device...")
        b = await backup_device(device_id, trigger="pre-upgrade")
        if b.get("ok"):
            _jobs[device_id]["log"].append(f"Backup created: {b['filename']}")
            _jobs[device_id]["backup_filename"] = b["filename"]
        else:
            _jobs[device_id]["log"].append(f"Backup failed: {b.get('error')} — continuing anyway")

    # 2. Trigger download+install
    _jobs[device_id]["status"] = "downloading"
    _jobs[device_id]["log"].append("Sending download-install command...")
    try:
        try:
            await client.rest_get("system/package/update/download-install")
            _jobs[device_id]["log"].append("REST download-install sent")
        except Exception:
            await client.api_command("/system/package/update/download-install")
            _jobs[device_id]["log"].append("API download-install sent")
    except Exception as e:
        _jobs[device_id]["status"] = "error"
        _jobs[device_id]["error"] = f"install trigger failed: {e}"
        _jobs[device_id]["log"].append(f"ERROR: {e}")
        return {"error": str(e)}

    # 3. Wait for reboot (up to 5 min total)
    _jobs[device_id]["status"] = "rebooting"
    _jobs[device_id]["log"].append("Device rebooting, polling every 15s...")
    deadline = datetime.utcnow() + timedelta(minutes=5)

    # Wait 30s first — device needs to actually start rebooting
    await asyncio.sleep(30)

    while datetime.utcnow() < deadline:
        try:
            new_client = build_client(device, cred)
            resource = await new_client.get_resource()
            new_version = (resource.get("version") or "").split(" ")[0]
            if new_version:
                _jobs[device_id]["status"] = "done"
                _jobs[device_id]["new_version"] = new_version
                _jobs[device_id]["finished_at"] = datetime.utcnow().isoformat()
                _jobs[device_id]["log"].append(f"Device back online with version {new_version}")

                with SessionLocal() as db:
                    d = db.execute(select(Device).where(Device.id == device_id)).scalar_one_or_none()
                    if d:
                        d.ros_version = resource.get("version", new_version)
                        d.online = True
                        d.last_seen = datetime.utcnow()
                        db.commit()
                try:
                    from services import activity
                    activity.record(
                        "firmware_upgraded",
                        device_id=device_id,
                        device_name=_jobs[device_id].get("identity"),
                        device_ip=_jobs[device_id].get("ip"),
                        old_version=_jobs[device_id].get("old_version"),
                        new_version=new_version,
                    )
                except Exception as e:
                    print(f"[firmware] activity record error: {e}")
                return {"ok": True, "old": _jobs[device_id]["old_version"], "new": new_version}
        except Exception:
            pass
        await asyncio.sleep(15)

    _jobs[device_id]["status"] = "timeout"
    _jobs[device_id]["log"].append("Timeout — device did not come back within 5 min")
    try:
        from services import activity
        activity.record(
            "firmware_upgrade_failed",
            device_id=device_id,
            device_name=_jobs[device_id].get("identity"),
            device_ip=_jobs[device_id].get("ip"),
            old_version=_jobs[device_id].get("old_version"),
            error="timeout after 5 min",
        )
    except Exception as e:
        print(f"[firmware] activity record error: {e}")
    return {"error": "timeout waiting for device"}


async def upgrade_bulk(device_ids: list, do_backup: bool = False) -> dict:
    """Sequential upgrade. Each device fully completes (or fails) before next.
    do_backup controlled per bulk operation — user opts in via UI checkbox."""
    for did in device_ids:
        _jobs[did] = {"status": "queued", "log": ["Waiting in queue"]}

    results = {}
    for did in device_ids:
        try:
            r = await upgrade_device(did, do_backup=do_backup)
            results[did] = r
        except Exception as e:
            results[did] = {"error": str(e)}
    return {"results": results, "total": len(device_ids), "backup": do_backup}


def list_backups(device_id: Optional[int] = None) -> list:
    """List recorded backups. Optionally filtered by device_id."""
    with SessionLocal() as db:
        q = select(DeviceBackup).order_by(DeviceBackup.created_at.desc())
        if device_id is not None:
            q = q.where(DeviceBackup.device_id == device_id)
        rows = db.execute(q).scalars().all()
        return [{
            "id": b.id,
            "device_id": b.device_id,
            "created_at": b.created_at.isoformat() if b.created_at else None,
            "filename": b.filename,
            "trigger": b.trigger,
            "size_bytes": b.size_bytes,
            "downloaded_locally": bool(b.content_b64),
        } for b in rows]
