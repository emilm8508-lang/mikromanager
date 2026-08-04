"""
Firmware status collector — walks device version data (via cached
version_service) and produces a tenant-level summary for the central alerter.

The result is attached to unencrypted envelope metadata so OVH can dispatch
one-off "new RouterOS X available, N devices to upgrade" alerts.
Dedup is done server-side (OVH) by latest_stable version string.
"""
from typing import Optional

from models.database import SessionLocal, Device
from sqlalchemy import select
from services import version_service as ver_svc


async def collect_firmware_status() -> Optional[dict]:
    """Returns:
    {
      'latest_stable': '7.15.2',
      'outdated_count': 3,
      'devices_outdated': [
        {'name': 'R1', 'current': '7.13.1', 'target': '7.15.2'},
        ...
      ],
    }
    Or None if versions couldn't be fetched.
    """
    try:
        latest = await ver_svc.fetch_latest()
    except Exception:
        return None
    if not latest:
        return None

    stable = latest.get("stable") or {}
    latest_stable = stable.get("version") or ""
    if not latest_stable:
        return None

    outdated = []
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        for d in devices:
            if not d.ros_version:
                continue
            target = ver_svc.pick_target(d.ros_version, latest)
            if not target or target.get("status") != "outdated":
                continue
            outdated.append({
                "name": d.identity or d.name or d.ip,
                "current": d.ros_version,
                "target": target.get("target") or target.get("current"),
            })

    return {
        "latest_stable": latest_stable,
        "outdated_count": len(outdated),
        "devices_outdated": outdated[:20],  # cap payload
    }
