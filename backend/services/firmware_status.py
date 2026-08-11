"""
Firmware status collector — walks device version data and produces a
tenant-level summary for the central alerter.

The result is attached to unencrypted envelope metadata so OVH can dispatch
one-off "new RouterOS X available, N devices to upgrade" / "N devices need
a RouterBOARD firmware upgrade" alerts. Dedup is done server-side (OVH).

Two genuinely different things get reported here, per RouterOS's own
terminology — conflating them was the root cause of a prior "the firmware
alert doesn't seem right" bug report:
  - RouterOS VERSION (the OS package, e.g. "7.15.2") — outdated_count/
    devices_outdated below.
  - RouterBOARD FIRMWARE (a separate bootloader/RouterBOOT version shown by
    /system/routerboard as current-firmware vs upgrade-firmware) — what
    RouterOS's own admin UI actually calls "firmware" — firmware_
    outdated_count/devices_firmware_outdated below.
"""
from typing import Optional

from models.database import SessionLocal, Device
from sqlalchemy import select
from services import versions as ver_svc


def _pick_headline_version(latest_map: dict) -> str:
    """A single representative "latest stable" figure for the alert
    headline — prefers the newer major track (7) if we have it, else 6.
    (Per-device comparisons never use this — they always stay on each
    device's own major track via ver_svc.pick_target.)"""
    for channel in ("7", "6"):
        entry = latest_map.get(channel)
        if entry and entry.get("version"):
            return entry["version"]
    return ""


async def collect_firmware_status() -> Optional[dict]:
    """Returns:
    {
      'latest_stable': '7.15.2',
      'outdated_count': 3,
      'devices_outdated': [{'name': 'R1', 'current': '7.13.1', 'target': '7.15.2'}, ...],
      'firmware_outdated_count': 1,
      'devices_firmware_outdated': [{'name': 'R2', 'current': '7.1', 'target': '7.2'}, ...],
    }
    Or None if versions couldn't be fetched.
    """
    try:
        latest = await ver_svc.fetch_latest()
    except Exception:
        latest = None

    latest_stable = _pick_headline_version(latest) if latest else ""

    outdated = []
    firmware_outdated = []
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        for d in devices:
            name = d.identity or d.name or d.ip

            # RouterOS version — prefer the device's OWN reported check
            # (per-device, architecture/channel-aware — the authoritative
            # answer for THIS specific model) over the global-file guess,
            # which has no idea whether a given model still gets a
            # particular release at all.
            if d.ros_update_status:
                if d.ros_update_status.lower().startswith("new") and d.latest_ros_version:
                    outdated.append({
                        "name": name, "current": d.ros_version or "",
                        "target": d.latest_ros_version,
                    })
            elif d.ros_version and latest:
                target = ver_svc.pick_target(d.ros_version, latest)
                if target and target.get("status") == "outdated":
                    outdated.append({
                        "name": name, "current": d.ros_version,
                        "target": target.get("target") or target.get("current"),
                    })

            # RouterBOARD firmware — genuinely different from the above.
            if (d.current_firmware and d.upgrade_firmware
                    and d.current_firmware != d.upgrade_firmware):
                firmware_outdated.append({
                    "name": name, "current": d.current_firmware,
                    "target": d.upgrade_firmware,
                })

    if not outdated and not firmware_outdated:
        return None if not latest_stable else {
            "latest_stable": latest_stable, "outdated_count": 0, "devices_outdated": [],
            "firmware_outdated_count": 0, "devices_firmware_outdated": [],
        }

    return {
        "latest_stable": latest_stable,
        "outdated_count": len(outdated),
        "devices_outdated": outdated[:20],  # cap payload
        "firmware_outdated_count": len(firmware_outdated),
        "devices_firmware_outdated": firmware_outdated[:20],
    }
