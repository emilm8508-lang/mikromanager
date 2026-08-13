"""
Firmware status collector — walks device version data and produces both:
  - a tenant-level summary for the central alerter (collect_firmware_status,
    unchanged behavior/shape — attached to unencrypted envelope metadata so
    OVH can dispatch one-off "N devices to upgrade" alerts), and
  - a full compliance report for the local UI (collect_compliance_report) —
    every device classified compliant/outdated/unknown, plus aggregate
    percentages, evidence-oriented for an ISO 27001 / NIS2 audit ("X% of
    devices on the approved version") rather than just a to-do list.

Two genuinely different things get reported here, per RouterOS's own
terminology — conflating them was the root cause of a prior "the firmware
alert doesn't seem right" bug report:
  - RouterOS VERSION (the OS package, e.g. "7.15.2").
  - RouterBOARD FIRMWARE (a separate bootloader/RouterBOOT version shown by
    /system/routerboard as current-firmware vs upgrade-firmware) — what
    RouterOS's own admin UI actually calls "firmware".
"""
from typing import List, Optional

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


def _classify_device(d: Device, latest: Optional[dict]) -> dict:
    """Per-device compliance classification for both RouterOS version and
    RouterBOARD firmware — 'unknown' (not 'outdated') when we genuinely
    can't tell (no credentials yet, device never enriched, non-Mikrotik
    gear with no RouterBOARD concept at all), so those devices are excluded
    from the percentage's denominator rather than silently counted as
    either compliant or outdated."""
    name = d.identity or d.name or d.ip

    ros_status = "unknown"
    ros_target = None
    if d.ros_update_status:
        # Per-device, architecture/channel-aware — the authoritative answer
        # for THIS specific model, preferred over the global-file guess.
        ros_target = d.latest_ros_version
        ros_status = "outdated" if d.ros_update_status.lower().startswith("new") and d.latest_ros_version else "compliant"
    elif d.ros_version and latest:
        target = ver_svc.pick_target(d.ros_version, latest)
        if target:
            ros_target = target.get("target") or target.get("current")
            ros_status = "outdated" if target.get("status") == "outdated" else "compliant"

    firmware_status = "unknown"
    if d.current_firmware and d.upgrade_firmware:
        firmware_status = "compliant" if d.current_firmware == d.upgrade_firmware else "outdated"

    return {
        "device_id": d.id, "name": name, "ip": d.ip, "model": d.model, "vendor": d.vendor,
        "ros_version": d.ros_version, "ros_target": ros_target, "ros_status": ros_status,
        "firmware_current": d.current_firmware, "firmware_target": d.upgrade_firmware,
        "firmware_status": firmware_status,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
    }


async def _classify_all() -> tuple:
    """Returns (rows, latest_stable) — shared by both collectors below so
    the classification logic (and its edge cases) only exists once."""
    try:
        latest = await ver_svc.fetch_latest()
    except Exception:
        latest = None
    latest_stable = _pick_headline_version(latest) if latest else ""

    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        rows = [_classify_device(d, latest) for d in devices]
    return rows, latest_stable


async def collect_firmware_status() -> Optional[dict]:
    """Returns:
    {
      'latest_stable': '7.15.2',
      'outdated_count': 3,
      'devices_outdated': [{'name': 'R1', 'current': '7.13.1', 'target': '7.15.2'}, ...],
      'firmware_outdated_count': 1,
      'devices_firmware_outdated': [{'name': 'R2', 'current': '7.1', 'target': '7.2'}, ...],
    }
    Or None if versions couldn't be fetched. Unchanged shape from before —
    this feeds the central alerter, which several existing OVH rules key on."""
    rows, latest_stable = await _classify_all()

    outdated = [
        {"name": r["name"], "current": r["ros_version"] or "", "target": r["ros_target"]}
        for r in rows if r["ros_status"] == "outdated"
    ]
    firmware_outdated = [
        {"name": r["name"], "current": r["firmware_current"], "target": r["firmware_target"]}
        for r in rows if r["firmware_status"] == "outdated"
    ]

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


async def collect_compliance_report() -> dict:
    """Full per-device breakdown + aggregate compliance percentages, for
    the local UI's "raport zgodności" — evidence of the fleet's patch
    posture for an audit, not just a to-do list. Percentages are computed
    only over devices we could actually classify (ros_status/firmware_
    status != 'unknown') — a device with no credentials yet shouldn't drag
    the percentage down as if it were known-outdated."""
    rows, latest_stable = await _classify_all()

    def _pct(known: List[dict], key: str) -> Optional[float]:
        if not known:
            return None
        compliant = sum(1 for r in known if r[key] == "compliant")
        return round(compliant / len(known) * 100, 1)

    ros_known = [r for r in rows if r["ros_status"] != "unknown"]
    firmware_known = [r for r in rows if r["firmware_status"] != "unknown"]

    return {
        "latest_stable": latest_stable,
        "total_devices": len(rows),
        "ros_known_count": len(ros_known),
        "ros_compliant_count": sum(1 for r in ros_known if r["ros_status"] == "compliant"),
        "ros_compliant_pct": _pct(ros_known, "ros_status"),
        "firmware_known_count": len(firmware_known),
        "firmware_compliant_count": sum(1 for r in firmware_known if r["firmware_status"] == "compliant"),
        "firmware_compliant_pct": _pct(firmware_known, "firmware_status"),
        "devices": rows,
    }
