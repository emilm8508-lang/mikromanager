"""
Fleet view of the Mikrotik devices — the part of MikroTik's own fleet
management (inventory, resources, alerts, available updates, Wi-Fi overview)
this agent can offer from data it already holds plus a few extra reads.

  - collect: hourly (from resource_monitor's Mikrotik loop) and on demand, one
    pass per device reads architecture, uptime, installed packages, update
    channel and the Wi-Fi interfaces/clients, and stores them on the Device
    row. A failed read never wipes what was stored before.
  - build_overview(): everything the "Mikrotik" tab shows, computed from the
    database only (no live connections), so the page is instant and works
    for devices that are momentarily unreachable.
  - public_summary(): the same without IP addresses, for the snapshot's
    plaintext envelope -> Central's "Mikrotik" page.

Bandwidth/traffic is deliberately NOT part of this view (not wanted).

Alerts here are COMPUTED from the stored values with the same thresholds the
alert pipeline uses (resource_monitor's *_ALERT_* constants) — a dashboard
summary of what is wrong right now, not a second alerting mechanism.
"""
import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.crypto import decrypt
from services.device_client import build_client
import re

from services.mikrotik_client import MikrotikClient
from services import resource_monitor as rm

CPU_ALERT_PCT = float(os.environ.get("MIKROTIK_CPU_ALERT_PCT", "90"))
_STEP_TIMEOUT_SEC = 12
_MAX_STATIONS_STORED = 500
_AUTO_REFRESH_MIN_GAP_SEC = 300

_refresh_running = False
_last_auto_refresh = 0.0


# ── Wi-Fi parsing (pure) ─────────────────────────────────────────────────────

def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1")


def _int_or_none(v) -> Optional[int]:
    try:
        return int(str(v).split(",")[0].split(".")[0])
    except (TypeError, ValueError):
        return None


_UPTIME_RE = re.compile(r"^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_uptime(value) -> Optional[int]:
    """RouterOS uptime such as "2w3d4h5m6s" (weeks appear after 7 days — the
    shared duration parser in mikrotik_client.py has no "w", and uptime is
    exactly where it matters) or a plain number of seconds."""
    if value is None or value == "":
        return None
    s = str(value).strip()
    if s.isdigit():
        return int(s)
    m = _UPTIME_RE.match(s)
    if not m or not any(m.groups()):
        return None
    w, d, h, mi, sec = (int(g) if g else 0 for g in m.groups())
    return w * 604800 + d * 86400 + h * 3600 + mi * 60 + sec


def band_of(freq_mhz: Optional[int], band_str: Optional[str]) -> Optional[str]:
    """'2.4' | '5' | '6' from the operating frequency if known, else from the
    interface's band string ('2ghz-b/g/n', '5ghz-ax', ...). A frequency
    configured as 'auto' is not a number, so the band string is the fallback."""
    if freq_mhz:
        if 2400 <= freq_mhz <= 2500:
            return "2.4"
        if 4900 <= freq_mhz < 5925:
            return "5"
        if 5925 <= freq_mhz <= 7125:
            return "6"
    b = (band_str or "").lower()
    if b.startswith("2ghz") or b.startswith("2.4"):
        return "2.4"
    if b.startswith("5ghz"):
        return "5"
    if b.startswith("6ghz"):
        return "6"
    return None


def parse_wifi(raw: dict) -> dict:
    """{"aps": [{iface, ssid, freq, band, running}], "stations": [{iface, band, freq, signal}]}
    from MikrotikClient.get_wifi_overview(). Works for both stacks: the RouterOS
    7 "wifi" package (dotted keys such as "configuration.ssid" /
    "channel.frequency") and the legacy "wireless" one (flat "ssid" /
    "frequency" / "band"). Unverified against live devices — every field is
    read defensively, anything unrecognised just stays None."""
    flavor = raw.get("flavor")
    aps, by_iface = [], {}
    for r in raw.get("interfaces") or []:
        if not isinstance(r, dict) or _truthy(r.get("disabled")):
            continue
        name = r.get("name")
        if flavor == "wifi":
            mode = str(r.get("configuration.mode") or r.get("mode") or "ap").lower()
            ssid = r.get("configuration.ssid") or r.get("ssid")
            freq = _int_or_none(r.get("channel.frequency") or r.get("frequency"))
            band_s = r.get("channel.band") or r.get("configuration.band") or r.get("band")
            is_ap = mode == "ap"
        else:
            mode = str(r.get("mode") or "").lower()
            ssid = r.get("ssid")
            freq = _int_or_none(r.get("frequency"))
            band_s = r.get("band")
            is_ap = "ap" in mode or mode == "bridge"
        info = {"iface": name, "ssid": ssid, "freq": freq, "band": band_of(freq, band_s),
                "running": _truthy(r.get("running"))}
        by_iface[name] = info
        if is_ap and name:
            aps.append(info)

    stations = []
    for r in (raw.get("registrations") or [])[:_MAX_STATIONS_STORED]:
        if not isinstance(r, dict):
            continue
        ap = by_iface.get(r.get("interface")) or {}
        sig = r.get("signal") if r.get("signal") is not None else str(r.get("signal-strength") or "").split("@")[0]
        stations.append({"iface": r.get("interface"), "freq": ap.get("freq"),
                         "band": ap.get("band") or band_of(None, r.get("band")), "signal": _int_or_none(sig)})
    return {"aps": aps, "stations": stations}


# ── Collection ───────────────────────────────────────────────────────────────

async def _step(coro, default=None):
    try:
        return await asyncio.wait_for(coro, timeout=_STEP_TIMEOUT_SEC)
    except Exception:
        return default


async def collect_device(device_id: int) -> bool:
    """One device; never raises. False when the device couldn't be read at all."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential).join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return False
        device, cred = row
        try:
            client = build_client(device, cred)
        except Exception:
            return False
    if not isinstance(client, MikrotikClient):
        return False

    resource = await _step(client.get_resource(), {}) or {}
    packages = await _step(client.get_packages(), []) or []
    channel = await _step(client.get_update_channel())
    wifi_raw = await _step(client.get_wifi_overview(), {"flavor": None, "interfaces": [], "registrations": []})
    if not resource and not packages and channel is None:
        return False                      # nothing answered: keep everything as it was

    pkgs = [{"name": p.get("name"), "version": p.get("version"), "disabled": _truthy(p.get("disabled"))}
            for p in packages if isinstance(p, dict) and p.get("name")]
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        if not d:
            return False
        if resource.get("architecture-name"):
            d.architecture = str(resource["architecture-name"])
        up = parse_uptime(resource.get("uptime"))
        if up is not None:
            d.uptime_sec = up
        if pkgs:
            d.packages_json = json.dumps(pkgs)
        if channel:
            d.ros_channel = channel
        d.wifi_json = json.dumps(parse_wifi(wifi_raw or {}))
        d.fleet_checked_at = datetime.utcnow()
        db.commit()
    return True


async def refresh_all_devices() -> dict:
    global _refresh_running
    if _refresh_running:
        return {"skipped": True}
    _refresh_running = True
    try:
        with SessionLocal() as db:
            ids = [d.id for d in db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
                   if (d.vendor or "mikrotik").lower() == "mikrotik"]
        sem = asyncio.Semaphore(5)
        ok = 0

        async def _one(did):
            nonlocal ok
            async with sem:
                try:
                    ok += 1 if await collect_device(did) else 0
                except Exception as e:
                    print(f"[fleet] collect error for device {did}: {e}")
        await asyncio.gather(*[_one(i) for i in ids])
        return {"checked": ok, "total": len(ids)}
    finally:
        _refresh_running = False


def maybe_refresh_in_background() -> None:
    """Called when the overview is requested while some device has never been
    collected (fresh install / fresh upgrade) — start one background pass,
    at most once per few minutes so a page left open can't hammer the devices."""
    global _last_auto_refresh
    now = datetime.utcnow().timestamp()
    if _refresh_running or now - _last_auto_refresh < _AUTO_REFRESH_MIN_GAP_SEC:
        return
    _last_auto_refresh = now
    try:
        asyncio.get_event_loop().create_task(refresh_all_devices())
    except RuntimeError:
        pass


# ── Overview ─────────────────────────────────────────────────────────────────

def _device_alerts(d: Device) -> List[str]:
    keys = []
    if not d.online:
        keys.append("offline")
    if (d.ros_update_status or "").lower().startswith("new") and d.latest_ros_version:
        keys.append("update_available")
    if d.current_firmware and d.upgrade_firmware and d.current_firmware != d.upgrade_firmware:
        keys.append("firmware_outdated")
    if d.cpu_load_pct is not None and d.cpu_load_pct >= CPU_ALERT_PCT:
        keys.append("cpu_high")
    if d.mem_used_pct is not None and d.mem_used_pct >= rm.MEM_ALERT_PCT:
        keys.append("memory_high")
    if d.disk_used_pct is not None and d.disk_used_pct >= rm.DISK_ALERT_PCT:
        keys.append("disk_high")
    if d.temperature_c is not None and d.temperature_c >= rm.TEMP_ALERT_C:
        keys.append("temperature_high")
    return keys


_ALERT_DEFS = [   # (key, severity) in display order
    ("offline", "high"), ("cpu_high", "high"), ("memory_high", "high"), ("disk_high", "high"),
    ("temperature_high", "high"), ("update_available", "medium"), ("firmware_outdated", "medium"),
]


def _loads(text: Optional[str], default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def _aggregate_wifi(devices: List[dict]) -> dict:
    """AP / station counts per band and per channel (frequency) across the fleet."""
    by_band: Dict[str, dict] = {}
    by_channel: Dict[str, Dict[int, dict]] = {}
    aps_total = stations_total = 0
    for d in devices:
        w = d["wifi"]
        for ap in w.get("aps", []):
            aps_total += 1
            b = ap.get("band") or "?"
            by_band.setdefault(b, {"aps": 0, "stations": 0})["aps"] += 1
            if ap.get("freq"):
                by_channel.setdefault(b, {}).setdefault(ap["freq"], {"aps": 0, "stations": 0})["aps"] += 1
        for st in w.get("stations", []):
            stations_total += 1
            b = st.get("band") or "?"
            by_band.setdefault(b, {"aps": 0, "stations": 0})["stations"] += 1
            if st.get("freq"):
                by_channel.setdefault(b, {}).setdefault(st["freq"], {"aps": 0, "stations": 0})["stations"] += 1
    return {
        "aps_total": aps_total, "stations_total": stations_total, "by_band": by_band,
        "by_channel": {b: [{"freq": f, **c} for f, c in sorted(ch.items())] for b, ch in by_channel.items()},
    }


def build_overview(include_ip: bool = True, include_packages: bool = True) -> dict:
    """Pure database read. include_ip/include_packages=False gives the
    redacted shape used for Central."""
    with SessionLocal() as db:
        rows = [d for d in db.execute(select(Device).order_by(Device.identity, Device.ip)).scalars().all()
                if (d.vendor or "mikrotik").lower() == "mikrotik"]
    devices = []
    for d in rows:
        pkgs = _loads(d.packages_json, [])
        alert_keys = _device_alerts(d)
        dev = {
            "id": d.id, "name": d.identity or d.name or d.ip, "model": d.model, "board_name": d.board_name,
            "architecture": d.architecture, "ros_version": d.ros_version, "ros_channel": d.ros_channel,
            "latest_ros_version": d.latest_ros_version,
            "update_available": "update_available" in alert_keys,
            "firmware_current": d.current_firmware, "firmware_target": d.upgrade_firmware,
            "online": bool(d.online), "paired": d.credential_id is not None,
            "cpu": d.cpu_load_pct, "mem": d.mem_used_pct, "mem_total_bytes": d.mem_total_bytes,
            "disk": d.disk_used_pct, "disk_total_bytes": d.disk_total_bytes, "temperature": d.temperature_c,
            "uptime_sec": d.uptime_sec, "packages_count": len(pkgs),
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "resources_checked_at": d.last_resources_check_at.isoformat() if d.last_resources_check_at else None,
            "fleet_checked_at": d.fleet_checked_at.isoformat() if d.fleet_checked_at else None,
            "alerts": alert_keys, "wifi": _loads(d.wifi_json, {"aps": [], "stations": []}),
        }
        if include_ip:
            dev["ip"] = d.ip
        if include_packages:
            dev["packages"] = pkgs
        devices.append(dev)

    alerts = []
    for key, severity in _ALERT_DEFS:
        affected = [{"id": d["id"], "name": d["name"]} for d in devices if key in d["alerts"]]
        if affected:
            alerts.append({"key": key, "severity": severity, "count": len(affected),
                           "total": len(devices), "devices": affected})
    updates = [{"id": d["id"], "name": d["name"], "current": d["ros_version"], "latest": d["latest_ros_version"],
                "channel": d["ros_channel"]} for d in devices if d["update_available"]]
    wifi = _aggregate_wifi(devices)
    if not include_ip:                                   # keep Central's copy compact: counts only
        for d in devices:
            d["wifi"] = {"aps": len(d["wifi"].get("aps", [])), "stations": len(d["wifi"].get("stations", []))}
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "totals": {"devices": len(devices), "online": sum(1 for d in devices if d["online"]),
                   "paired": sum(1 for d in devices if d["paired"])},
        "devices": devices, "alerts": alerts, "updates": updates, "wifi": wifi,
        "never_collected": sum(1 for d in devices if d["paired"] and not d["fleet_checked_at"]),
    }


def public_summary() -> dict:
    """Redacted copy for the snapshot's plaintext envelope (Central): device
    names, models, versions and resource figures — no IP addresses, no package
    lists (counts only), Wi-Fi as counts."""
    o = build_overview(include_ip=False, include_packages=False)
    for a in o["alerts"]:
        a["devices"] = [d["name"] for d in a["devices"]]
    return o
