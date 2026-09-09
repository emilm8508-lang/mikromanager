"""
PRTG sensor problem monitoring — detects a sensor's status changing between
"ok" and "needs attention" (services/prtg_client.py's PROBLEM_STATUSES) and
reports it via alert_events, the same agent-detected-and-reported mechanism
already used for tunnel up/down (services/tunnel_monitor.py) and WAN link
status (services/edge_discovery.py) — rides the snapshot's existing
alert_events list into OVH's already-generic alerts_process() (ovh/
notifications.php), no new event-type allow-list to extend there, only a
new selectable option in the Central UI's alert-rule event-type dropdown.

State persistence pattern (per-sensor last-known bucket, self-dedup, never
pruned on a transient miss, full list scanned every cycle so a recovery is
detected too, not just a new problem) copied 1:1 from tunnel_monitor.py's
_TUNNEL_STATE_PATH/_load_state/_save_state/collect_tunnel_events — see that
module for the original reasoning, reproduced here verbatim.

Correlates each sensor's parent-device IP against our own Device/LinuxHost/
WindowsHost tables (same by-IP-dict pattern as services/inventory.py's
linux_by_ip/windows_by_ip) so an alert/summary shows a familiar local name
instead of only PRTG's own device label, when the IP happens to be a
already-known host.
"""
import json
import os
import time
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, LinuxHost, WindowsHost
from services import activity
from services import prtg_client

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "prtg_state.json")

# How often list_devices()+list_sensors() actually hit PRTG — collect_prtg_events()
# itself still runs every ~2 min uplink cycle, but only pays for a real HTTP
# round-trip once per this window. Same reasoning as tunnel_monitor.py's
# TUNNEL_CHECK_MIN: PRTG's own polling is already far more frequent than we
# need to re-check it here.
POLL_MIN = int(os.environ.get("MIKROTIK_PRTG_POLL_MIN", "5"))
_cache = {"data": None, "at": 0.0}


def _load_state() -> dict:
    if not os.path.exists(_STATE_PATH):
        return {}
    try:
        with open(_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
    try:
        with open(_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[prtg_monitor] state persist error: {e}")


def _resolve_local_name(ip: Optional[str]) -> Optional[str]:
    """Exactly inventory.py's linux_by_ip/windows_by_ip pattern, one lookup
    at a time (this runs at most once per problem sensor per cycle, not
    hot-path enough to warrant pre-building the dicts once). Returns a
    friendly local identity if the IP matches a known device, else None -
    the caller falls back to PRTG's own device name in that case."""
    if not ip:
        return None
    with SessionLocal() as db:
        d = db.execute(select(Device).where(Device.ip == ip)).scalar_one_or_none()
        if d:
            return d.identity or d.name or ip
        lh = db.execute(select(LinuxHost).where(LinuxHost.ip == ip)).scalar_one_or_none()
        if lh:
            return lh.hostname or ip
        wh = db.execute(select(WindowsHost).where(WindowsHost.ip == ip)).scalar_one_or_none()
        if wh:
            return wh.hostname or ip
    return None


async def _scan() -> Optional[List[dict]]:
    """TTL-cached (POLL_MIN minutes). Joins list_devices()+list_sensors()
    into one flat per-sensor list: {objid, sensor_name, prtg_device_name,
    ip, local_name, status, status_name, message}. Returns None (keeps the
    last good cache rather than an empty list) when PRTG isn't configured
    or a request failed this cycle - a transient API hiccup must never look
    like "everything's fine now", same principle as the WAN "running" field
    fix earlier in this project."""
    if not prtg_client.is_configured():
        return None
    now = time.time()
    if _cache["data"] is not None and (now - _cache["at"]) < POLL_MIN * 60:
        return _cache["data"]

    devices = await prtg_client.list_devices()
    sensors = await prtg_client.list_sensors()
    if devices is None or sensors is None:
        return _cache["data"]

    out = []
    for s in sensors:
        dev = devices.get(s["parentid"], {})
        ip = dev.get("host")
        out.append({
            "objid": s["objid"],
            "sensor_name": s.get("sensor") or "sensor",
            "prtg_device_name": dev.get("name") or "?",
            "ip": ip,
            "local_name": _resolve_local_name(ip),
            "status": s["status"],
            "status_name": prtg_client.STATUS_NAMES.get(s["status"], str(s["status"])),
            "message": s.get("message"),
        })
    _cache["data"] = out
    _cache["at"] = now
    return out


async def collect_prtg_events() -> List[dict]:
    """Compare each sensor's current problem/ok bucket against the last
    value persisted to disk, and emit prtg_sensor_down/prtg_sensor_up for
    any transition. Self-dedupes (new bucket saved immediately after
    comparison) and deliberately never prunes a sensor's entry just because
    this run's scan failed - same reasoning as
    tunnel_monitor.collect_tunnel_events()."""
    sensors = await _scan()
    if sensors is None:
        return []

    state = _load_state()
    events: List[dict] = []
    for s in sensors:
        key = f"sensor:{s['objid']}"
        bucket = "problem" if s["status"] in prtg_client.PROBLEM_STATUSES else "ok"
        prev = state.get(key)
        if prev is not None and prev != bucket:
            event_type = "prtg_sensor_down" if bucket == "problem" else "prtg_sensor_up"
            device_name = s["local_name"] or s["prtg_device_name"]
            events.append({
                "type": event_type,
                "device_name": device_name,
                "sensor_name": s["sensor_name"],
                "ip": s["ip"],
                "status_name": s["status_name"],
                "message": s.get("message"),
                "count": 1,
                "detected_at": datetime.utcnow().isoformat(),
            })
            try:
                activity.record(event_type, device_name=device_name,
                                 sensor_name=s["sensor_name"], status_name=s["status_name"])
            except Exception as e:
                print(f"[prtg_monitor] activity record error: {e}")
        state[key] = bucket

    _save_state(state)
    return events


def public_summary() -> List[dict]:
    """Redacted view for the snapshot's plaintext envelope, feeding
    Central's cross-tenant external-monitoring page — only sensors
    currently in a problem state (same "just what needs attention" cut as
    compliance.public_summary()), from the last cache populated by
    collect_prtg_events() this cycle (no extra network round-trip)."""
    sensors = _cache["data"] or []
    return [{
        "device_name": s["local_name"] or s["prtg_device_name"],
        "sensor_name": s["sensor_name"],
        "status_name": s["status_name"],
        "message": s.get("message"),
    } for s in sensors if s["status"] in prtg_client.PROBLEM_STATUSES]


async def collect_activity() -> None:
    """Pulls PRTG's own recent log (sensor status changes, user actions,
    system messages — prtg_client.list_messages()) into this agent's local
    Activity Log, so PRTG's own event history shows up in the same place
    as every other "what happened" entry (restarts, upgrades, backups),
    instead of being a second place to check. Deliberately separate from
    collect_prtg_events()/alert_events above — this is history, not
    alerting, so it never reaches Telegram (PRTG's own log routinely
    includes routine noise like "sensor paused by user" that shouldn't
    page anyone).

    Dedup by message objid (PRTG's own unique id for the log entry itself,
    not the related sensor/device) — the state's seen-set is REPLACED
    (not accumulated) with exactly this batch's ids each call, same
    reasoning as resource_monitor.py's _check_device_log_events(): PRTG's
    own log is itself a bounded/rolling window (we only ever fetch the
    most recent N), so this self-prunes with no manual cleanup needed."""
    if not prtg_client.is_configured():
        return
    messages = await prtg_client.list_messages(count=50)
    if messages is None:
        return

    state = _load_state()
    prev_seen = set(state.get("_activity_seen") or [])
    current_seen = set()

    for m in messages:
        current_seen.add(m["objid"])
        if m["objid"] in prev_seen:
            continue
        when = None
        try:
            raw = float(m.get("datetime_raw"))
            when = (datetime(1899, 12, 30) + timedelta(days=raw)).isoformat()
        except (TypeError, ValueError):
            pass
        try:
            activity.record(
                "prtg_activity", prtg_type=m.get("type"), name=m.get("name"),
                status=m.get("status"), message=m.get("message"), event_time=when,
            )
        except Exception as e:
            print(f"[prtg_monitor] activity record error: {e}")

    state["_activity_seen"] = list(current_seen)
    _save_state(state)
