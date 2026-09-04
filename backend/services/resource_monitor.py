"""
Disk/memory/network-interface monitoring — three metrics, three host types,
ALL now decoupled the same way: a slow, independent loop does the actual
live poll (REST/API/SSH/WinRM) and persists raw numbers; the fast
2-minute collect_resource_events() (called from uplink.py's
_build_snapshot(), same cadence as edge_discovery/tunnel_monitor) only
ever reads whatever was last persisted and checks it against a threshold —
cheap DB reads, no new device connections on the fast path.

  - Mikrotik devices: used to be live-polled every single 2-minute
    snapshot cycle (30x/hour per router) — confirmed by the user as
    excessive ("urządzenia sieciowe skanowane zbyt często"). The actual
    REST/API poll (_poll_mikrotik_devices, /system/resource +
    /interface print) now runs on its own slow loop
    (DEVICE_RESOURCE_CHECK_MIN, default 60 min — "raz na godzinę" per
    the user's explicit ask), persisting to Device.mem_used_pct/
    disk_used_pct/cpu_load_pct and DeviceInterfaceStats (rx/tx byte +
    error counters, Mbps rate computed from the delta between two
    successive HOURLY samples now rather than two 2-minute samples —
    still a meaningful sustained-load signal, arguably less noisy).
    _check_mikrotik_events() then just diffs those persisted values
    every 2-minute cycle, mirroring _collect_linux_events/
    _collect_windows_events below exactly.

  - Linux/Windows hosts: SSH/WinRM is much heavier than a REST call, so
    these were already NOT re-checked every 2 minutes. services/
    linux_manage.py and services/windows_manage.py's own
    refresh_managed_hosts_resources() collect the raw disk/memory
    numbers on their own slow, independent schedule (MIKROTIK_
    RESOURCE_CHECK_MIN, default 30 min — deliberately left as-is, the
    user's complaint was specifically about network devices) and persist
    them to LinuxHost/WindowsHost/*Disk.

Threshold-crossing detection follows tunnel_monitor.py's pattern (state
persisted to a JSON file under data/, self-dedup, never pruned on a
transient miss) but with hysteresis instead of a simple boolean flip:
alerting starts at >= threshold, clears only once back below
threshold - HYSTERESIS_PCT, so a value oscillating right at the line
doesn't spam a fresh alert on every single poll.

Interface errors/drops use a cooldown instead of hysteresis (there's no
sensible "percent" to hysteresis around) — any new error/drop since the
last CHECK re-fires at most once per IFACE_ERROR_COOLDOWN_SEC.
"""
import asyncio
import hashlib
import json
import os
import time
from datetime import datetime
from typing import List, Optional
from sqlalchemy import select

from models.database import (
    SessionLocal, Device, Credential, DeviceInterfaceStats,
    LinuxHost, LinuxHostDisk, WindowsHost, WindowsHostDisk,
)
from services.crypto import decrypt
from services.device_client import build_client
from services.mikrotik_client import MikrotikClient
from services import activity

DISK_ALERT_PCT = float(os.environ.get("MIKROTIK_DISK_ALERT_PCT", "90"))
MEM_ALERT_PCT = float(os.environ.get("MIKROTIK_MEM_ALERT_PCT", "90"))
HYSTERESIS_PCT = float(os.environ.get("MIKROTIK_RESOURCE_ALERT_HYSTERESIS_PCT", "5"))
IFACE_ERROR_COOLDOWN_SEC = int(os.environ.get("MIKROTIK_IFACE_ERROR_COOLDOWN_SEC", "1800"))
# How often Linux/Windows hosts get a fresh SSH/WinRM disk+memory check —
# deliberately independent of (and much slower than) the 2-minute snapshot
# cadence used for the cheap alert-diff pass.
RESOURCE_CHECK_MIN = int(os.environ.get("MIKROTIK_RESOURCE_CHECK_MIN", "30"))
# How often Mikrotik devices get a fresh REST/API resource+interface poll —
# separate from RESOURCE_CHECK_MIN above (Linux/Windows) since the user's
# complaint was specifically about network devices being polled too often;
# default 60 = "raz na godzinę" (once an hour), down from every 2 minutes.
DEVICE_RESOURCE_CHECK_MIN = int(os.environ.get("MIKROTIK_DEVICE_RESOURCE_CHECK_MIN", "60"))

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "resource_state.json")
# Separate file from resource_state.json above — deliberately NOT shared.
# The hourly Mikrotik poll (_poll_mikrotik_devices) does real network I/O
# across many devices and can span minutes; the 2-minute fast cycle
# (collect_resource_events) also loads/saves resource_state.json during
# that same window. If the log-dedup state lived in that same file, the
# hourly poll's own load-early/save-late pattern would clobber whatever
# the fast cycle wrote in between (classic read-modify-write race across
# awaits) — a dedicated file sidesteps that entirely rather than needing
# any locking.
_LOG_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "device_log_state.json")

_loop_task: Optional[asyncio.Task] = None
# Critical/error log events found during the hourly Mikrotik poll, drained
# by the next 2-minute collect_resource_events() call — the poll itself
# already knows (at fetch time, comparing against _LOG_STATE_PATH) which
# entries are genuinely new, so there's nothing left for the fast cycle to
# compute; it just needs to report them within ~2 minutes of detection,
# matching the responsiveness other alert_events already have.
_pending_log_events: List[dict] = []


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
        print(f"[resource_monitor] state persist error: {e}")


def _load_log_state() -> dict:
    if not os.path.exists(_LOG_STATE_PATH):
        return {}
    try:
        with open(_LOG_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_log_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_LOG_STATE_PATH), exist_ok=True)
    try:
        with open(_LOG_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[resource_monitor] log state persist error: {e}")


def _check_pct_threshold(state: dict, key: str, value: Optional[float], threshold: float) -> Optional[bool]:
    """Hysteresis threshold check against a boolean flag stored in state[key].
    Returns True the moment value crosses INTO alert (caller should emit an
    event), False the moment it drops back out (caller just clears, no
    event), None otherwise (no transition — most calls, most of the time)."""
    if value is None:
        return None
    was_alerting = bool(state.get(key, False))
    if not was_alerting and value >= threshold:
        state[key] = True
        return True
    if was_alerting and value < threshold - HYSTERESIS_PCT:
        state[key] = False
        return False
    return None


# ── Mikrotik: resource + interface polling (own connections, cheap REST) ──

def _pct(used: Optional[float], total: Optional[float]) -> Optional[float]:
    try:
        used, total = float(used), float(total)
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None
    return round(used / total * 100, 1)


async def _collect_device_resources(device_id: int) -> Optional[dict]:
    """One device: fetch /system/resource + /interface, persist, return a
    dict the caller uses to run threshold checks. None on total failure
    (device unreachable this cycle) — never raises, mirrors
    tunnel_monitor._collect_device_tunnels's per-device error isolation."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return None
        device, cred = row
        iface_threshold = device.iface_mbps_threshold

    client = build_client(device, cred)
    if not isinstance(client, MikrotikClient):
        return None

    device_name = device.identity or device.name or device.ip

    try:
        resource = await asyncio.wait_for(client.get_resource(), timeout=8)
    except Exception:
        resource = {}

    mem_total = resource.get("total-memory")
    mem_free = resource.get("free-memory")
    mem_used_pct = None
    if mem_total is not None and mem_free is not None:
        try:
            mem_used_pct = _pct(float(mem_total) - float(mem_free), mem_total)
        except (TypeError, ValueError):
            mem_used_pct = None

    disk_total = resource.get("total-hdd-space")
    disk_free = resource.get("free-hdd-space")
    disk_used_pct = None
    if disk_total is not None and disk_free is not None:
        try:
            disk_used_pct = _pct(float(disk_total) - float(disk_free), disk_total)
        except (TypeError, ValueError):
            disk_used_pct = None

    cpu_load = resource.get("cpu-load")
    try:
        cpu_load = int(cpu_load) if cpu_load is not None else None
    except (TypeError, ValueError):
        cpu_load = None

    now = datetime.utcnow()
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        if d:
            if mem_used_pct is not None:
                d.mem_used_pct = mem_used_pct
            if disk_used_pct is not None:
                d.disk_used_pct = disk_used_pct
            if cpu_load is not None:
                d.cpu_load_pct = cpu_load
            d.last_resources_check_at = now
            db.commit()

    # Interfaces — rx/tx byte + error/drop counters, diffed against the
    # previous sample to get a Mbps rate and error/drop deltas. A device
    # reachable for /system/resource but not /interface (unlikely, but
    # defensive) still reports its mem/disk/cpu above.
    iface_samples = []
    try:
        interfaces = await asyncio.wait_for(client.get_interfaces(), timeout=8)
    except Exception:
        interfaces = []

    with SessionLocal() as db:
        prev_rows = {
            r.iface_name: r for r in db.execute(
                select(DeviceInterfaceStats).where(DeviceInterfaceStats.device_id == device_id)
            ).scalars().all()
        }
        for iface in interfaces or []:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name")
            if not name or str(iface.get("disabled", "false")).lower() in ("true", "yes"):
                continue

            def _int_or_none(v):
                try:
                    return int(v) if v is not None else None
                except (TypeError, ValueError):
                    return None

            rx_bytes = _int_or_none(iface.get("rx-byte"))
            tx_bytes = _int_or_none(iface.get("tx-byte"))
            rx_errors = _int_or_none(iface.get("rx-error"))
            tx_errors = _int_or_none(iface.get("tx-error"))
            rx_drops = _int_or_none(iface.get("rx-drop"))
            tx_drops = _int_or_none(iface.get("tx-drop"))

            prev = prev_rows.get(name)
            rx_mbps = tx_mbps = None
            errors_delta = 0
            if prev and prev.last_sample_at:
                dt = (now - prev.last_sample_at).total_seconds()
                # A smaller-than-before counter means the device rebooted
                # (or the interface was reset) — treat as a fresh baseline,
                # never compute a nonsense rate/delta off a counter wrap.
                if dt > 0 and rx_bytes is not None and prev.rx_bytes is not None and rx_bytes >= prev.rx_bytes:
                    rx_mbps = round((rx_bytes - prev.rx_bytes) * 8 / dt / 1_000_000, 2)
                if dt > 0 and tx_bytes is not None and prev.tx_bytes is not None and tx_bytes >= prev.tx_bytes:
                    tx_mbps = round((tx_bytes - prev.tx_bytes) * 8 / dt / 1_000_000, 2)
                for cur, old in (
                    (rx_errors, prev.rx_errors), (tx_errors, prev.tx_errors),
                    (rx_drops, prev.rx_drops), (tx_drops, prev.tx_drops),
                ):
                    if cur is not None and old is not None and cur >= old:
                        errors_delta += cur - old

            row = prev or DeviceInterfaceStats(device_id=device_id, iface_name=name)
            row.rx_bytes, row.tx_bytes = rx_bytes, tx_bytes
            row.rx_errors, row.tx_errors = rx_errors, tx_errors
            row.rx_drops, row.tx_drops = rx_drops, tx_drops
            row.rx_mbps, row.tx_mbps = rx_mbps, tx_mbps
            row.last_sample_at = now
            if not prev:
                db.add(row)

            iface_samples.append({
                "name": name, "rx_mbps": rx_mbps, "tx_mbps": tx_mbps,
                "errors_delta": errors_delta,
            })
        db.commit()

    return {
        "device_id": device_id, "device_name": device_name,
        "mem_used_pct": mem_used_pct, "disk_used_pct": disk_used_pct,
        "iface_threshold": iface_threshold, "iface_samples": iface_samples,
    }


def _check_device_log_events(log_state: dict, device_id: int, device_name: str, logs: list) -> List[dict]:
    """Filters raw log entries (from MikrotikClient.get_logs()) down to
    CRITICAL/error severity, and dedups against what was already reported
    last poll — RouterOS's own log buffer is a ring buffer that keeps old
    entries until they roll off, so re-reading it every poll without dedup
    would re-alert on the SAME old entry forever. Dedup key is a hash of
    (time, message): a genuinely repeated error (e.g. a flapping link)
    gets a fresh time each real occurrence and still fires each time; the
    exact same still-buffered entry read again next poll does not.
    log_state[device_key] is REPLACED (not accumulated) with this poll's
    signatures each call — matches the device's own buffer, so an entry
    that ages out of the real buffer naturally stops being "seen" too,
    no manual pruning needed."""
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()
    state_key = f"mikrotik:{device_id}:log_sigs"
    prev_seen = set(log_state.get(state_key) or [])
    current_seen = set()
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        topics = (entry.get("topics") or "").lower()
        if "critical" not in topics and "error" not in topics:
            continue
        sig = hashlib.sha1(
            f"{entry.get('time')}|{entry.get('message')}".encode("utf-8", errors="ignore")
        ).hexdigest()
        current_seen.add(sig)
        if sig in prev_seen:
            continue
        events.append({
            "type": "device_log_critical", "device_id": device_id, "device_name": device_name,
            "severity": "critical" if "critical" in topics else "error",
            "topics": entry.get("topics"), "message": entry.get("message"),
            "log_time": entry.get("time"), "count": 1, "detected_at": now_iso,
        })
        try:
            activity.record("device_log_critical", device_name=device_name,
                            topics=entry.get("topics"), message=entry.get("message"))
        except Exception as e:
            print(f"[resource_monitor] activity record error: {e}")
    log_state[state_key] = list(current_seen)
    return events


async def _poll_device_logs(device_id: int, log_state: dict) -> List[dict]:
    """One device's log fetch — same client/get_logs()/topic-filter shape
    as backend/api/system.py's get_critical_logs() (that endpoint stays
    as-is for the live on-demand dashboard view), but persisted+deduped
    here instead of just returned fresh for whoever happens to be
    looking. Per the user's explicit ask: errors/criticals should be
    surfaced automatically as agent info -> Central, not only when
    someone opens the local dashboard."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return []
        device, cred = row

    try:
        client = MikrotikClient(
            device.ip, cred.username, decrypt(cred.password_enc),
            api_port=device.api_port, web_port=device.web_port,
            snmp_community=decrypt(cred.snmp_community_enc) if cred.snmp_community_enc else None,
            snmp_port=device.snmp_port or 161,
        )
        logs = await asyncio.wait_for(client.get_logs(limit=200), timeout=8)
    except Exception:
        return []

    device_name = device.identity or device.name or device.ip
    return _check_device_log_events(log_state, device_id, device_name, logs)


async def _poll_mikrotik_devices() -> None:
    """The actual live REST/API poll (mem/disk/cpu + interface byte
    counters, PLUS critical/error log entries) for every credentialed
    Mikrotik device — runs on its own slow, independent schedule
    (DEVICE_RESOURCE_CHECK_MIN, default 60 min) instead of every 2-minute
    snapshot cycle. Resource numbers persist via _collect_device_resources
    (Device.mem_used_pct/disk_used_pct/cpu_load_pct, DeviceInterfaceStats);
    _check_mikrotik_events() below reads those on the fast cycle instead
    of connecting to devices itself. New critical/error log entries are
    appended to _pending_log_events, drained by the very next
    collect_resource_events() call (within ~2 min of this poll finishing)."""
    with SessionLocal() as db:
        devices = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        ids = [d.id for d in devices if (d.vendor or "mikrotik").lower() == "mikrotik"]

    sem = asyncio.Semaphore(5)
    log_state = _load_log_state()

    async def _bounded(did):
        async with sem:
            try:
                await _collect_device_resources(did)
            except Exception as e:
                print(f"[resource_monitor] mikrotik poll error for device {did}: {e}")
            try:
                events = await _poll_device_logs(did, log_state)
                if events:
                    _pending_log_events.extend(events)
            except Exception as e:
                print(f"[resource_monitor] log poll error for device {did}: {e}")

    await asyncio.gather(*[_bounded(i) for i in ids])
    _save_log_state(log_state)


def _check_mikrotik_events(state: dict) -> List[dict]:
    """Cheap DB-only check for Mikrotik devices — reads whatever
    _poll_mikrotik_devices() last persisted, no new device connections
    here. Mirrors _collect_linux_events/_collect_windows_events below
    exactly. Interface error counters are cumulative on the device, so
    the delta is computed against the value THIS function itself last
    saw (stored in `state`), independent of the poll's own internal
    diffing (which only computes the Mbps rate, not an error delta)."""
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()
    with SessionLocal() as db:
        devices = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        mikrotik_devices = [d for d in devices if (d.vendor or "mikrotik").lower() == "mikrotik"]
        device_ids = [d.id for d in mikrotik_devices]
        iface_by_device: dict = {}
        if device_ids:
            for r in db.execute(
                select(DeviceInterfaceStats).where(DeviceInterfaceStats.device_id.in_(device_ids))
            ).scalars().all():
                iface_by_device.setdefault(r.device_id, []).append(r)

        for d in mikrotik_devices:
            device_id = d.id
            device_name = d.identity or d.name or d.ip
            iface_threshold = d.iface_mbps_threshold

            for metric, value, threshold, event_type in (
                ("mem", d.mem_used_pct, MEM_ALERT_PCT, "memory_high"),
                ("disk", d.disk_used_pct, DISK_ALERT_PCT, "disk_space_low"),
            ):
                key = f"mikrotik:{device_id}:{metric}"
                crossed = _check_pct_threshold(state, key, value, threshold)
                if crossed is True:
                    events.append({
                        "type": event_type, "device_id": device_id, "device_name": device_name,
                        "value_pct": value, "count": 1, "detected_at": now_iso,
                    })
                    try:
                        activity.record(event_type, device_name=device_name, value_pct=value)
                    except Exception as e:
                        print(f"[resource_monitor] activity record error: {e}")

            for row in iface_by_device.get(device_id, []):
                for cur, suffix in ((row.rx_errors, "rx"), (row.tx_errors, "tx")):
                    if cur is None:
                        continue
                    cum_key = f"mikrotik:{device_id}:{row.iface_name}:errors:{suffix}"
                    prev_cum = state.get(cum_key)
                    state[cum_key] = cur
                    if prev_cum is None or cur < prev_cum:
                        continue  # first observation, or counter reset/reboot
                    delta = cur - prev_cum
                    if delta <= 0:
                        continue
                    ts_key = f"mikrotik:{device_id}:{row.iface_name}:errors:ts"
                    last_alert = state.get(ts_key)
                    if not last_alert or (time.time() - last_alert) > IFACE_ERROR_COOLDOWN_SEC:
                        events.append({
                            "type": "interface_errors", "device_id": device_id, "device_name": device_name,
                            "iface_name": row.iface_name, "errors_delta": delta,
                            "count": 1, "detected_at": now_iso,
                        })
                        try:
                            activity.record("interface_errors", device_name=device_name,
                                            iface_name=row.iface_name, errors_delta=delta)
                        except Exception as e:
                            print(f"[resource_monitor] activity record error: {e}")
                        state[ts_key] = time.time()

                if iface_threshold:
                    mbps = max(row.rx_mbps or 0, row.tx_mbps or 0)
                    key = f"mikrotik:{device_id}:{row.iface_name}:overload"
                    # Reuse the same hysteresis helper with the Mbps threshold
                    # itself as the "percent" scale — HYSTERESIS_PCT doesn't
                    # apply in Mbps terms, so use a flat 10% margin instead.
                    was_alerting = bool(state.get(key, False))
                    crossed = None
                    if not was_alerting and mbps >= iface_threshold:
                        state[key] = True
                        crossed = True
                    elif was_alerting and mbps < iface_threshold * 0.9:
                        state[key] = False
                        crossed = False
                    if crossed is True:
                        events.append({
                            "type": "interface_overload", "device_id": device_id, "device_name": device_name,
                            "iface_name": row.iface_name, "mbps": mbps, "threshold_mbps": iface_threshold,
                            "count": 1, "detected_at": now_iso,
                        })
                        try:
                            activity.record("interface_overload", device_name=device_name,
                                            iface_name=row.iface_name, mbps=mbps, threshold_mbps=iface_threshold)
                        except Exception as e:
                            print(f"[resource_monitor] activity record error: {e}")

    return events


# ── Linux/Windows: diff already-persisted values, no new connections here ──

def _collect_linux_events(state: dict) -> List[dict]:
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()
    with SessionLocal() as db:
        hosts = db.execute(select(LinuxHost).where(LinuxHost.managed == True)).scalars().all()  # noqa: E712
        for h in hosts:
            identity = h.hostname or h.ip
            key = f"linux:{h.id}:mem"
            crossed = _check_pct_threshold(state, key, h.mem_used_pct, MEM_ALERT_PCT)
            if crossed is True:
                events.append({
                    "type": "memory_high", "host_type": "linux", "host_id": h.id, "ip": h.ip,
                    "hostname": identity, "value_pct": h.mem_used_pct, "count": 1, "detected_at": now_iso,
                })
                try:
                    activity.record("memory_high", host_type="linux", ip=h.ip, hostname=identity,
                                    value_pct=h.mem_used_pct)
                except Exception as e:
                    print(f"[resource_monitor] activity record error: {e}")

            disks = db.execute(select(LinuxHostDisk).where(LinuxHostDisk.host_id == h.id)).scalars().all()
            for d in disks:
                key = f"linux:{h.id}:disk:{d.mount_point}"
                crossed = _check_pct_threshold(state, key, d.pct, DISK_ALERT_PCT)
                if crossed is True:
                    events.append({
                        "type": "disk_space_low", "host_type": "linux", "host_id": h.id, "ip": h.ip,
                        "hostname": identity, "mount": d.mount_point, "value_pct": d.pct,
                        "count": 1, "detected_at": now_iso,
                    })
                    try:
                        activity.record("disk_space_low", host_type="linux", ip=h.ip, hostname=identity,
                                        mount=d.mount_point, value_pct=d.pct)
                    except Exception as e:
                        print(f"[resource_monitor] activity record error: {e}")
    return events


def _collect_windows_events(state: dict) -> List[dict]:
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()
    with SessionLocal() as db:
        hosts = db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all()  # noqa: E712
        for h in hosts:
            identity = h.hostname or h.ip
            key = f"windows:{h.id}:mem"
            crossed = _check_pct_threshold(state, key, h.mem_used_pct, MEM_ALERT_PCT)
            if crossed is True:
                events.append({
                    "type": "memory_high", "host_type": "windows", "host_id": h.id, "ip": h.ip,
                    "hostname": identity, "value_pct": h.mem_used_pct, "count": 1, "detected_at": now_iso,
                })
                try:
                    activity.record("memory_high", host_type="windows", ip=h.ip, hostname=identity,
                                    value_pct=h.mem_used_pct)
                except Exception as e:
                    print(f"[resource_monitor] activity record error: {e}")

            disks = db.execute(select(WindowsHostDisk).where(WindowsHostDisk.host_id == h.id)).scalars().all()
            for d in disks:
                key = f"windows:{h.id}:disk:{d.drive_letter}"
                crossed = _check_pct_threshold(state, key, d.pct, DISK_ALERT_PCT)
                if crossed is True:
                    events.append({
                        "type": "disk_space_low", "host_type": "windows", "host_id": h.id, "ip": h.ip,
                        "hostname": identity, "mount": d.drive_letter, "value_pct": d.pct,
                        "count": 1, "detected_at": now_iso,
                    })
                    try:
                        activity.record("disk_space_low", host_type="windows", ip=h.ip, hostname=identity,
                                        mount=d.drive_letter, value_pct=d.pct)
                    except Exception as e:
                        print(f"[resource_monitor] activity record error: {e}")
    return events


def _drain_pending_log_events() -> List[dict]:
    """Pops whatever critical/error log events the hourly Mikrotik poll
    has found since the last drain — see _pending_log_events' own
    docstring for why this is a simple in-process buffer rather than
    another state file (the poll already did the dedup work at fetch
    time; this just hands off what it found to the next snapshot)."""
    global _pending_log_events
    events = _pending_log_events
    _pending_log_events = []
    return events


async def collect_resource_events() -> List[dict]:
    """Called every snapshot cycle (~2 min) from uplink.py, same as
    edge_discovery/tunnel_monitor. Cheap DB-only diff for all three host
    types now — Mikrotik included — no live device connections on this
    fast path; the actual polls run on their own slow, independent loops
    (see _mikrotik_refresh_loop / _refresh_loop below). Also drains any
    critical/error device log events the hourly Mikrotik poll found."""
    state = _load_state()
    events = _check_mikrotik_events(state)
    events += _collect_linux_events(state)
    events += _collect_windows_events(state)
    events += _drain_pending_log_events()
    _save_state(state)
    return events


# ── Slow, independent loop: SSH/WinRM disk+memory refresh for managed hosts ─

async def _refresh_loop():
    # First run shortly after startup (not immediately — mirrors refresher.
    # py's FIRST_RUN_DELAY_SEC reasoning: keep boot fast, but don't leave
    # a freshly (re)started agent with no resource data for a full
    # RESOURCE_CHECK_MIN either).
    delay = 60
    while True:
        try:
            await asyncio.sleep(delay)
            delay = RESOURCE_CHECK_MIN * 60
            from services import linux_manage, windows_manage
            try:
                await linux_manage.refresh_managed_hosts_resources()
            except Exception as e:
                print(f"[resource_monitor] linux refresh error: {e}")
            try:
                await windows_manage.refresh_managed_hosts_resources()
            except Exception as e:
                print(f"[resource_monitor] windows refresh error: {e}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[resource_monitor] refresh loop error: {e}")


# ── Slow, independent loop: Mikrotik REST/API resource+interface poll ──────

async def _mikrotik_refresh_loop():
    # Own schedule, separate from Linux/Windows above — see
    # DEVICE_RESOURCE_CHECK_MIN's docstring for why they're decoupled.
    delay = 60
    while True:
        try:
            await asyncio.sleep(delay)
            delay = DEVICE_RESOURCE_CHECK_MIN * 60
            await _poll_mikrotik_devices()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[resource_monitor] mikrotik refresh loop error: {e}")


_mikrotik_loop_task: Optional[asyncio.Task] = None


def start():
    global _loop_task, _mikrotik_loop_task
    if _loop_task is None or _loop_task.done():
        loop = asyncio.get_event_loop()
        _loop_task = loop.create_task(_refresh_loop())
    if _mikrotik_loop_task is None or _mikrotik_loop_task.done():
        loop = asyncio.get_event_loop()
        _mikrotik_loop_task = loop.create_task(_mikrotik_refresh_loop())


def stop():
    global _loop_task, _mikrotik_loop_task
    if _loop_task and not _loop_task.done():
        _loop_task.cancel()
        _loop_task = None
    if _mikrotik_loop_task and not _mikrotik_loop_task.done():
        _mikrotik_loop_task.cancel()
        _mikrotik_loop_task = None
