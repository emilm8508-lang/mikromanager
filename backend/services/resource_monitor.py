"""
Disk/memory/network-interface monitoring — three metrics, three host types:

  - Mikrotik devices: polled here directly (own connections, REST/API —
    cheap), on the SAME 2-minute cadence as edge_discovery/tunnel_monitor
    (called from uplink.py's _build_snapshot()). /system/resource already
    gets fetched elsewhere in the app (refresher.py, tunnel_monitor.py) but
    its memory/disk/cpu fields were always discarded — this is the first
    place that persists them. Interface rx/tx byte + error/drop counters
    come from MikrotikClient.get_interfaces() (/interface print), diffed
    against the previous sample (DeviceInterfaceStats) to get a Mbps rate
    and error/drop deltas — RouterOS doesn't report a live rate over
    REST/API the way "interface monitor-traffic" does interactively, so we
    compute it ourselves from two byte-counter samples.

  - Linux/Windows hosts: SSH/WinRM is much heavier than a REST call, so
    these are NOT re-checked every 2 minutes. services/linux_manage.py and
    services/windows_manage.py's own refresh_managed_hosts_resources()
    collect the raw disk/memory numbers on a much slower, independent
    schedule (this module's own loop, MIKROTIK_RESOURCE_CHECK_MIN, default
    30 min) and persist them to LinuxHost/WindowsHost/*Disk. This module's
    collect_resource_events() then just reads those already-persisted
    values every 2-minute snapshot cycle to decide whether a threshold was
    just crossed — cheap DB reads, no new SSH/WinRM connections on the fast
    path, so the "how often is the raw number refreshed" and "how often do
    we check for alert-worthy transitions" cadences are decoupled.

Threshold-crossing detection follows tunnel_monitor.py's pattern (state
persisted to a JSON file under data/, self-dedup, never pruned on a
transient miss) but with hysteresis instead of a simple boolean flip:
alerting starts at >= threshold, clears only once back below
threshold - HYSTERESIS_PCT, so a value oscillating right at the line
doesn't spam a fresh alert on every single poll.

Interface errors/drops use a cooldown instead of hysteresis (there's no
sensible "percent" to hysteresis around) — any new error/drop since the
last sample re-fires at most once per IFACE_ERROR_COOLDOWN_SEC.
"""
import asyncio
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
from services.device_client import build_client
from services.mikrotik_client import MikrotikClient
from services import activity

DISK_ALERT_PCT = float(os.environ.get("MIKROTIK_DISK_ALERT_PCT", "90"))
MEM_ALERT_PCT = float(os.environ.get("MIKROTIK_MEM_ALERT_PCT", "90"))
HYSTERESIS_PCT = float(os.environ.get("MIKROTIK_RESOURCE_ALERT_HYSTERESIS_PCT", "5"))
IFACE_ERROR_COOLDOWN_SEC = int(os.environ.get("MIKROTIK_IFACE_ERROR_COOLDOWN_SEC", "1800"))
# How often Linux/Windows hosts get a fresh SSH/WinRM disk+memory check —
# deliberately independent of (and much slower than) the 2-minute snapshot
# cadence used for the cheap Mikrotik REST poll and the alert-diff pass.
RESOURCE_CHECK_MIN = int(os.environ.get("MIKROTIK_RESOURCE_CHECK_MIN", "30"))

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "resource_state.json")

_loop_task: Optional[asyncio.Task] = None


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


async def _collect_mikrotik_events(state: dict) -> List[dict]:
    with SessionLocal() as db:
        devices = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        ids = [d.id for d in devices if (d.vendor or "mikrotik").lower() == "mikrotik"]

    sem = asyncio.Semaphore(5)

    async def _bounded(did):
        async with sem:
            try:
                return await _collect_device_resources(did)
            except Exception:
                return None

    results = await asyncio.gather(*[_bounded(i) for i in ids])

    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()
    for r in results:
        if not r:
            continue
        device_id, device_name = r["device_id"], r["device_name"]

        for metric, value, threshold, event_type in (
            ("mem", r["mem_used_pct"], MEM_ALERT_PCT, "memory_high"),
            ("disk", r["disk_used_pct"], DISK_ALERT_PCT, "disk_space_low"),
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

        for iface in r["iface_samples"]:
            if iface["errors_delta"] > 0:
                key = f"mikrotik:{device_id}:{iface['name']}:errors:ts"
                last_alert = state.get(key)
                if not last_alert or (time.time() - last_alert) > IFACE_ERROR_COOLDOWN_SEC:
                    events.append({
                        "type": "interface_errors", "device_id": device_id, "device_name": device_name,
                        "iface_name": iface["name"], "errors_delta": iface["errors_delta"],
                        "count": 1, "detected_at": now_iso,
                    })
                    try:
                        activity.record("interface_errors", device_name=device_name,
                                        iface_name=iface["name"], errors_delta=iface["errors_delta"])
                    except Exception as e:
                        print(f"[resource_monitor] activity record error: {e}")
                    state[key] = time.time()

            if r["iface_threshold"]:
                mbps = max(iface["rx_mbps"] or 0, iface["tx_mbps"] or 0)
                key = f"mikrotik:{device_id}:{iface['name']}:overload"
                # Reuse the same hysteresis helper with the Mbps threshold
                # itself as the "percent" scale — HYSTERESIS_PCT doesn't
                # apply in Mbps terms, so use a flat 10% margin instead.
                was_alerting = bool(state.get(key, False))
                crossed = None
                if not was_alerting and mbps >= r["iface_threshold"]:
                    state[key] = True
                    crossed = True
                elif was_alerting and mbps < r["iface_threshold"] * 0.9:
                    state[key] = False
                    crossed = False
                if crossed is True:
                    events.append({
                        "type": "interface_overload", "device_id": device_id, "device_name": device_name,
                        "iface_name": iface["name"], "mbps": mbps, "threshold_mbps": r["iface_threshold"],
                        "count": 1, "detected_at": now_iso,
                    })
                    try:
                        activity.record("interface_overload", device_name=device_name,
                                        iface_name=iface["name"], mbps=mbps, threshold_mbps=r["iface_threshold"])
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


async def collect_resource_events() -> List[dict]:
    """Called every snapshot cycle (~2 min) from uplink.py, same as
    edge_discovery/tunnel_monitor. Polls Mikrotik devices directly (cheap
    REST); for Linux/Windows just diffs whatever refresh_managed_hosts_
    resources() last wrote to the DB — no SSH/WinRM here."""
    state = _load_state()
    events = await _collect_mikrotik_events(state)
    events += _collect_linux_events(state)
    events += _collect_windows_events(state)
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


def start():
    global _loop_task
    if _loop_task is None or _loop_task.done():
        loop = asyncio.get_event_loop()
        _loop_task = loop.create_task(_refresh_loop())


def stop():
    global _loop_task
    if _loop_task and not _loop_task.done():
        _loop_task.cancel()
        _loop_task = None
