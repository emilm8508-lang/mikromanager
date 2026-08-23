"""
Periodic device checks — split into two independent cadences:

  1. Lightweight liveness ping (PING_INTERVAL_MIN, default 5) — a bare TCP
     connect probe against the device's own configured ports. No
     authentication involved, so it never shows up in the device's own
     admin log (RouterOS only logs authenticated login/logout, not a raw
     TCP SYN probe). Keeps online/offline status fresh with zero log noise.

  2. Full enrichment (INTERVAL_MIN, default 1440 = once a day) —
     authenticated REST/API/SNMP calls to update identity/model/ROS
     version, plus topology rediscovery. This is what actually logs
     in/out on the device, so it deliberately runs far less often than
     the ping.

Both run as asyncio tasks started from FastAPI lifespan. State is held in
module-level globals so /api/system endpoints can report progress.
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
_full_task: Optional[asyncio.Task] = None

_last_ping: Optional[datetime] = None
_ping_task: Optional[asyncio.Task] = None

# Full, authenticated enrichment — identity/model/ROS version + topology.
# Defaults to once a day; the lightweight ping (below) keeps online/offline
# fresh in between without touching the device's own auth log.
INTERVAL_MIN = int(os.environ.get("MIKROTIK_REFRESH_MIN", "1440"))
# Bare TCP-connect liveness probe — cheap, unauthenticated, no log entries.
PING_INTERVAL_MIN = int(os.environ.get("MIKROTIK_PING_MIN", "5"))
# Delay before the FIRST enrichment run after a (re)start — short, not a
# full INTERVAL_MIN, so app boot still stays fast but an agent that restarts
# at least once a day (e.g. the daily auto-update) doesn't have this reset
# every time and end up never completing a single enrichment run.
FIRST_RUN_DELAY_SEC = int(os.environ.get("MIKROTIK_REFRESH_FIRST_DELAY_SEC", "300"))


def status() -> dict:
    return {
        "interval_min": INTERVAL_MIN,
        "ping_interval_min": PING_INTERVAL_MIN,
        "in_progress": _in_progress,
        "last_run": _last_run.isoformat() if _last_run else None,
        "last_ping": _last_ping.isoformat() if _last_ping else None,
        "last_duration_sec": round(_last_duration_sec, 1) if _last_duration_sec else None,
        "devices_checked_last": _devices_checked,
        "devices_updated_last": _devices_updated,
        "next_run_estimated": (
            _last_run.timestamp() + INTERVAL_MIN * 60 if _last_run else None
        ),
    }


# ── 1. Lightweight liveness ping (no auth, no device-side log entry) ────────

async def _ping_one(dev_id: int) -> None:
    with SessionLocal() as db:
        device = db.execute(select(Device).where(Device.id == dev_id)).scalar_one_or_none()
        if not device:
            return
        ip = device.ip
        # Winbox (8291) is always worth trying in addition to whatever's
        # configured — api_port defaults to 8728 in the DB regardless of
        # whether the API service is actually enabled, so `ports` was
        # effectively never empty and the (8728, 80, 22, 443) fallback
        # below never ran in practice. A router deliberately hardened to
        # Winbox+SNMP-only management (API/web/SSH all disabled) was
        # therefore always reported "offline" here despite being perfectly
        # reachable — confirmed on a real device (CCR2004, SNMP-only badge,
        # manageable via Winbox, shown "Offline" in the Devices list).
        ports = {8291}
        for p in (device.api_port, device.web_port, device.ssh_port):
            if p:
                ports.add(p)

    online_now = False
    for port in ports:
        if await scan_svc._tcp_open(ip, port):
            online_now = True
            break

    with SessionLocal() as db:
        device = db.execute(select(Device).where(Device.id == dev_id)).scalar_one_or_none()
        if not device:
            return
        device.online = online_now
        device.last_seen = datetime.utcnow()
        db.commit()


async def ping_all_devices() -> None:
    """Bare liveness probe across every device. Cheap enough to run at a
    much tighter interval than the full authenticated enrichment."""
    global _last_ping

    with SessionLocal() as db:
        ids = [d.id for d in db.execute(select(Device.id)).all()]

    sem = asyncio.Semaphore(20)

    async def _bounded(did):
        async with sem:
            try:
                await _ping_one(did)
            except Exception:
                pass

    await asyncio.gather(*(_bounded(i) for i in ids))
    _last_ping = datetime.utcnow()


# ── 2. Full, authenticated enrichment (identity/model/version + topology) ──

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

    if (username and password) or community:
        # Full enrichment via REST → API → SNMP fallback (Mikrotik) or pure SNMP (Cisco)
        try:
            with SessionLocal() as db2:
                dev_row = db2.execute(select(Device).where(Device.id == dev_id)).scalar_one_or_none()
            vendor = (dev_row.vendor if dev_row else "mikrotik") or "mikrotik"

            if vendor == "cisco-sb":
                # Cisco SB — direct via CiscoClient (SNMP-only)
                from services.cisco_client import CiscoClient
                client = CiscoClient(
                    ip=ip, username=username or "", password=password or "",
                    snmp_community=community, snmp_port=snmp_port,
                    web_port=web_port,
                )
                info = {}
                try:
                    ident = await client.get_identity()
                    info["identity"] = ident.get("name", "")
                except Exception:
                    pass
                try:
                    res = await client.get_resource()
                    info["model"] = res.get("board-name", "")
                    info["ros_version"] = res.get("version", "")
                except Exception:
                    pass
            else:
                info = await scan_svc.enrich_device(
                    ip, username or "", password or "",
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
                if info.get("board_name"):
                    new_fields["board_name"] = info["board_name"]
                # These can legitimately be "" (e.g. upgrade_firmware empty
                # when already current) so persist whenever the key is
                # present at all, not just when truthy like the fields above.
                if "current_firmware" in info:
                    new_fields["current_firmware"] = info["current_firmware"]
                if "upgrade_firmware" in info:
                    new_fields["upgrade_firmware"] = info["upgrade_firmware"]
                if "latest_ros_version" in info:
                    new_fields["latest_ros_version"] = info["latest_ros_version"]
                if "ros_update_status" in info:
                    new_fields["ros_update_status"] = info["ros_update_status"]
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


async def _ping_loop():
    """Frequent, unauthenticated liveness loop. Pings immediately on
    startup, THEN sleeps — not sleep-then-ping — so a restart (routine,
    or the daily self-update) doesn't leave online/offline stuck on
    stale pre-restart data for a full PING_INTERVAL_MIN before the first
    check even runs. Same reasoning as _full_loop's FIRST_RUN_DELAY_SEC,
    just immediate here since a bare TCP probe is cheap enough not to
    need any startup delay at all."""
    while True:
        try:
            await ping_all_devices()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[refresher] ping error: {e}")
        try:
            await asyncio.sleep(PING_INTERVAL_MIN * 60)
        except asyncio.CancelledError:
            break


async def _full_loop():
    """Infrequent, authenticated full-enrichment loop. First run happens
    FIRST_RUN_DELAY_SEC after startup (not immediately — app boot stays
    fast — but not a full INTERVAL_MIN either, see that constant's
    docstring for why)."""
    delay = FIRST_RUN_DELAY_SEC
    while True:
        try:
            await asyncio.sleep(delay)
            delay = INTERVAL_MIN * 60
            await refresh_all_devices()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[refresher] error: {e}")


def start():
    global _full_task, _ping_task
    loop = asyncio.get_event_loop()
    if _full_task is None or _full_task.done():
        _full_task = loop.create_task(_full_loop())
    if _ping_task is None or _ping_task.done():
        _ping_task = loop.create_task(_ping_loop())


def stop():
    global _full_task, _ping_task
    if _full_task and not _full_task.done():
        _full_task.cancel()
        _full_task = None
    if _ping_task and not _ping_task.done():
        _ping_task.cancel()
        _ping_task = None
