"""
Alert detection on the agent side.

Scans device logs for suspicious patterns (failed logins, device reboots)
and produces alert_event objects that are attached (unencrypted) to the
next uplink snapshot envelope. Central OVH server then matches events
against configured rules and dispatches Telegram / webhook notifications.

Dedup cache prevents the same event being reported repeatedly.
"""
import asyncio
import os
import re
import time
from datetime import datetime
from typing import List, Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.device_client import build_client


# ── Config ──────────────────────────────────────────────────────────────────
# Thresholds configurable via env for per-agent tuning.
# Rules on OVH decide whether to actually notify; agent just detects >= this.
THRESHOLD = int(os.environ.get("MIKROMANAGER_ALERT_FAILED_LOGIN_THRESHOLD", "5"))
WINDOW_SEC = int(os.environ.get("MIKROMANAGER_ALERT_FAILED_LOGIN_WINDOW", "900"))

# Cache full scan results — uplink runs every 2 min, but scanning every
# device that often floods their logs with "user X logged in / logged out"
# entries. Rescan only once per SCAN_TTL_SEC (default 1h).
SCAN_TTL_SEC = int(os.environ.get("MIKROMANAGER_ALERT_SCAN_TTL", "3600"))
_scan_cache = {"data": [], "ts": 0.0}

# Dedup: per device, the set of individual log entries (content
# fingerprints, not just a count) already included in an alert we've
# already sent — prevents re-firing on the SAME stale log entries forever.
# RouterOS keeps a bounded log buffer; if a device is quiet, entries from a
# past incident can sit in that buffer for a long time without rotating
# out. Fingerprinting by (message, time) rather than relying on RouterOS's
# own "time" field as an orderable watermark, since that field's format is
# ambiguous across a day boundary ("HH:MM:SS" for today vs "MMM/DD
# HH:MM:SS" for older entries) and can't be reliably compared. Separate
# dicts per alert type so a device tripping both detectors in the same
# scan doesn't have one type's fingerprints clobber the other's.
_alerted_fingerprints: dict = {}
_alerted_reboot_fingerprints: dict = {}


FAILED_LOGIN_HINT_RE = re.compile(
    r"login\s+failure|failed\s+login|authentication\s+failed",
    re.IGNORECASE,
)
FAILED_LOGIN_DETAIL_RE = re.compile(
    r"(?:for user\s+(\S+))?[^\n]*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

# RouterOS's exact reboot-notice wording varies (clean vs unclean shutdown,
# version differences) — matched broadly rather than pinned to one exact
# phrase, since a live router to confirm the precise string against isn't
# available in this dev environment. Covers the common variants: "router
# was rebooted [without proper shutdown]", "router rebooted", "system
# started"/"system rebooted".
REBOOT_HINT_RE = re.compile(
    r"router\s+(?:was\s+)?rebooted|system\s+(?:started|rebooted)",
    re.IGNORECASE,
)


async def _scan_device(device_id: int) -> List[dict]:
    """Scan one device's recent logs. Returns a list of alert dicts — zero,
    one, or more (a device can trip more than one detector in a single scan)."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return []
        device, cred = row

    client = build_client(device, cred)
    try:
        logs = await asyncio.wait_for(client.get_logs(limit=300), timeout=8)
    except Exception:
        return []

    events: List[dict] = []
    device_name = device.identity or device.name or device.ip

    # ── Failed logins ────────────────────────────────────────────────────
    failed = []
    for entry in logs:
        msg = str(entry.get("message") or "")
        if not FAILED_LOGIN_HINT_RE.search(msg):
            continue
        m = FAILED_LOGIN_DETAIL_RE.search(msg)
        source_ip = m.group(2) if m else None
        user = m.group(1) if m else None
        failed.append({
            "user": user, "source_ip": source_ip,
            "time": entry.get("time"), "message": msg,
        })

    if len(failed) >= THRESHOLD:
        # Only re-alert if at least one currently-matching entry wasn't
        # already part of a previous alert for this device — otherwise the
        # SAME stale entries sitting in the router's log buffer (nothing
        # new has actually happened) would re-fire every scan forever.
        fingerprints = {(f["message"], f["time"]) for f in failed}
        already_alerted = _alerted_fingerprints.get(device_id, set())
        if fingerprints - already_alerted:
            _alerted_fingerprints[device_id] = fingerprints
            sources = sorted(set(f["source_ip"] for f in failed if f["source_ip"]))[:10]
            users = sorted(set(f["user"] for f in failed if f["user"]))[:10]
            events.append({
                "type": "failed_logins",
                "device_id": device_id,
                "device_ip": device.ip,
                "device_name": device_name,
                "count": len(failed),
                "sources": sources,
                "users": users,
                "window_sec": WINDOW_SEC,
                "threshold": THRESHOLD,
                "detected_at": datetime.utcnow().isoformat(),
            })

    # ── Device reboot ────────────────────────────────────────────────────
    reboots = []
    for entry in logs:
        msg = str(entry.get("message") or "")
        if REBOOT_HINT_RE.search(msg):
            reboots.append({"time": entry.get("time"), "message": msg})

    if reboots:
        fingerprints = {(r["message"], r["time"]) for r in reboots}
        already_alerted = _alerted_reboot_fingerprints.get(device_id, set())
        if fingerprints - already_alerted:
            _alerted_reboot_fingerprints[device_id] = fingerprints
            # Prefer today's "HH:MM:SS" entries (sort higher lexicographically
            # among themselves) as the most recent — same best-effort
            # ordering caveat as elsewhere for RouterOS's ambiguous time format.
            latest = max(reboots, key=lambda r: r["time"] or "")
            events.append({
                "type": "device_rebooted",
                "device_id": device_id,
                "device_ip": device.ip,
                "device_name": device_name,
                "count": 1,  # discrete event, not a threshold count — always 1 so a default min_count=1 rule fires
                "log_message": latest["message"],
                "log_time": latest["time"],
                "detected_at": datetime.utcnow().isoformat(),
            })

    return events


async def collect_alert_events() -> List[dict]:
    """Scan every device with credentials. Concurrency-bounded so we don't hammer.
    Result cached for SCAN_TTL_SEC to avoid re-logging into every device on
    every uplink cycle."""
    now = time.time()
    if (now - _scan_cache["ts"]) < SCAN_TTL_SEC:
        return _scan_cache["data"]

    with SessionLocal() as db:
        ids = [d.id for d in db.execute(
            select(Device).where(Device.credential_id.is_not(None))
        ).scalars().all()]

    sem = asyncio.Semaphore(5)

    async def _bounded(did):
        async with sem:
            try:
                return await _scan_device(did)
            except Exception:
                return []

    results = await asyncio.gather(*[_bounded(i) for i in ids])
    data = [event for device_events in results for event in device_events]
    _scan_cache["data"] = data
    _scan_cache["ts"] = now
    return data
