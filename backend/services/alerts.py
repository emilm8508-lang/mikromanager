"""
Alert detection on the agent side.

Scans device logs for suspicious patterns (failed logins) and produces
alert_event objects that are attached (unencrypted) to the next uplink
snapshot envelope. Central OVH server then matches events against
configured rules and dispatches Telegram / webhook notifications.

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

# Dedup: prevents flooding OVH with duplicate events for the same device.
_seen: dict = {}
_SEEN_TTL_SEC = 3600


def _prune_seen():
    now = time.time()
    for k in list(_seen.keys()):
        if now - _seen[k] > _SEEN_TTL_SEC:
            del _seen[k]


FAILED_LOGIN_HINT_RE = re.compile(
    r"login\s+failure|failed\s+login|authentication\s+failed",
    re.IGNORECASE,
)
FAILED_LOGIN_DETAIL_RE = re.compile(
    r"(?:for user\s+(\S+))?[^\n]*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)


async def _scan_device(device_id: int) -> Optional[dict]:
    """Scan one device's recent logs. Returns alert dict if threshold exceeded."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return None
        device, cred = row

    client = build_client(device, cred)
    try:
        logs = await asyncio.wait_for(client.get_logs(limit=300), timeout=8)
    except Exception:
        return None

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
            "time": entry.get("time"),
        })

    if len(failed) < THRESHOLD:
        return None

    # Bucket into groups of 5 so we don't fire an alert on every single new entry.
    bucket = len(failed) // 5
    key = (device_id, "failed_logins", bucket)
    now = time.time()
    if key in _seen and (now - _seen[key]) < WINDOW_SEC:
        return None
    _seen[key] = now

    sources = sorted(set(f["source_ip"] for f in failed if f["source_ip"]))[:10]
    users = sorted(set(f["user"] for f in failed if f["user"]))[:10]

    return {
        "type": "failed_logins",
        "device_id": device_id,
        "device_ip": device.ip,
        "device_name": device.identity or device.name or device.ip,
        "count": len(failed),
        "sources": sources,
        "users": users,
        "window_sec": WINDOW_SEC,
        "threshold": THRESHOLD,
        "detected_at": datetime.utcnow().isoformat(),
    }


async def collect_alert_events() -> List[dict]:
    """Scan every device with credentials. Concurrency-bounded so we don't hammer."""
    _prune_seen()
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
                return None

    results = await asyncio.gather(*[_bounded(i) for i in ids])
    return [r for r in results if r]
