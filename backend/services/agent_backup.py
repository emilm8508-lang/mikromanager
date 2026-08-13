"""
Agent self-backup (BCP) — periodically packages this agent's own state
(SQLite DB, Fernet encryption key, session secret, uplink config) into an
encrypted archive and uploads it to OVH, so a lost/corrupted disk doesn't
also wipe out the entire device inventory, credentials, and OVH access —
distinct from the existing per-ROUTER config backup (services/firmware.py),
which is a different concern entirely.

Deliberately refuses to run at all if no enc_key is configured (see
services/uplink.py) — this never uploads an unencrypted backup; "no key
configured" means "no backup happens", not "send it in the clear".

Restore: backend/scripts/restore_backup.py, given a downloaded backup
(ovh/api.php's backup_download action) and the same enc_key.
"""
import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import tarfile
import time
from datetime import datetime, timedelta
from typing import Optional

import aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services import uplink

BACKUP_DAY = int(os.environ.get("MIKROTIK_BACKUP_DAY", "6"))    # 0=Mon..6=Sun, default Sunday
BACKUP_HOUR = int(os.environ.get("MIKROTIK_BACKUP_HOUR", "3"))  # after the weekly vuln scan (2:00)

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
# What "the agent's own state" means here — deliberately excludes ephemeral/
# regenerable files (activity_pending.json, wan_state.json): losing those
# just means one alert cycle re-learns them, not worth the extra bytes.
BACKUP_FILES = ["mikrotik.db", ".key", ".session_secret", "uplink.json", "central_proxy.json"]

_state = {
    "last_backup_at": None,
    "last_error": None,
    "last_size_bytes": None,
    "in_progress": False,
}
_task: Optional[asyncio.Task] = None


def status() -> dict:
    now = datetime.utcnow()
    next_dt = _next_run_datetime(now)
    return {
        **_state,
        "backup_day": BACKUP_DAY,
        "backup_hour": BACKUP_HOUR,
        "next_run_estimated": next_dt.timestamp(),
        "enc_key_configured": bool(uplink.get_enc_key()),
    }


def _next_run_datetime(now: datetime) -> datetime:
    days_ahead = (BACKUP_DAY - now.weekday()) % 7
    candidate = (now + timedelta(days=days_ahead)).replace(
        hour=BACKUP_HOUR, minute=0, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


def _build_archive() -> bytes:
    """Tar+gzip every existing backup file into an in-memory archive.
    Missing files (e.g. central_proxy.json only exists once the Central
    proxy has been used at least once) are skipped, not fatal — run purely
    synchronously (tarfile/file I/O), called via run_in_executor."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in BACKUP_FILES:
            path = os.path.join(_DATA_DIR, name)
            if os.path.isfile(path):
                tar.add(path, arcname=name)
    return buf.getvalue()


def encrypt_archive(archive_bytes: bytes, enc_key_b64: str) -> bytes:
    """Same AES-256-GCM envelope shape as uplink.py's snapshot E2E
    encryption — one algorithm, one mental model for "encrypted" in this
    app, reused rather than reinvented. version 'v':1 (distinct from the
    snapshot envelope's v:2) since the payload shape is different (no
    plaintext metadata fields alongside the ciphertext — a backup has no
    safe-to-expose public summary the way a snapshot does)."""
    key = base64.b64decode(enc_key_b64)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, archive_bytes, None)
    envelope = {
        "v": 1,
        "alg": "aes-256-gcm",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "created_at": datetime.utcnow().isoformat(),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def decrypt_archive(envelope: dict, enc_key_b64: str) -> bytes:
    """Inverse of encrypt_archive() — shared with restore_backup.py so the
    decrypt logic exists in exactly one place."""
    if envelope.get("v") != 1 or envelope.get("alg") != "aes-256-gcm":
        raise ValueError(f"unsupported backup envelope: v={envelope.get('v')} alg={envelope.get('alg')}")
    key = base64.b64decode(enc_key_b64)
    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ciphertext"])
    return AESGCM(key).decrypt(nonce, ct, None)


async def create_and_upload_backup() -> dict:
    """Returns {"ok": bool, "error": str|None, "size_bytes": int|None}."""
    if _state["in_progress"]:
        return {"ok": False, "error": "a backup is already in progress", "size_bytes": None}
    if not uplink.is_configured():
        return {"ok": False, "error": "central not configured", "size_bytes": None}
    enc_key = uplink.get_enc_key()
    if not enc_key:
        return {
            "ok": False,
            "error": "no enc_key configured — refusing to upload an unencrypted backup; "
                     "set up E2E encryption in Centralny → Agent (uplink) first",
            "size_bytes": None,
        }

    _state["in_progress"] = True
    try:
        loop = asyncio.get_event_loop()
        archive = await loop.run_in_executor(None, _build_archive)
        body = await loop.run_in_executor(None, encrypt_archive, archive, enc_key)

        url = uplink.backup_url()
        if not url:
            _state["last_error"] = "no backup URL derivable from uplink config"
            return {"ok": False, "error": _state["last_error"], "size_bytes": None}

        ts = str(int(time.time()))
        api_key = uplink._config["api_key"]
        sig = hmac.new(api_key.encode(), (ts + "|").encode() + body, hashlib.sha256).hexdigest()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Tenant": uplink._config["tenant"],
            "X-Timestamp": ts,
            "X-Signature": sig,
            "Content-Type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=body, headers=headers) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    _state["last_error"] = f"HTTP {resp.status}: {text[:200]}"
                    return {"ok": False, "error": _state["last_error"], "size_bytes": None}

        _state["last_backup_at"] = datetime.utcnow().isoformat()
        _state["last_size_bytes"] = len(body)
        _state["last_error"] = None
        return {"ok": True, "error": None, "size_bytes": len(body)}
    except Exception as e:
        _state["last_error"] = str(e)
        return {"ok": False, "error": str(e), "size_bytes": None}
    finally:
        _state["in_progress"] = False


async def _loop():
    while True:
        try:
            now = datetime.utcnow()
            sleep_sec = max(1.0, (_next_run_datetime(now) - now).total_seconds())
            await asyncio.sleep(sleep_sec)
            await create_and_upload_backup()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[agent_backup] loop error: {e}")


def start():
    global _task
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None
