"""
Uplink service — sends periodic snapshots of local agent state to a central
HTTPS endpoint (e.g. PHP+MySQL on OVH shared hosting).

Snapshot includes: device list, online/offline, model, ROS version, topology
links, recent critical logs. Sent every UPLINK_INTERVAL seconds (default 120).

On send failure, snapshots are buffered locally (up to 50) and retried.
Configuration via environment variables OR via /api/system/uplink/config.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime
from typing import Optional
import aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from models.database import SessionLocal, Device, DeviceLink
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient


# Config — can be overridden via UI/env vars
_config = {
    "url": os.environ.get("MIKROTIK_UPLINK_URL", ""),
    "tenant": os.environ.get("MIKROTIK_UPLINK_TENANT", ""),
    "api_key": os.environ.get("MIKROTIK_UPLINK_KEY", ""),
    # End-to-end encryption key (base64). If set, payload is AES-256-GCM
    # encrypted before POST. Server stores only ciphertext. Viewer needs
    # the same key to decrypt.
    "enc_key": os.environ.get("MIKROTIK_UPLINK_ENC_KEY", ""),
    "interval_sec": int(os.environ.get("MIKROTIK_UPLINK_INTERVAL", "120")),
}

_state = {
    "last_sent": None,
    "last_attempt": None,
    "last_error": None,
    "buffered_count": 0,
    "total_sent": 0,
    "total_failed": 0,
}
_buffer = []
_task: Optional[asyncio.Task] = None


def is_configured() -> bool:
    return bool(_config["url"] and _config["tenant"] and _config["api_key"])


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "tenant": _config["tenant"],
        "interval_sec": _config["interval_sec"],
        "has_api_key": bool(_config["api_key"]),
        "has_enc_key": bool(_config["enc_key"]),  # E2E encryption active
        **_state,
    }


def configure(url: str, tenant: str, api_key: str, interval_sec: int = 120,
              enc_key: str = "") -> dict:
    """Update uplink configuration at runtime. Persists to a small JSON file."""
    _config["url"] = url
    _config["tenant"] = tenant
    _config["api_key"] = api_key
    if enc_key:
        # Validate it's base64 of 32 bytes (AES-256 key)
        try:
            raw = base64.b64decode(enc_key)
            if len(raw) != 32:
                raise ValueError(f"enc_key must be 32 bytes (got {len(raw)})")
            _config["enc_key"] = enc_key
        except Exception as e:
            raise ValueError(f"invalid enc_key: {e}")
    elif enc_key == "":
        # Empty string explicitly = keep existing
        pass
    _config["interval_sec"] = max(30, interval_sec)
    _persist()
    stop()
    start()
    return status()


def generate_enc_key() -> str:
    """Generate a fresh 32-byte AES-256-GCM key, return base64-encoded."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uplink.json")


def _persist():
    import json
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    # Don't write api_key in plaintext if we encrypt — but for simplicity here we do.
    # The file is in backend/data which is .gitignored.
    with open(_CONFIG_PATH, "w") as f:
        json.dump(_config, f, indent=2)


def _load():
    import json
    if not os.path.exists(_CONFIG_PATH):
        return
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
        for k in ("url", "tenant", "api_key", "interval_sec"):
            if k in saved:
                _config[k] = saved[k]
    except Exception as e:
        print(f"[uplink] config load error: {e}")


async def _build_snapshot() -> dict:
    """Build current snapshot from local database + fresh log scan."""
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        links = db.execute(select(DeviceLink)).scalars().all()
        dev_list = [{
            "id": d.id,
            "ip": d.ip,
            "identity": d.identity,
            "name": d.name,
            "model": d.model,
            "ros_version": d.ros_version,
            "board_name": d.board_name,
            "online": d.online,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "has_api": d.has_api,
            "has_ssh": d.has_ssh,
            "has_web": d.has_web,
            "has_snmp": d.has_snmp,
            "api_port": d.api_port,
            "web_port": d.web_port,
        } for d in devices]
        link_list = [{
            "a": l.device_a_id,
            "b": l.device_b_id,
            "type": l.link_type,
            "iface_a": l.interface_a,
            "iface_b": l.interface_b,
        } for l in links]

    # Get critical logs (cached or fresh)
    try:
        from api import system as sys_api
        crit_logs = await sys_api.get_critical_logs(limit=30)
        if hasattr(crit_logs, "body"):  # if it's a Response object
            crit_logs = []
    except Exception:
        crit_logs = []

    return {
        "tenant": _config["tenant"],
        "sent_at": int(time.time()),
        "sent_at_iso": datetime.utcnow().isoformat(),
        "agent_version": "1.2",
        "devices_count": len(dev_list),
        "devices_online": sum(1 for d in dev_list if d["online"]),
        "devices": dev_list,
        "links": link_list,
        "critical_logs": crit_logs,
    }


def _build_request_body(snapshot: dict) -> tuple:
    """Build the request body (encrypted if enc_key configured) and HMAC headers.
    Returns (body_bytes, headers_dict)."""
    plaintext = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")

    if _config["enc_key"]:
        # E2E encryption: AES-256-GCM with random 12-byte nonce.
        # Result envelope: { v: 2, alg: "aes-256-gcm", nonce: b64, ciphertext: b64 }
        # Server stores this opaquely. Only client with enc_key can decrypt.
        key = base64.b64decode(_config["enc_key"])
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        envelope = {
            "v": 2,
            "alg": "aes-256-gcm",
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            # These two are PUBLIC metadata that the server/index page can use
            # for listing without decrypting. They reveal only timestamp + size.
            "tenant": _config["tenant"],
            "sent_at": snapshot.get("sent_at"),
            "devices_count": snapshot.get("devices_count"),
            "devices_online": snapshot.get("devices_online"),
        }
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    else:
        body = plaintext

    # HMAC-SHA256 over: timestamp || body. Prevents tamper + replay.
    ts = str(int(time.time()))
    sig = hmac.new(
        _config["api_key"].encode(), (ts + "|").encode() + body,
        hashlib.sha256
    ).hexdigest()

    headers = {
        "Authorization": f"Bearer {_config['api_key']}",
        "X-Tenant": _config["tenant"],
        "X-Timestamp": ts,
        "X-Signature": sig,
        "X-Encrypted": "1" if _config["enc_key"] else "0",
        "Content-Type": "application/json",
        "User-Agent": "MikroManager-Agent/1.2",
    }
    return body, headers


async def _send_one(snapshot: dict) -> bool:
    if not is_configured():
        return False
    body, headers = _build_request_body(snapshot)
    timeout = aiohttp.ClientTimeout(total=20)
    _state["last_attempt"] = datetime.utcnow().isoformat()
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(_config["url"], data=body, headers=headers) as resp:
                if 200 <= resp.status < 300:
                    _state["last_sent"] = datetime.utcnow().isoformat()
                    _state["last_error"] = None
                    _state["total_sent"] += 1
                    return True
                body = await resp.text()
                _state["last_error"] = f"HTTP {resp.status}: {body[:200]}"
                _state["total_failed"] += 1
                return False
    except asyncio.TimeoutError:
        _state["last_error"] = "timeout"
        _state["total_failed"] += 1
        return False
    except Exception as e:
        _state["last_error"] = f"{type(e).__name__}: {e}"
        _state["total_failed"] += 1
        return False


async def send_now() -> dict:
    """Manually trigger one send. Returns result + status."""
    snapshot = await _build_snapshot()
    success = await _send_one(snapshot)
    if not success:
        _buffer.append(snapshot)
        _state["buffered_count"] = len(_buffer)
    return {"success": success, "status": status()}


async def _loop():
    global _buffer
    # Wait one interval before first try
    while True:
        try:
            await asyncio.sleep(_config["interval_sec"])
            if not is_configured():
                continue

            snapshot = await _build_snapshot()
            _buffer.append(snapshot)

            # Try to drain buffer oldest-first
            while _buffer:
                head = _buffer[0]
                if await _send_one(head):
                    _buffer.pop(0)
                else:
                    break  # keep buffered, retry next cycle

            # Cap buffer
            if len(_buffer) > 50:
                _buffer = _buffer[-50:]
            _state["buffered_count"] = len(_buffer)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[uplink] loop error: {e}")


def start():
    global _task
    _load()
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None
