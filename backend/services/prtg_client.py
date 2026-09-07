"""
PRTG connector — connection settings for the monitoring-aggregation
connectors planned in doktorat/plan-architektura-ai-anomalie.md (§3.4/§4):
MikroManager pulls sensor status from a client's existing PRTG install as
an additional data source, alongside Mikrotik/Windows/Linux/Dell iDRAC.

Mirrors services/uplink.py's config/persist shape (small JSON file under
backend/data/, .gitignored), but the API token is encrypted at rest with
services/crypto (the same Fernet key used for Credential.password_enc/
snmp_community_enc) rather than stored in plaintext — see key_status()/
rotate_key() hooks below, which fold this file into the existing
"documented key lifecycle" story on the Bezpieczeństwo page.

Actual polling of PRTG (to feed Device/DeviceInterfaceStats/alert_events)
is a separate follow-up — this module is connection settings + a
connectivity test only.
"""
import json
import os
from typing import Optional

import aiohttp

from services.crypto import encrypt, decrypt

_config = {
    "url": "",         # e.g. https://prtg.klient.local
    "api_token": "",   # plaintext in memory; encrypted on disk
    "verify_ssl": True,
}

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "prtg.json")


def is_configured() -> bool:
    return bool(_config["url"] and _config["api_token"])


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "has_api_token": bool(_config["api_token"]),
        "verify_ssl": _config["verify_ssl"],
    }


def configure(url: str, api_token: str = "", verify_ssl: bool = True) -> dict:
    """Empty api_token means 'keep existing' — mirrors uplink.configure()'s
    handling of api_key, so the UI can change the URL/verify_ssl toggle
    without forcing a re-paste of the token."""
    _config["url"] = url.rstrip("/")
    if api_token:
        _config["api_token"] = api_token
    _config["verify_ssl"] = verify_ssl
    _persist()
    return status()


def _persist():
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    to_save = dict(_config)
    if to_save["api_token"]:
        to_save["api_token"] = encrypt(to_save["api_token"])
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(to_save, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)


def _load():
    if not os.path.exists(_CONFIG_PATH):
        return
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
        if saved.get("url"):
            _config["url"] = saved["url"]
        if "verify_ssl" in saved:
            _config["verify_ssl"] = bool(saved["verify_ssl"])
        token = saved.get("api_token")
        if token:
            try:
                _config["api_token"] = decrypt(token)
            except Exception:
                # Wrong/rotated key, or a pre-encryption plaintext file —
                # never crash agent startup over a stale connector secret.
                print("[prtg] could not decrypt stored api_token — reconfigure via UI")
    except Exception as e:
        print(f"[prtg] config load error: {e}")


_load()


async def test_connection() -> dict:
    """Cheap read-only call (1 sensor row) to confirm URL + token are
    valid. Never raises — always returns {"ok": bool, ...}."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    url = f"{_config['url']}/api/table.json"
    params = {"content": "sensors", "columns": "objid,sensor,status", "count": "1"}
    headers = {"Authorization": f"Bearer {_config['api_token']}"}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return {"ok": True, "sample_count": len(data.get("sensors", []))}
                text = (await resp.text())[:300]
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def has_secret() -> bool:
    """Used by services.crypto.key_status() to count this as one more
    Fernet-encrypted field for the key-lifecycle summary."""
    return bool(_config["api_token"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    """Used by services.crypto.rotate_key() mid-rotation — re-encrypts the
    stored api_token in place under the new key. Returns 1 if a secret was
    rotated, 0 if nothing was configured. Takes explicit Fernet instances
    (not get_fernet()) because this runs while the module-level key is
    still the OLD one."""
    if not os.path.exists(_CONFIG_PATH):
        return 0
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
    except Exception:
        return 0
    token = saved.get("api_token")
    if not token:
        return 0
    try:
        plaintext = old_fernet.decrypt(token.encode()).decode()
    except Exception:
        return 0
    saved["api_token"] = new_fernet.encrypt(plaintext.encode()).decode()
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)
    _config["api_token"] = plaintext  # keep in-memory copy in sync
    return 1
