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

# PRTG sensor status codes (Paessler KB "Complete list for Sensor Status
# codes") - which ones count as "needs attention" for prtg_monitor.py.
# Deliberately excludes the Paused* states (7/8/9/11/12) - those are a
# deliberate operator choice in PRTG, not a problem to alert on.
PROBLEM_STATUSES = frozenset({4, 5, 6, 10, 13, 14})
STATUS_NAMES = {
    1: "Unknown", 2: "Collecting", 3: "Up", 4: "Warning", 5: "Down",
    6: "Brak sondy (NoProbe)", 7: "Wstrzymany (użytkownik)",
    8: "Wstrzymany (zależność)", 9: "Wstrzymany (harmonogram)",
    10: "Nietypowy (Unusual)", 11: "Wstrzymany (licencja)",
    12: "Wstrzymany do...", 13: "Down (potwierdzony)", 14: "Down (częściowy)",
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
    # PRTG's own HTTP API docs (paessler.com/manuals/prtg/http_api) document
    # both an "Authorization: Bearer <token>" header AND a plain "apitoken"
    # query parameter as equally valid. Confirmed live: a real PRTG server
    # rejected the Bearer header with "401 Unsupported authorization scheme"
    # (most likely something in front of PRTG - a reverse proxy or an older
    # core version - intercepting the header before PRTG's own auth logic
    # sees it) - the query-parameter form sidesteps that path entirely.
    params = {"content": "sensors", "columns": "objid,sensor,status", "count": "1",
              "apitoken": _config["api_token"]}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return {"ok": True, "sample_count": len(data.get("sensors", []))}
                text = (await resp.text())[:300]
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def list_devices() -> Optional[dict]:
    """content=devices -> {objid: {"name":..., "host":...}}, used by
    prtg_monitor.py to resolve a sensor's parent device IP/DNS (sensors
    themselves carry no host info - see list_sensors()'s docstring).
    Returns None (not {}) on any failure, so a transient API/network error
    is never mistaken for "zero devices configured"."""
    if not is_configured():
        return None
    url = f"{_config['url']}/api/table.json"
    params = {"content": "devices", "columns": "objid,name,host", "count": "*",
              "apitoken": _config["api_token"]}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                out = {}
                for d in data.get("devices", []):
                    if not isinstance(d, dict) or "objid" not in d:
                        continue
                    out[d["objid"]] = {"name": d.get("name"), "host": d.get("host")}
                return out
    except Exception as e:
        print(f"[prtg] list_devices error: {e}")
        return None


async def list_sensors() -> Optional[list]:
    """content=sensors -> ALL sensors (not just problem ones - prtg_monitor
    needs the full list every cycle to detect a return-to-Up as well as a
    new problem, the same reason tunnel_monitor.py scans every tunnel, not
    just the down ones). Each row: {objid, sensor, parentid, status,
    message, priority}. Returns None on failure."""
    if not is_configured():
        return None
    url = f"{_config['url']}/api/table.json"
    # PRTG's plain "status" column is human-readable text ("Down", "Up
    # (Paused)", ...); "status_raw" is the numeric code documented in
    # PROBLEM_STATUSES above - must be requested explicitly, it isn't
    # included unless named in "columns".
    params = {"content": "sensors",
              "columns": "objid,sensor,parentid,status_raw,message,priority",
              "count": "*", "apitoken": _config["api_token"]}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                out = []
                for s in data.get("sensors", []):
                    if not isinstance(s, dict) or "objid" not in s:
                        continue
                    try:
                        status_val = int(s.get("status_raw"))
                    except (TypeError, ValueError):
                        continue
                    out.append({
                        "objid": s["objid"], "sensor": s.get("sensor"),
                        "parentid": s.get("parentid"), "status": status_val,
                        "message": s.get("message"),
                    })
                return out
    except Exception as e:
        print(f"[prtg] list_sensors error: {e}")
        return None


async def list_messages(count: int = 50) -> Optional[list]:
    """content=messages -> PRTG's own log (sensor status changes, user
    actions like pause/acknowledge, system messages) - used by
    prtg_monitor.py to feed this agent's local Activity Log, separate from
    (and broader than) the up/down-only alerting in collect_prtg_events().
    Always sorted newest-first by PRTG itself for this content type, so no
    explicit sortby is needed - just cap to the most recent `count`.

    Each row's "objid" here is the MESSAGE's own unique id (distinct from
    "parent", the related sensor/device's id) - confirmed by Paessler's own
    example queries always requesting both columns together, which would
    be redundant if they were the same value. Used as the dedup key by the
    caller instead of (time, text) hashing.

    datetime_raw is an OLE Automation date (days since 1899-12-30, UTC) -
    the same "numeric raw companion field" convention already relied on
    for status_raw in list_sensors() above; requested explicitly via
    columns since PRTG's plain "datetime" column is a locale-formatted
    string, not reliably parseable. Returns None on failure."""
    if not is_configured():
        return None
    url = f"{_config['url']}/api/table.json"
    params = {"content": "messages",
              "columns": "objid,datetime_raw,parent,type,name,status,message",
              "count": str(count), "apitoken": _config["api_token"]}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                out = []
                for m in data.get("messages", []):
                    if not isinstance(m, dict) or "objid" not in m:
                        continue
                    out.append({
                        "objid": m["objid"], "datetime_raw": m.get("datetime_raw"),
                        "parent": m.get("parent"), "type": m.get("type"),
                        "name": m.get("name"), "status": m.get("status"),
                        "message": m.get("message"),
                    })
                return out
    except Exception as e:
        print(f"[prtg] list_messages error: {e}")
        return None


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
