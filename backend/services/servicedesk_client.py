"""
ManageEngine ServiceDesk Plus (on-premise) connector — settings + a
connectivity test + a generic ticket-creation call, for the NIS2/KSC
incident-and-request-register use case: the client already has SDP
installed (unused so far), so instead of building our own incident
tracker, MikroManager creates tickets in the system they already trust
and that already has SLA/due-date tracking built in.

This is per-tenant, not a Central/OVH feature: the client's SDP install is
on-premise, behind their own firewall — OVH (shared hosting on the public
internet) has no way to reach it, but the agent already lives inside that
same network, exactly like the PRTG/Check_MK connectors before it. Mirrors
their config/persist/encryption shape 1:1 (small JSON file under
backend/data/, .gitignored, authtoken encrypted at rest with services.crypto
— see key_status()/rotate_key() hooks below).

Auth: SDP on-premise's REST API v3 uses a per-technician "Authtoken" —
generated in the SDP web UI (User Profile -> Generate Authtoken, or
Admin -> Technicians), sent as a request header. Confirmed against
ManageEngine's own API v3 documentation (both the on-premise "SDP help
desk guide" and the API v3 request/response reference) — NOT guessed, but
also not yet exercised against a real instance in this codebase, since no
authtoken had been generated yet at the time this was written. Response
success/failure is signalled by a response_status.status field
("success"/"failed"), not by the bare HTTP status code alone — a 200 can
still carry a validation error in that envelope.

Deliberately does NOT (yet) wire any alert type to auto-create a ticket —
create_ticket() below is a ready-to-use building block, called from
nowhere yet. Which local events should become SDP tickets is a separate,
later decision.
"""
import json
import os
from typing import Optional

import aiohttp

from services.crypto import encrypt, decrypt

_config = {
    "url": "",         # e.g. http://sdp.klient.local:8080
    "authtoken": "",    # technician API key; plaintext in memory, encrypted on disk
    "verify_ssl": True,
}

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "servicedesk.json")

# ManageEngine's own convention across the API v3 family: the envelope's
# response_status.status field, not the bare HTTP status code, is the real
# success/failure signal (a 200 can still carry a validation error here).
_STATUS_OK = "success"


def is_configured() -> bool:
    return bool(_config["url"] and _config["authtoken"])


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "has_authtoken": bool(_config["authtoken"]),
        "verify_ssl": _config["verify_ssl"],
    }


def configure(url: str, authtoken: str = "", verify_ssl: bool = True) -> dict:
    """Empty authtoken means 'keep existing' — mirrors prtg_client.configure()."""
    _config["url"] = url.rstrip("/")
    if authtoken:
        _config["authtoken"] = authtoken
    _config["verify_ssl"] = verify_ssl
    _persist()
    return status()


def _persist():
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    to_save = dict(_config)
    if to_save["authtoken"]:
        to_save["authtoken"] = encrypt(to_save["authtoken"])
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
        token = saved.get("authtoken")
        if token:
            try:
                _config["authtoken"] = decrypt(token)
            except Exception:
                # Wrong/rotated key, or a pre-encryption plaintext file —
                # never crash agent startup over a stale connector secret.
                print("[servicedesk] could not decrypt stored authtoken — reconfigure via UI")
    except Exception as e:
        print(f"[servicedesk] config load error: {e}")


_load()


def _headers() -> dict:
    return {
        "Authtoken": _config["authtoken"],
        "Accept": "application/vnd.manageengine.sdp.v3+json",
    }


async def test_connection() -> dict:
    """Cheap read-only call (1 request row) to confirm URL + authtoken are
    valid. Never raises — always returns {"ok": bool, ...}."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    url = f"{_config['url']}/api/v3/requests"
    list_info = json.dumps({"list_info": {"row_count": 1}})
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, params={"input_data": list_info}, headers=_headers(),
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = None
                resp_status = (data or {}).get("response_status") or {}
                if resp.status == 200 and resp_status.get("status") == _STATUS_OK:
                    return {"ok": True, "sample_count": len(data.get("requests", []) if data else [])}
                text = (await resp.text())[:300] if data is None else str(resp_status)
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def create_ticket(subject: str, description: str = "", request_type: str = "Incident",
                         priority: Optional[str] = None, urgency: Optional[str] = None,
                         category: Optional[str] = None) -> dict:
    """Creates a new SDP request/incident. request_type is either
    "Incident" or "Service Request" — both live in the same /api/v3/requests
    module in SDP's ITIL terminology, distinguished by this one field
    (confirmed against ManageEngine's official API v3 reference). priority/
    urgency/category are looked up by name on the SDP side — an unknown
    name is rejected by SDP itself (surfaced via response_status.messages),
    not validated here, since the allowed values are entirely instance-
    specific (each SDP install defines its own).

    Deliberately narrow surface — exactly what a NIS2 incident/request
    register entry needs, not every field this API supports. Never
    raises — always returns {"ok": bool, ...}; a real HTTP/network error and
    a clean "SDP rejected this" are both reported the same way (see
    "error"), callers that only care about ok/id don't need to tell them
    apart.
    """
    if not is_configured():
        return {"ok": False, "error": "not configured"}

    request: dict = {"subject": subject[:250], "request_type": {"name": request_type}}
    if description:
        request["description"] = description
    if priority:
        request["priority"] = {"name": priority}
    if urgency:
        request["urgency"] = {"name": urgency}
    if category:
        request["category"] = {"name": category}
    input_data = json.dumps({"request": request})

    url = f"{_config['url']}/api/v3/requests"
    headers = dict(_headers())
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(url, data={"input_data": input_data}, headers=headers,
                                     timeout=aiohttp.ClientTimeout(total=15)) as resp:
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = (await resp.text())[:300]
                    return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
                resp_status = data.get("response_status") or {}
                if resp_status.get("status") == _STATUS_OK:
                    created = data.get("request") or {}
                    return {"ok": True, "id": created.get("id"), "display_id": created.get("display_id")}
                return {"ok": False, "error": str(resp_status.get("messages") or resp_status), "raw": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def has_secret() -> bool:
    """Used by services.crypto.key_status() to count this as one more
    Fernet-encrypted field for the key-lifecycle summary."""
    return bool(_config["authtoken"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    """Used by services.crypto.rotate_key() mid-rotation — re-encrypts the
    stored authtoken in place under the new key. Returns 1 if a secret was
    rotated, 0 if nothing was configured."""
    if not os.path.exists(_CONFIG_PATH):
        return 0
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
    except Exception:
        return 0
    token = saved.get("authtoken")
    if not token:
        return 0
    try:
        plaintext = old_fernet.decrypt(token.encode()).decode()
    except Exception:
        return 0
    saved["authtoken"] = new_fernet.encrypt(plaintext.encode()).decode()
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)
    _config["authtoken"] = plaintext  # keep in-memory copy in sync
    return 1
