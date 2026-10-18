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

_DEFAULT_RULES = {
    "wan": {"enabled": False, "delay_min": 5},          # WAN interface of a router down (wan_down / wan_up)
    "service": {"enabled": False, "delay_min": 5},      # a watched Windows / Linux service down (host_service_down / _up)
    "idrac": {"enabled": False, "delay_min": 5},        # a Dell server's iDRAC unreachable (idrac_unreachable / idrac_reachable)
}
_DEFAULT_TICKET = {"request_type": "Incident", "priority": "", "urgency": "", "category": "", "closure_code": "Success"}

_config = {
    "url": "",         # e.g. http://sdp.klient.local:8080
    "authtoken": "",    # technician API key; plaintext in memory, encrypted on disk
    "verify_ssl": True,
    "rules": json.loads(json.dumps(_DEFAULT_RULES)),   # which outages open a ticket, and after how many minutes
    "ticket": dict(_DEFAULT_TICKET),                   # the fields of those tickets (names as they exist in this SDP)
    "close_on_recovery": True,                         # resolve + close the ticket when the outage ends
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
        "rules": _config["rules"],
        "ticket": _config["ticket"],
        "close_on_recovery": _config["close_on_recovery"],
    }


def configure(url: str, authtoken: str = "", verify_ssl: bool = True, rules: Optional[dict] = None, ticket: Optional[dict] = None,
              close_on_recovery: Optional[bool] = None) -> dict:
    """Empty authtoken means 'keep existing' — mirrors prtg_client.configure(). `rules` / `ticket` / `close_on_recovery` are only changed
    when given (a caller that only knows URL + token leaves them alone)."""
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"Adres musi zaczynać się od http:// lub https:// (np. https://sdp.klient.local:8081), a jest: {url or 'pusty'}")
    _config["url"] = url.rstrip("/")
    if authtoken:
        _config["authtoken"] = authtoken
    _config["verify_ssl"] = verify_ssl
    if rules is not None:
        for name, default in _DEFAULT_RULES.items():
            r = rules.get(name) or {}
            _config["rules"][name] = {"enabled": bool(r.get("enabled", default["enabled"])),
                                      "delay_min": max(0, min(24 * 60, int(r.get("delay_min", default["delay_min"]) or 0)))}
    if ticket is not None:
        for k in _DEFAULT_TICKET:
            if k in ticket:
                _config["ticket"][k] = str(ticket[k] or "").strip()[:80]
        if not _config["ticket"]["request_type"]:
            _config["ticket"]["request_type"] = "Incident"
    if close_on_recovery is not None:
        _config["close_on_recovery"] = bool(close_on_recovery)
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
        for name in _DEFAULT_RULES:
            r = (saved.get("rules") or {}).get(name)
            if isinstance(r, dict):
                _config["rules"][name] = {"enabled": bool(r.get("enabled")), "delay_min": max(0, min(24 * 60, int(r.get("delay_min", 5) or 0)))}
        for k in _DEFAULT_TICKET:
            if isinstance((saved.get("ticket") or {}).get(k), str):
                _config["ticket"][k] = saved["ticket"][k]
        if "close_on_recovery" in saved:
            _config["close_on_recovery"] = bool(saved["close_on_recovery"])
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


def _status_of(data) -> dict:
    """The envelope's response_status as one dict. SDP v3 sends an object for some answers and a one-element ARRAY for others (the list
    of requests, for one) - treating it as an object failed with "'list' object has no attribute 'get'"."""
    st = (data or {}).get("response_status") if isinstance(data, dict) else None
    if isinstance(st, list):
        st = st[0] if st else {}
    return st if isinstance(st, dict) else {}


def url_problem() -> Optional[str]:
    """What is wrong with the saved URL, or None. aiohttp only says "InvalidURL: rdp.local:8081/api/v3/requests" for an address without
    http:// or https:// - not something an operator can act on."""
    u = _config["url"]
    if not u.lower().startswith(("http://", "https://")):
        return f"Adres ServiceDesk musi zaczynać się od http:// lub https:// (jest: {u or 'pusty'}). Przykład: https://sdp.klient.local:8081"
    return None


def explain(error: str) -> str:
    """The error as the help desk gave it, plus - for the answers that have a known cause - what to do about it."""
    e = str(error or "")
    low = e.lower()
    if "4002" in e or "does not have this permission" in low or "http 403" in low:
        return (e + " - Technik, do którego należy ten klucz (Authtoken), nie ma w ServiceDesk uprawnienia do tej operacji. Wygeneruj klucz dla technika "
                "z rolą SDAdmin albo z rolą, która pozwala na zgłoszenia: przeglądanie, dodawanie, edycję, notatki, rozwiązania i zamykanie.")
    if "401" in e or "invalid api key" in low or "authtoken" in low:
        return e + " - ServiceDesk nie przyjął klucza (Authtoken): sprawdź, czy jest skopiowany w całości i czy należy do aktywnego technika."
    if "ssl" in low or "certificate" in low:
        return e + " - problem z certyfikatem HTTPS: dla certyfikatu samopodpisanego wyłącz weryfikację TLS w ustawieniach."
    if "cannot connect" in low or "name or service not known" in low or "getaddrinfo" in low or "timed out" in low or "timeout" in low:
        return e + " - agent nie łączy się z tym adresem: sprawdź nazwę/adres, port i czy agent ma dostęp do serwera ServiceDesk."
    return e


async def test_connection() -> dict:
    """Cheap read-only call (1 request row) to confirm URL + authtoken are
    valid. Never raises — always returns {"ok": bool, ...}."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    if url_problem():
        return {"ok": False, "error": url_problem()}
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
                resp_status = _status_of(data)
                if resp.status == 200 and resp_status.get("status") == _STATUS_OK:
                    return {"ok": True, "sample_count": len(data.get("requests", []) if data else [])}
                text = (await resp.text())[:300] if data is None else str(resp_status)
                return {"ok": False, "error": explain(f"HTTP {resp.status}: {text}")}
    except Exception as e:
        return {"ok": False, "error": explain(str(e))}


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
    if url_problem():
        return {"ok": False, "error": url_problem()}

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
                    return {"ok": False, "error": explain(f"HTTP {resp.status}: {text}")}
                resp_status = _status_of(data)
                if resp_status.get("status") == _STATUS_OK:
                    created = data.get("request") or {}
                    return {"ok": True, "id": created.get("id"), "display_id": created.get("display_id")}
                return {"ok": False, "error": explain(str(resp_status.get("messages") or resp_status)), "raw": data}
    except Exception as e:
        return {"ok": False, "error": explain(str(e))}


async def _call(method: str, path: str, payload: Optional[dict] = None, timeout: int = 15) -> dict:
    """One SDP API v3 call with the `input_data` form encoding the API wants. Never raises: {"ok": bool, "data": ..., "error": str}."""
    if url_problem():
        return {"ok": False, "error": url_problem()}
    headers = dict(_headers())
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request(method, f"{_config['url']}/api/v3/{path.lstrip('/')}",
                                       data={"input_data": json.dumps(payload)} if payload is not None else None, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    return {"ok": False, "error": explain(f"HTTP {resp.status}: {(await resp.text())[:300]}")}
                st = _status_of(data)
                if st.get("status") == _STATUS_OK:
                    return {"ok": True, "data": data}
                return {"ok": False, "error": explain(str(st.get("messages") or st or f"HTTP {resp.status}")[:400]), "data": data}
    except Exception as e:
        return {"ok": False, "error": explain(str(e))}


async def close_ticket(request_id: str, resolution: str, closure_code: Optional[str] = None) -> dict:
    """Resolves and closes a request: a note with the text (always - it stays visible whatever follows), the resolution, then the close with
    its closure info. When this instance refuses the close (a closure code it does not have, mandatory fields of its own ...) the request is
    left "Resolved" instead, with the reason in "error"/"steps". Returns {"ok": bool, "closed": bool, "steps": [...], "error": str|None};
    ok is True when the request ended Closed or at least Resolved.

    Written from ManageEngine's API v3 reference (requests/{id}/notes, /resolutions, /close); not yet exercised against a live instance
    here, which is why every step is reported and the test button of the settings page exists."""
    steps: list = []
    code = closure_code or _config["ticket"].get("closure_code") or "Success"
    r = await _call("POST", f"requests/{request_id}/notes", {"request_note": {"description": resolution, "show_to_requester": True, "notify_technician": False}})
    steps.append({"step": "note", "ok": r["ok"], "error": r.get("error")})
    r = await _call("PUT", f"requests/{request_id}/resolutions", {"resolution": {"content": resolution}})
    steps.append({"step": "resolution", "ok": r["ok"], "error": r.get("error")})
    closure = {"requester_ack_resolution": False, "requester_ack_comments": resolution, "closure_comments": resolution}
    for with_code in (True, False):
        info = dict(closure)
        if with_code and code:
            info["closure_code"] = {"name": code}
        r = await _call("PUT", f"requests/{request_id}/close", {"request": {"closure_info": info}})
        steps.append({"step": "close" + ("" if with_code else " (no closure code)"), "ok": r["ok"], "error": r.get("error")})
        if r["ok"]:
            return {"ok": True, "closed": True, "steps": steps, "error": None}
        if not code:
            break
    r = await _call("PUT", f"requests/{request_id}", {"request": {"status": {"name": "Resolved"}}})
    steps.append({"step": "status Resolved", "ok": r["ok"], "error": r.get("error")})
    return {"ok": r["ok"], "closed": False, "steps": steps, "error": next((s["error"] for s in steps if s["step"].startswith("close") and s["error"]), None)}


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
