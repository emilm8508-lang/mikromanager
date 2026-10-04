"""
ManageEngine Endpoint Central (on-premise) connector — settings, login,
connectivity test and a read-only "fetch raw sample" diagnostic, for
pulling client-workstation patch/inventory state into Central.

Per-tenant, agent-side, exactly like services/servicedesk_client.py and
prtg_client.py: the client's Endpoint Central server is on-premise
behind their own firewall, so only the agent (same network) can reach
it, never OVH. Config persisted to a small JSON file under data/, the
password encrypted at rest with services.crypto (same key-rotation
lifecycle as the other connectors).

Auth: Endpoint Central's REST API logs in with username + base64-encoded
password and returns a token that's sent back in the `Authorization`
header. The login call differs by API version: v1.4 takes a JSON POST to
/api/1.4/desktop/authentication, older v1.3 a GET with query parameters
(both documented by ManageEngine). Which one a given install accepts
isn't knowable without trying, so login() tries 1.4 first and falls back
to 1.3. The token's exact location in the JSON response isn't documented
publicly either, so it's found by searching the response for an
"auth_token" key rather than hardcoding one path.

Deliberately NO data collection yet beyond fetch_sample(): the exact
response shapes of the inventory/patch endpoints weren't verifiable
without a real instance (same situation as ServiceDesk Plus), so the
Central pages get built on shapes confirmed live via fetch_sample(), not
guessed.
"""
import base64
import json
import os
from typing import Any, Optional

import aiohttp

from services.crypto import encrypt, decrypt

_config = {
    "url": "",            # e.g. https://endpoint.klient.local:8383
    "username": "",
    "password": "",       # plaintext in memory; encrypted on disk
    "auth_type": "local_authentication",   # or "ad_authentication"
    "domain": "",         # only for ad_authentication
    "totp_secret": "",    # base32 secret of the account's authenticator app; only for 2FA accounts
    "verify_ssl": True,
}
_AUTH_TYPES = ("local_authentication", "ad_authentication")

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "endpointcentral.json")
_SAMPLE_MAX_CHARS = 20000


def is_configured() -> bool:
    return bool(_config["url"] and _config["username"] and _config["password"])


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "username": _config["username"],
        "has_password": bool(_config["password"]),
        "has_totp": bool(_config["totp_secret"]),
        "auth_type": _config["auth_type"],
        "domain": _config["domain"],
        "verify_ssl": _config["verify_ssl"],
    }


def configure(url: str, username: str, password: str = "", auth_type: str = "local_authentication",
              domain: str = "", verify_ssl: bool = True, totp_secret: str = "") -> dict:
    """Empty password/totp_secret mean 'keep existing' — mirrors prtg_client.configure()."""
    _config["url"] = url.rstrip("/")
    _config["username"] = username
    if password:
        _config["password"] = password
    if totp_secret:
        _config["totp_secret"] = totp_secret.replace(" ", "").upper()
    _config["auth_type"] = auth_type if auth_type in _AUTH_TYPES else "local_authentication"
    _config["domain"] = domain
    _config["verify_ssl"] = verify_ssl
    _persist()
    return status()


def _persist():
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    to_save = dict(_config)
    for field in ("password", "totp_secret"):
        if to_save[field]:
            to_save[field] = encrypt(to_save[field])
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
        for key in ("url", "username", "auth_type", "domain"):
            if saved.get(key):
                _config[key] = saved[key]
        if _config["auth_type"] not in _AUTH_TYPES:
            _config["auth_type"] = "local_authentication"
        if "verify_ssl" in saved:
            _config["verify_ssl"] = bool(saved["verify_ssl"])
        for field in ("password", "totp_secret"):
            if saved.get(field):
                try:
                    _config[field] = decrypt(saved[field])
                except Exception:
                    print(f"[endpointcentral] could not decrypt stored {field} — reconfigure via UI")
    except Exception as e:
        print(f"[endpointcentral] config load error: {e}")


_load()


def _find_token(obj: Any) -> Optional[str]:
    """Searches a login response for an "auth_token" value at any depth —
    its exact path isn't publicly documented (see module docstring)."""
    if isinstance(obj, dict):
        tok = obj.get("auth_token")
        if isinstance(tok, str) and tok:
            return tok
        for v in obj.values():
            found = _find_token(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_token(v)
            if found:
                return found
    return None


_TWO_FACTOR_MSG = ("konto ma włączone 2FA (kod OTP) — podaj sekret TOTP tego konta (klucz z aplikacji "
                   "Authenticator) albo użyj osobnego konta API bez 2FA")


def _two_factor_data(data: Any) -> Optional[dict]:
    """The login answers HTTP 200 with a two_factor_data block (and no
    auth_token) when the account has 2FA on — seen live against a real
    instance. Returns that block, or None if 2FA isn't what's blocking."""
    try:
        tf = data["message_response"]["authentication"]["two_factor_data"]
        if tf.get("is_TwoFactor_Enabled") and _find_token(data) is None:
            return tf
    except Exception:
        pass
    return None


async def _otp_validate(session: aiohttp.ClientSession, uid: str) -> dict:
    """Second login step for 2FA accounts (documented: POST
    /api/1.4/desktop/authentication/otpValidate with uid + otp). The OTP is
    computed from the stored TOTP secret, so a background poller can re-login
    whenever the token expires without anyone typing a code."""
    if not _config["totp_secret"]:
        return {"ok": False, "error": _TWO_FACTOR_MSG}
    try:
        import pyotp
        otp = pyotp.TOTP(_config["totp_secret"]).now()
    except Exception as e:
        return {"ok": False, "error": f"niepoprawny sekret TOTP: {e}"}
    try:
        async with session.post(f"{_config['url']}/api/1.4/desktop/authentication/otpValidate",
                                 json={"uid": uid, "otp": otp, "rememberme_enabled": False},
                                 timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json(content_type=None)
            token = _find_token(data)
            if resp.status == 200 and token:
                return {"ok": True, "token": token, "api_version": "1.4 (2FA)"}
            return {"ok": False, "error": f"OTP: HTTP {resp.status} {str(data)[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"OTP: {e}"}

async def login() -> dict:
    """Returns {"ok": True, "token": str, "api_version": "1.4"|"1.3"} or
    {"ok": False, "error": str}. Never raises."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    b64_pw = base64.b64encode(_config["password"].encode("utf-8")).decode()
    body = {"username": _config["username"], "password": b64_pw, "auth_type": _config["auth_type"]}
    if _config["auth_type"] == "ad_authentication" and _config["domain"]:
        body["domainName"] = _config["domain"]

    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    errors = []
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # v1.4: JSON POST
            try:
                async with session.post(f"{_config['url']}/api/1.4/desktop/authentication", json=body,
                                         timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    data = await resp.json(content_type=None)
                    token = _find_token(data)
                    if resp.status == 200 and token:
                        return {"ok": True, "token": token, "api_version": "1.4"}
                    tf = _two_factor_data(data)
                    if tf:
                        return await _otp_validate(session, tf.get("unique_userID", ""))
                    errors.append(f"1.4: HTTP {resp.status} {str(data)[:200]}")
            except Exception as e:
                errors.append(f"1.4: {e}")
            # v1.3: GET with query parameters
            try:
                async with session.get(f"{_config['url']}/api/1.3/desktop/authentication", params=body,
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    data = await resp.json(content_type=None)
                    token = _find_token(data)
                    if resp.status == 200 and token:
                        return {"ok": True, "token": token, "api_version": "1.3"}
                    errors.append(f"1.3: HTTP {resp.status} {str(data)[:200]}")
            except Exception as e:
                errors.append(f"1.3: {e}")
    except Exception as e:
        errors.append(str(e))
    return {"ok": False, "error": " | ".join(errors)}


async def test_connection() -> dict:
    """Login only — proves URL + credentials work. Never raises."""
    res = await login()
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}
    return {"ok": True, "api_version": res["api_version"]}


async def fetch_sample(path: str) -> dict:
    """Read-only GET of one API path (must start with /api/) so the real
    response shape can be inspected before any page is built on it —
    the whole point of this module being connector-only for now. Output
    truncated; never raises."""
    if not path.startswith("/api/") or ".." in path or "://" in path:
        return {"ok": False, "error": "path must start with /api/"}
    res = await login()
    if not res["ok"]:
        return {"ok": False, "error": res["error"]}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(f"{_config['url']}{path}", headers={"Authorization": res["token"]},
                                    timeout=aiohttp.ClientTimeout(total=30)) as resp:
                text = await resp.text()
                # Errors come back as HTTP 200 with "status":"error" in the body.
                body_ok = '"status":"error"' not in text.replace(" ", "")
                return {"ok": resp.status == 200 and body_ok, "status": resp.status,
                        "body": text[:_SAMPLE_MAX_CHARS], "truncated": len(text) > _SAMPLE_MAX_CHARS}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def has_secret() -> bool:
    return bool(_config["password"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    if not os.path.exists(_CONFIG_PATH):
        return 0
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
    except Exception:
        return 0
    count = 0
    for field in ("password", "totp_secret"):
        if not saved.get(field):
            continue
        try:
            plaintext = old_fernet.decrypt(saved[field].encode()).decode()
        except Exception:
            continue
        saved[field] = new_fernet.encrypt(plaintext.encode()).decode()
        _config[field] = plaintext
        count += 1
    if not count:
        return 0
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)
    return count
