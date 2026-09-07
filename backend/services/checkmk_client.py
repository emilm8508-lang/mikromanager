"""
Check_MK (Checkmk) connector — connection settings for the monitoring-
aggregation connectors planned in doktorat/plan-architektura-ai-anomalie.md
(§3.4/§4): MikroManager pulls host/service status from a client's existing
Checkmk install via its REST API, alongside Mikrotik/Windows/Linux/Dell
iDRAC. Mirrors services/prtg_client.py exactly — see that module's
docstring for the encryption/rotation rationale.

Uses an automation user (Setup > Users > "automation user" in Checkmk),
authenticated as `Authorization: Bearer <username> <secret>` against
`{url}/{site}/check_mk/api/1.0/`.
"""
import json
import os

import aiohttp

from services.crypto import encrypt, decrypt

_config = {
    "url": "",        # e.g. https://checkmk.klient.local
    "site": "",        # Checkmk site name
    "username": "",    # automation user, not secret
    "secret": "",      # plaintext in memory; encrypted on disk
    "verify_ssl": True,
}

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "checkmk.json")


def is_configured() -> bool:
    return bool(_config["url"] and _config["site"] and _config["username"] and _config["secret"])


def _base_url() -> str:
    return f"{_config['url']}/{_config['site']}/check_mk/api/1.0"


def status() -> dict:
    return {
        "enabled": is_configured(),
        "url": _config["url"],
        "site": _config["site"],
        "username": _config["username"],
        "has_secret": bool(_config["secret"]),
        "verify_ssl": _config["verify_ssl"],
    }


def configure(url: str, site: str, username: str, secret: str = "", verify_ssl: bool = True) -> dict:
    """Empty secret means 'keep existing' — same convention as
    prtg_client.configure()/uplink.configure()."""
    _config["url"] = url.rstrip("/")
    _config["site"] = site.strip().strip("/")
    _config["username"] = username
    if secret:
        _config["secret"] = secret
    _config["verify_ssl"] = verify_ssl
    _persist()
    return status()


def _persist():
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    to_save = dict(_config)
    if to_save["secret"]:
        to_save["secret"] = encrypt(to_save["secret"])
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
        for k in ("url", "site", "username"):
            if saved.get(k):
                _config[k] = saved[k]
        if "verify_ssl" in saved:
            _config["verify_ssl"] = bool(saved["verify_ssl"])
        secret = saved.get("secret")
        if secret:
            try:
                _config["secret"] = decrypt(secret)
            except Exception:
                print("[checkmk] could not decrypt stored secret — reconfigure via UI")
    except Exception as e:
        print(f"[checkmk] config load error: {e}")


_load()


async def test_connection() -> dict:
    """GET the API root — returns a small JSON index on success, 401 on
    bad credentials. Cheap, read-only, no host/service names needed."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    url = _base_url() + "/"
    headers = {"Authorization": f"Bearer {_config['username']} {_config['secret']}"}
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return {"ok": True}
                text = (await resp.text())[:300]
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def has_secret() -> bool:
    return bool(_config["secret"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    """See prtg_client.reencrypt_with_keys() — identical pattern."""
    if not os.path.exists(_CONFIG_PATH):
        return 0
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
    except Exception:
        return 0
    secret = saved.get("secret")
    if not secret:
        return 0
    try:
        plaintext = old_fernet.decrypt(secret.encode()).decode()
    except Exception:
        return 0
    saved["secret"] = new_fernet.encrypt(plaintext.encode()).decode()
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)
    _config["secret"] = plaintext
    return 1
