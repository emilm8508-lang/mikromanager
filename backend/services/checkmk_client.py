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
from typing import Optional

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
    # Users naturally paste the URL straight from their browser's address
    # bar while looking at Checkmk, which already ends in "/<site>/check_mk"
    # — strip that back off before appending it again, so pasting the full
    # browser URL alongside the site name doesn't build a duplicated,
    # 404ing path (confirmed live: url=".../sanmed/check_mk" + site="sanmed"
    # produced ".../sanmed/check_mk/sanmed/check_mk/api/1.0").
    url = _config["url"].rstrip("/")
    site = _config["site"]
    if url.endswith("/check_mk"):
        url = url[: -len("/check_mk")]
    if site and url.endswith(f"/{site}"):
        url = url[: -len(f"/{site}")]
    return f"{url}/{site}/check_mk/api/1.0"


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


def _headers() -> dict:
    # Official Checkmk REST API examples (docs.checkmk.com/latest/en/rest_api.html)
    # always send Accept: application/json alongside the Bearer header -
    # without it, some setups content-negotiate to an HTML response instead.
    return {"Authorization": f"Bearer {_config['username']} {_config['secret']}",
            "Accept": "application/json"}


async def test_connection() -> dict:
    """GET the host_config collection — cheap, read-only, no specific host
    name needed. NOT the bare API root: confirmed (Checkmk forum reports of
    the same "branded 404" symptom seen live here) that Checkmk's REST API
    has no route at all for "/check_mk/api/{ver}/" itself - an unmapped path
    falls through to the classic web GUI's own themed "Page not found",
    which is indistinguishable from a real routing problem unless you know
    to hit an actual resource instead."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    url = _base_url() + "/domain-types/host_config/collections/all"
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=_headers(),
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return {"ok": True, "host_count": len(data.get("value", []))}
                text = (await resp.text())[:300]
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def list_host_ips() -> Optional[dict]:
    """domain-types/host_config/collections/all (configuration domain, NOT
    live monitoring state) -> {host_name: ip_or_None}, used by
    checkmk_monitor.py to resolve a host/service to an IP for correlation
    against our own Device/LinuxHost/WindowsHost tables. Returns None (not
    {}) on failure - a transient error must never look like "no hosts"."""
    if not is_configured():
        return None
    url = _base_url() + "/domain-types/host_config/collections/all"
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=_headers(),
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                out = {}
                for h in data.get("value", []):
                    if not isinstance(h, dict):
                        continue
                    name = h.get("id") or h.get("title")
                    if not name:
                        continue
                    attrs = ((h.get("extensions") or {}).get("attributes")) or {}
                    out[name] = attrs.get("ipaddress") or None
                return out
    except Exception as e:
        print(f"[checkmk] list_host_ips error: {e}")
        return None


async def _query_monitoring(domain: str, columns: list) -> Optional[list]:
    """Shared GET against a Checkmk *monitoring* domain-type (service/host -
    live status, distinct from the host_config *configuration* domain
    above), no state filter (fetch everything - list_service_states()/
    list_host_states() need the full list every cycle to detect a recovery,
    not just current problems, same reasoning as prtg_client.list_sensors())."""
    if not is_configured():
        return None
    url = _base_url() + f"/domain-types/{domain}/collections/all"
    # Checkmk expects repeated "columns=" query params (confirmed via the
    # official curl examples: --data-urlencode 'columns=x' repeated per
    # column) - a list-of-tuples is what aiohttp encodes as repeated keys;
    # a plain {"columns": [...]} dict value would NOT encode the same way.
    params = [("columns", c) for c in columns]
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=_headers(), params=params,
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                out = []
                for row in data.get("value", []):
                    if not isinstance(row, dict):
                        continue
                    ext = row.get("extensions") or {}
                    if isinstance(ext, dict) and ext:
                        out.append(ext)
                return out
    except Exception as e:
        print(f"[checkmk] _query_monitoring({domain}) error: {e}")
        return None


async def list_service_states() -> Optional[list]:
    """Every service's live state: {host_name, description, state,
    plugin_output}. state: 0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN."""
    return await _query_monitoring("service", ["host_name", "description", "state", "plugin_output"])


async def list_host_states() -> Optional[list]:
    """Every host's live state: {name, state, plugin_output}.
    state: 0=UP, 1=DOWN, 2=UNREACHABLE."""
    return await _query_monitoring("host", ["name", "state", "plugin_output"])


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
