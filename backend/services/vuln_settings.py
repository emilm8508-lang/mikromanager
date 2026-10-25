"""
Settings of the vulnerability data sources that can be changed from the application instead of an environment variable of the agent's process.

Today that is the NVD API key. NVD answers a keyless client about 5 requests per 30 seconds and a client with a (free) key about ten times as many, so
the weekly scan of a big network - and the lookup of the CVEs of a Windows host's missing updates - finishes in a fraction of the time with one. The key is
requested for free (an e-mail address) at https://nvd.nist.gov/developers/request-an-api-key and entered once on the Vulnerabilities page; it is kept
Fernet-encrypted in data/vuln_settings.json like the other connector secrets. The MIKROTIK_NVD_API_KEY environment variable still works as a fallback.
"""
import asyncio
import json
import os
from typing import Optional

from services.crypto import encrypt, decrypt

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vuln_settings.json")
_state = {"nvd_key": ""}                 # plaintext in memory, encrypted on disk
NVD_INTERVAL_KEY = 1.2                   # seconds between requests with a key (NVD: 50 per 30 s)
NVD_INTERVAL_NOKEY = 6.5                 # without one (NVD: 5 per 30 s)
NVD_INTERVAL_CENTRAL = 0.05              # through Central: it keeps NVD's spacing for all agents itself, and answers repeated lookups from its cache


def _load() -> None:
    if not os.path.exists(_PATH):
        return
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        enc = saved.get("nvd_key")
        if enc:
            _state["nvd_key"] = decrypt(enc)
    except Exception as e:
        print(f"[vuln_settings] could not read the stored NVD key - enter it again in the application: {e}")


def _persist() -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    data = {"nvd_key": encrypt(_state["nvd_key"]) if _state["nvd_key"] else ""}
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, _PATH)


def nvd_key() -> str:
    """The key the scanner uses: the one entered in the application, else the environment variable, else ''."""
    return _state["nvd_key"] or os.environ.get("MIKROTIK_NVD_API_KEY", "")


def nvd_mode() -> str:
    """Where the scanner's NVD lookups go: "local" (a key of this agent), "central" (the organisation's key, kept in Central - the agent never has it) or
    "keyless" (NVD directly without a key: slow)."""
    if nvd_key():
        return "local"
    from services import nvd_central
    return "central" if nvd_central.available() else "keyless"


def nvd_backend():
    """What the scanner calls for NVD (searchCPE / searchCVE): nvdlib itself with a key of this agent, else the Central-first backend (which asks NVD
    directly, keyless, whenever Central cannot help)."""
    if nvd_key():
        import nvdlib
        return nvdlib
    from services import nvd_central
    return nvd_central.backend


def nvd_interval() -> float:
    mode = nvd_mode()
    return NVD_INTERVAL_KEY if mode == "local" else NVD_INTERVAL_CENTRAL if mode == "central" else NVD_INTERVAL_NOKEY


def status() -> dict:
    from services import nvd_central
    src = "app" if _state["nvd_key"] else "env" if os.environ.get("MIKROTIK_NVD_API_KEY") else None
    return {"nvd": {"configured": src is not None, "source": src, "interval_sec": nvd_interval(), "mode": nvd_mode(), "central": nvd_central.status()}}


def set_nvd_key(key: Optional[str]) -> dict:
    """Stores the key (None / '' removes the one entered in the application; the environment variable, if any, stays)."""
    _state["nvd_key"] = (key or "").strip()
    _persist()
    return status()


def _check_sync(key: str) -> Optional[str]:
    """None when NVD accepts the key, else why not. One cheap request (a single well-known CVE)."""
    import nvdlib
    try:
        r = nvdlib.searchCVE(cveId="CVE-2021-44228", key=key)
    except Exception as e:
        return f"{type(e).__name__}: {e}"[:300]
    return None if r else "NVD returned nothing for a known CVE"


async def check_nvd_key(key: str) -> Optional[str]:
    try:
        return await asyncio.wait_for(asyncio.get_event_loop().run_in_executor(None, _check_sync, key), timeout=40)
    except asyncio.TimeoutError:
        return "NVD did not answer in time"


def has_secret() -> bool:
    return bool(_state["nvd_key"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    """See prtg_client.reencrypt_with_keys() - identical pattern."""
    if not os.path.exists(_PATH):
        return 0
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        enc = saved.get("nvd_key")
        if not enc:
            return 0
        plaintext = old_fernet.decrypt(enc.encode()).decode()
    except Exception:
        return 0
    saved["nvd_key"] = new_fernet.encrypt(plaintext.encode()).decode()
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(saved, f)
    os.replace(tmp, _PATH)
    _state["nvd_key"] = plaintext
    return 1


_load()
