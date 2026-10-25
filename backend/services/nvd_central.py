"""
NVD lookups through Central: the agent uses the organisation's NVD API key without having it.

The NVD API key is the organisation's, not the client's: it is entered once in Central (ovh/nvd.php keeps it in the central database and returns it to nobody),
and the vulnerability scan of every agent asks Central for its NVD lookups. Central adds the key, remembers the answers (one product asked by many clients is one
request to NVD) and keeps NVD's spacing between requests across all agents. The agent never holds the key; its request is signed with the same tenant key as its
reports (ingest.php), so only a registered agent can ask.

`backend` is the object the scanner uses instead of the `nvdlib` module (it has the two functions the scanner calls, `searchCPE` and `searchCVE`, and returns the
same kind of objects): it asks Central first and falls back to asking NVD directly - slowly, without a key - when Central cannot help:

    Central not reachable / not deployed / an error     -> NVD directly for the next 15 minutes (then Central is tried again)
    Central has no key set (503 no_key)                  -> NVD directly for the next hour
    Central's queue for NVD is too long (429)            -> the lookup fails now (the scanner does not take that for "no vulnerabilities") and is retried later

What the scanner already knows stays on the agent (the findings are cached in its database), so a Central outage only delays *new* lookups.
"""
import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from typing import Callable, List, Optional

DOWN_SEC = 15 * 60
NO_KEY_SEC = 60 * 60
TIMEOUT_SEC = 45

_state = {"down_until": 0.0, "no_key_until": 0.0, "last_error": None, "last_error_at": None, "last_ok_at": None,
          "via_central": 0, "cache_hits": 0, "fallbacks": 0}


class CentralNvdError(Exception):
    pass


class CentralNoKey(CentralNvdError):
    pass


class CentralBusy(CentralNvdError):
    pass


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def url() -> Optional[str]:
    """Central's NVD endpoint: next to the ingest address the agent already reports to (.../ingest.php -> .../nvd.php), or None when it has none."""
    from services import uplink
    if not uplink.is_configured():
        return None
    base = str(uplink._config["url"]).split("?")[0]
    if "://" not in base or "/" not in base.split("://", 1)[1]:
        return None
    return base.rsplit("/", 1)[0] + "/nvd.php?action=lookup"


def available() -> bool:
    now = time.time()
    return url() is not None and now >= _state["down_until"] and now >= _state["no_key_until"]


def status() -> dict:
    now = time.time()
    return {"url_set": url() is not None, "available": available(), "no_key": now < _state["no_key_until"], "down": now < _state["down_until"],
            "last_error": _state["last_error"], "last_error_at": _state["last_error_at"], "last_ok_at": _state["last_ok_at"],
            "via_central": _state["via_central"], "cache_hits": _state["cache_hits"], "fallbacks": _state["fallbacks"]}


def _note_error(e: Exception) -> None:
    _state["last_error"] = f"{type(e).__name__}: {e}"[:300]
    _state["last_error_at"] = _now_iso()


def _post(kind: str, params: dict) -> dict:
    """One signed request to Central. The signature is the one of the reports: HMAC-SHA256(api_key, timestamp | body)."""
    import requests
    from services import uplink
    cfg = uplink._config
    body = json.dumps({"kind": kind, "params": params}, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time()))
    sig = hmac.new(cfg["api_key"].encode(), (ts + "|").encode() + body, hashlib.sha256).hexdigest()
    r = requests.post(url(), data=body, timeout=TIMEOUT_SEC, headers={
        "Authorization": f"Bearer {cfg['api_key']}", "X-Tenant": cfg["tenant"], "X-Timestamp": ts, "X-Signature": sig,
        "Content-Type": "application/json", "User-Agent": "MikroManager-Agent/1.2"})
    if r.status_code == 200:
        _state["via_central"] += 1
        if r.headers.get("X-Nvd-Cache") == "hit":
            _state["cache_hits"] += 1
        return r.json()
    try:
        detail = str((r.json() or {}).get("error") or "")
    except Exception:
        detail = ""
    if r.status_code == 503 and detail == "no_key":
        raise CentralNoKey("Central has no NVD key")
    if r.status_code == 429:
        raise CentralBusy("Central's queue for NVD is too long")
    raise CentralNvdError(f"HTTP {r.status_code} {detail}".strip())


# ── NVD's JSON -> the objects the scanner reads (the attributes nvdlib's objects have) ──────────────────────────────

def cve_object(item: dict) -> SimpleNamespace:
    """One element of "vulnerabilities" of NVD API 2.0 -> id, published, url, descriptions[], and v31score / v31severity (else v30, else v2) when present."""
    c = (item or {}).get("cve") or {}
    ns = SimpleNamespace(id=c.get("id"), published=c.get("published"), url=f"https://nvd.nist.gov/vuln/detail/{c.get('id')}",
                         descriptions=[SimpleNamespace(lang=d.get("lang"), value=d.get("value")) for d in c.get("descriptions") or [] if isinstance(d, dict)])
    metrics = c.get("metrics") or {}
    for key, prefix in (("cvssMetricV31", "v31"), ("cvssMetricV30", "v30"), ("cvssMetricV2", "v2")):
        arr = [m for m in metrics.get(key) or [] if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)]
        if not arr:
            continue
        m = next((x for x in arr if x.get("type") == "Primary"), arr[0])
        data = m["cvssData"]
        setattr(ns, prefix + "score", data.get("baseScore"))
        setattr(ns, prefix + "severity", data.get("baseSeverity") or m.get("baseSeverity"))     # CVSS v2 keeps the severity beside cvssData, not in it
    return ns


def _cves(data: dict) -> List[SimpleNamespace]:
    return [cve_object(v) for v in (data or {}).get("vulnerabilities") or [] if isinstance(v, dict)]


def _cpes(data: dict) -> List[SimpleNamespace]:
    return [SimpleNamespace(cpeName=(p.get("cpe") or {}).get("cpeName")) for p in (data or {}).get("products") or [] if isinstance(p, dict)]


class Backend:
    """What the scanner calls instead of the nvdlib module: the same two functions, Central first, NVD directly when Central cannot help."""

    def _run(self, kind: str, params: dict, convert: Callable, direct: str, direct_kw: dict) -> list:
        if available():
            try:
                out = convert(_post(kind, {k: v for k, v in params.items() if v not in (None, "")}))
                _state["last_ok_at"] = _now_iso()
                return out
            except CentralNoKey as e:
                _state["no_key_until"] = time.time() + NO_KEY_SEC
                _note_error(e)
            except CentralBusy as e:
                _note_error(e)
                raise TimeoutError(str(e))               # not a reason to go around Central: the lookup fails now and is retried later
            except Exception as e:                       # not reachable, not deployed (404), a server error ...
                _state["down_until"] = time.time() + DOWN_SEC
                _note_error(e)
        _state["fallbacks"] += 1
        import nvdlib
        from services import vuln_settings
        return getattr(nvdlib, direct)(key=vuln_settings.nvd_key() or None, **direct_kw) or []

    def searchCPE(self, keywordSearch: Optional[str] = None, limit: Optional[int] = None, key: Optional[str] = None, **kw) -> list:
        return self._run("cpes", {"keywordSearch": keywordSearch, "resultsPerPage": limit}, _cpes, "searchCPE",
                         {k: v for k, v in (("keywordSearch", keywordSearch), ("limit", limit)) if v is not None})

    def searchCVE(self, cveId: Optional[str] = None, cpeName: Optional[str] = None, keywordSearch: Optional[str] = None, limit: Optional[int] = None,
                  key: Optional[str] = None, **kw) -> list:
        return self._run("cves", {"cveId": cveId, "cpeName": cpeName, "keywordSearch": keywordSearch, "resultsPerPage": limit}, _cves, "searchCVE",
                         {k: v for k, v in (("cveId", cveId), ("cpeName", cpeName), ("keywordSearch", keywordSearch), ("limit", limit)) if v is not None})


backend = Backend()
