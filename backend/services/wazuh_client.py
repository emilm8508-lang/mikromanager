"""
Wazuh connector — pulls alert data from a client's existing Wazuh
deployment (SIEM/XDR: intrusion detection, log analysis, file-integrity
monitoring) into the same monitoring-aggregation family as
services/prtg_client.py and services/checkmk_client.py (see that module's
docstring for the encryption/rotation rationale — this one mirrors it).

Unlike PRTG/Checkmk, a real Wazuh deployment is actually TWO separate HTTP
APIs on two separate ports — confirmed against Wazuh's own documentation
(documentation.wazuh.com), not guessed:

  - Manager API (default port 55000) — agent management, vulnerability
    detection, SCA compliance, syscollector inventory. Auth: POST
    /security/user/authenticate with Basic auth -> short-lived JWT.
  - Indexer API (default port 9200, OpenSearch-based) — the actual alert
    stream (rule matches: intrusion attempts, FIM changes, log-based
    detections). Auth: plain HTTP Basic on every request, using its OWN
    username/password — not the manager's JWT, and possibly a different
    host entirely in a multi-node deployment.

This module deliberately only talks to the Indexer (alerts) for now — the
Manager API's vulnerability/SCA/inventory data overlaps with what this app
already collects itself (services/vuln_scan.py, services/compliance.py,
services/inventory.py); pulling the same kind of data a second time would
just create two disagreeing answers to the same question with no clear
benefit. The alert stream is the one thing Wazuh does that this app has no
equivalent of at all — most valuable for Windows hosts, where this app's
own visibility is limited to patch counts (services/windows_manage.py),
nothing like Wazuh's log-based/FIM detection.
"""
import json
import os
from typing import Optional

import aiohttp

from services.crypto import encrypt, decrypt

_config = {
    "indexer_url": "",       # e.g. https://wazuh.klient.local:9200
    "indexer_username": "",
    "indexer_password": "",  # plaintext in memory; encrypted on disk
    "verify_ssl": True,
}

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wazuh.json")


def is_configured() -> bool:
    return bool(_config["indexer_url"] and _config["indexer_username"] and _config["indexer_password"])


def status() -> dict:
    return {
        "enabled": is_configured(),
        "indexer_url": _config["indexer_url"],
        "indexer_username": _config["indexer_username"],
        "has_password": bool(_config["indexer_password"]),
        "verify_ssl": _config["verify_ssl"],
    }


def configure(indexer_url: str, indexer_username: str, indexer_password: str = "", verify_ssl: bool = True) -> dict:
    """Empty password means 'keep existing' — same convention as
    prtg_client.configure()/checkmk_client.configure()."""
    _config["indexer_url"] = indexer_url.rstrip("/")
    _config["indexer_username"] = indexer_username
    if indexer_password:
        _config["indexer_password"] = indexer_password
    _config["verify_ssl"] = verify_ssl
    _persist()
    return status()


def _persist():
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    to_save = dict(_config)
    if to_save["indexer_password"]:
        to_save["indexer_password"] = encrypt(to_save["indexer_password"])
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
        for k in ("indexer_url", "indexer_username"):
            if saved.get(k):
                _config[k] = saved[k]
        if "verify_ssl" in saved:
            _config["verify_ssl"] = bool(saved["verify_ssl"])
        password = saved.get("indexer_password")
        if password:
            try:
                _config["indexer_password"] = decrypt(password)
            except Exception:
                print("[wazuh] could not decrypt stored password — reconfigure via UI")
    except Exception as e:
        print(f"[wazuh] config load error: {e}")


_load()


def _auth() -> aiohttp.BasicAuth:
    return aiohttp.BasicAuth(_config["indexer_username"], _config["indexer_password"])


async def test_connection() -> dict:
    """GET the indexer root — cheap, read-only, confirms auth + reachability
    without depending on the wazuh-alerts-* index already existing (a
    brand new/quiet deployment might not have created it yet)."""
    if not is_configured():
        return {"ok": False, "error": "not configured"}
    url = _config["indexer_url"].rstrip("/") + "/"
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector, auth=_auth()) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return {"ok": True, "cluster_name": data.get("cluster_name"),
                             "version": (data.get("version") or {}).get("number")}
                text = (await resp.text())[:300]
                return {"ok": False, "error": f"HTTP {resp.status}: {text}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def list_recent_alerts(since_iso: str, min_level: int, size: int = 500) -> Optional[list]:
    """POST {indexer_url}/wazuh-alerts-*/_search — every alert (rule match)
    newer than since_iso (an absolute ISO8601 timestamp, or OpenSearch date
    math like "now-1h" for a first-ever poll) at or above min_level, oldest
    first (so the caller can safely advance its watermark to the LAST
    item's timestamp without gaps).

    Defensive per-document parsing — Wazuh's exact document shape can vary
    slightly by version/ruleset, so a malformed hit is skipped rather than
    aborting the whole batch, same philosophy as vuln_scan.py's
    _audit_entries_to_findings(). Returns None (not []) on connection/auth/
    query failure — a transient error must never look like "no new
    alerts", or the caller's watermark would silently skip past whatever
    happened during the outage."""
    if not is_configured():
        return None
    url = _config["indexer_url"].rstrip("/") + "/wazuh-alerts-*/_search"
    body = {
        "size": max(1, min(size, 1000)),
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gt": since_iso}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }
    connector = aiohttp.TCPConnector(ssl=_config["verify_ssl"])
    try:
        async with aiohttp.ClientSession(connector=connector, auth=_auth()) as session:
            async with session.post(url, json=body, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
    except Exception as e:
        print(f"[wazuh] list_recent_alerts error: {e}")
        return None

    out = []
    for hit in ((data.get("hits") or {}).get("hits") or []):
        src = hit.get("_source") if isinstance(hit, dict) else None
        if not isinstance(src, dict):
            continue
        ts = src.get("@timestamp")
        if not ts:
            continue
        agent = src.get("agent") or {}
        rule = src.get("rule") or {}
        out.append({
            "timestamp": ts,
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "agent_ip": agent.get("ip"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "rule_id": rule.get("id"),
        })
    return out


def has_secret() -> bool:
    return bool(_config["indexer_password"])


def reencrypt_with_keys(old_fernet, new_fernet) -> int:
    """See prtg_client.reencrypt_with_keys() — identical pattern."""
    if not os.path.exists(_CONFIG_PATH):
        return 0
    try:
        with open(_CONFIG_PATH) as f:
            saved = json.load(f)
    except Exception:
        return 0
    password = saved.get("indexer_password")
    if not password:
        return 0
    try:
        plaintext = old_fernet.decrypt(password.encode()).decode()
    except Exception:
        return 0
    saved["indexer_password"] = new_fernet.encrypt(plaintext.encode()).decode()
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(saved, f, indent=2)
    os.replace(tmp, _CONFIG_PATH)
    _config["indexer_password"] = plaintext
    return 1
