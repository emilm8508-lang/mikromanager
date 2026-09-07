"""
Check_MK service/host problem monitoring — detects a service or host's
live state changing between "ok" and "needs attention" and reports it via
alert_events. Direct sibling of services/prtg_monitor.py — see that
module's docstring for the full rationale (state-diff pattern copied from
tunnel_monitor.py, alert_events mechanism, IP-correlation against our own
Device/LinuxHost/WindowsHost tables).

Two independent problem types tracked here (both from Checkmk's live
*monitoring* domain-types, not its host_config *configuration* domain):
services (state 0=OK/1=WARN/2=CRIT/3=UNKNOWN) and hosts (state 0=UP/
1=DOWN/2=UNREACHABLE) — a service's host is resolved to an IP via a
separate host_config query (services/checkmk_client.list_host_ips()) for
the same local-name correlation prtg_monitor.py does.
"""
import json
import os
import time
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, LinuxHost, WindowsHost
from services import activity
from services import checkmk_client

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "checkmk_state.json")

POLL_MIN = int(os.environ.get("MIKROTIK_CHECKMK_POLL_MIN", "5"))
_cache = {"data": None, "at": 0.0}


def _load_state() -> dict:
    if not os.path.exists(_STATE_PATH):
        return {}
    try:
        with open(_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
    try:
        with open(_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[checkmk_monitor] state persist error: {e}")


def _resolve_local_name(ip: Optional[str]) -> Optional[str]:
    """See prtg_monitor._resolve_local_name() — identical pattern."""
    if not ip:
        return None
    with SessionLocal() as db:
        d = db.execute(select(Device).where(Device.ip == ip)).scalar_one_or_none()
        if d:
            return d.identity or d.name or ip
        lh = db.execute(select(LinuxHost).where(LinuxHost.ip == ip)).scalar_one_or_none()
        if lh:
            return lh.hostname or ip
        wh = db.execute(select(WindowsHost).where(WindowsHost.ip == ip)).scalar_one_or_none()
        if wh:
            return wh.hostname or ip
    return None


_SERVICE_STATE_NAMES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}
_HOST_STATE_NAMES = {0: "UP", 1: "DOWN", 2: "UNREACHABLE"}


async def _scan() -> Optional[dict]:
    """TTL-cached (POLL_MIN minutes). Returns {"services": [...], "hosts": [...]}
    with every service/host (not pre-filtered - needed to detect a recovery,
    not just a new problem). None (keeps last good cache) if Check_MK isn't
    configured or any of the three underlying queries failed this cycle."""
    if not checkmk_client.is_configured():
        return None
    now = time.time()
    if _cache["data"] is not None and (now - _cache["at"]) < POLL_MIN * 60:
        return _cache["data"]

    host_ips = await checkmk_client.list_host_ips()
    services = await checkmk_client.list_service_states()
    hosts = await checkmk_client.list_host_states()
    if host_ips is None or services is None or hosts is None:
        return _cache["data"]

    out_services = []
    for svc in services:
        host_name = svc.get("host_name")
        ip = host_ips.get(host_name)
        try:
            state = int(svc.get("state"))
        except (TypeError, ValueError):
            continue
        out_services.append({
            "host_name": host_name, "description": svc.get("description") or "service",
            "ip": ip, "local_name": _resolve_local_name(ip),
            "state": state, "state_name": _SERVICE_STATE_NAMES.get(state, str(state)),
            "plugin_output": svc.get("plugin_output"),
        })

    out_hosts = []
    for h in hosts:
        name = h.get("name")
        ip = host_ips.get(name)
        try:
            state = int(h.get("state"))
        except (TypeError, ValueError):
            continue
        out_hosts.append({
            "host_name": name, "ip": ip, "local_name": _resolve_local_name(ip),
            "state": state, "state_name": _HOST_STATE_NAMES.get(state, str(state)),
            "plugin_output": h.get("plugin_output"),
        })

    data = {"services": out_services, "hosts": out_hosts}
    _cache["data"] = data
    _cache["at"] = now
    return data


async def collect_checkmk_events() -> List[dict]:
    """Same diff logic as prtg_monitor.collect_prtg_events(), applied to
    both services and hosts independently (two different key namespaces,
    two different event-type pairs)."""
    data = await _scan()
    if data is None:
        return []

    state = _load_state()
    events: List[dict] = []

    for svc in data["services"]:
        key = f"service:{svc['host_name']}:{svc['description']}"
        bucket = "problem" if svc["state"] != 0 else "ok"
        prev = state.get(key)
        if prev is not None and prev != bucket:
            event_type = "checkmk_service_problem" if bucket == "problem" else "checkmk_service_ok"
            device_name = svc["local_name"] or svc["host_name"]
            events.append({
                "type": event_type, "device_name": device_name,
                "host_name": svc["host_name"], "description": svc["description"],
                "ip": svc["ip"], "state_name": svc["state_name"],
                "plugin_output": svc.get("plugin_output"),
                "count": 1, "detected_at": datetime.utcnow().isoformat(),
            })
            try:
                activity.record(event_type, device_name=device_name,
                                 description=svc["description"], state_name=svc["state_name"])
            except Exception as e:
                print(f"[checkmk_monitor] activity record error: {e}")
        state[key] = bucket

    for h in data["hosts"]:
        key = f"host:{h['host_name']}"
        bucket = "problem" if h["state"] != 0 else "ok"
        prev = state.get(key)
        if prev is not None and prev != bucket:
            event_type = "checkmk_host_down" if bucket == "problem" else "checkmk_host_up"
            device_name = h["local_name"] or h["host_name"]
            events.append({
                "type": event_type, "device_name": device_name,
                "host_name": h["host_name"], "ip": h["ip"], "state_name": h["state_name"],
                "count": 1, "detected_at": datetime.utcnow().isoformat(),
            })
            try:
                activity.record(event_type, device_name=device_name, state_name=h["state_name"])
            except Exception as e:
                print(f"[checkmk_monitor] activity record error: {e}")
        state[key] = bucket

    _save_state(state)
    return events


def public_summary() -> dict:
    """Redacted view for the snapshot's plaintext envelope — only
    services/hosts currently in a problem state, same "just what needs
    attention" cut as prtg_monitor.public_summary()/compliance.public_summary()."""
    data = _cache["data"] or {"services": [], "hosts": []}
    return {
        "services": [{
            "device_name": s["local_name"] or s["host_name"],
            "description": s["description"], "state_name": s["state_name"],
            "plugin_output": s.get("plugin_output"),
        } for s in data["services"] if s["state"] != 0],
        "hosts": [{
            "device_name": h["local_name"] or h["host_name"],
            "state_name": h["state_name"],
        } for h in data["hosts"] if h["state"] != 0],
    }
