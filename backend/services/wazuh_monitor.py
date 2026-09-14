"""
Wazuh alert-stream monitoring — pulls new alerts (rule matches) from a
client's Wazuh Indexer since the last successful poll and turns them into
alert_events, the same way prtg_monitor.py/checkmk_monitor.py do for their
sources (IP-correlation against our own Device/LinuxHost/WindowsHost
tables, feeding the same alert_events -> Central -> Telegram pipeline).

Structurally different from those two siblings though: PRTG/Checkmk each
report a persistent STATE (sensor up/down, service OK/CRIT) that this app
diffs between polls. A Wazuh alert is a one-off EVENT — a rule fired once,
there is no "still firing" state to track — so instead of a state-diff
this uses a watermark (last-seen @timestamp, persisted the same way
tunnel_monitor.py/edge_discovery.py persist their own state) and simply
asks the indexer for "everything newer than that", exactly like tailing a
log file.
"""
import json
import os
import time
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, LinuxHost, WindowsHost
from services import activity
from services import wazuh_client

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wazuh_state.json")

POLL_MIN = int(os.environ.get("MIKROTIK_WAZUH_POLL_MIN", "5"))
# Wazuh's own documented rule-level bands (documentation.wazuh.com): 0-7 is
# noise/informational, 8-10 is "requires investigation" (first-time-seen,
# invalid-source, multiple auth errors), 11+ is already actionable
# (rootkit warnings, attack patterns). Defaulting to 8 - "worth a human
# looking at it" - rather than 11, since this only fills the local
# activity log / Central's alert list; it takes an explicit alert_rules
# entry (separate, existing mechanism) to actually reach Telegram.
MIN_LEVEL = int(os.environ.get("MIKROTIK_WAZUH_MIN_LEVEL", "8"))

_cache = {"data": [], "at": 0.0}


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
        print(f"[wazuh_monitor] state persist error: {e}")


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


async def collect_wazuh_events() -> List[dict]:
    """Called every ~2-min uplink cycle (see uplink.py) but internally
    TTL-gated to POLL_MIN — the indexer is a real search engine, not
    something to query every cycle. Returns one alert_events entry per NEW
    Wazuh alert since the last successful poll (watermark-based, not
    state-diff — see module docstring)."""
    if not wazuh_client.is_configured():
        return []
    now = time.time()
    if (now - _cache["at"]) < POLL_MIN * 60:
        return []
    _cache["at"] = now

    state = _load_state()
    # First-ever poll: only look back 1h, never the whole history — an
    # existing Wazuh deployment can easily have months of past alerts, and
    # this app has no business replaying all of them as "new" the moment
    # it's configured.
    since = state.get("last_seen_at") or "now-1h"
    alerts = await wazuh_client.list_recent_alerts(since_iso=since, min_level=MIN_LEVEL)
    if alerts is None:
        return []  # transient failure — keep the old watermark, retry next cycle

    events: List[dict] = []
    latest_ts = None
    for a in alerts:
        ip = a.get("agent_ip")
        device_name = _resolve_local_name(ip) or a.get("agent_name") or "?"
        events.append({
            "type": "wazuh_alert", "device_name": device_name, "ip": ip,
            "agent_name": a.get("agent_name"), "rule_level": a.get("rule_level"),
            "rule_description": a.get("rule_description"),
            "count": 1, "detected_at": datetime.utcnow().isoformat(),
        })
        try:
            activity.record("wazuh_alert", device_name=device_name,
                             rule_description=a.get("rule_description"), rule_level=a.get("rule_level"))
        except Exception as e:
            print(f"[wazuh_monitor] activity record error: {e}")
        latest_ts = a.get("timestamp") or latest_ts

    # Advance the watermark even when nothing new came back — the query
    # itself succeeded (alerts is a list, possibly empty), so there is
    # nothing to catch up on next cycle; using "now" avoids re-querying an
    # ever-growing "since" window for zero results forever.
    state["last_seen_at"] = latest_ts or datetime.utcnow().isoformat()
    _save_state(state)
    _cache["data"] = events
    return events


def public_summary() -> list:
    """Redacted view for the snapshot's plaintext envelope — only the most
    recent poll's new alerts (not a running history), same "just what
    needs attention now" cut as prtg_monitor.py/checkmk_monitor.py."""
    return [{
        "device_name": e["device_name"], "agent_name": e.get("agent_name"),
        "rule_level": e.get("rule_level"), "rule_description": e.get("rule_description"),
    } for e in _cache["data"]]
