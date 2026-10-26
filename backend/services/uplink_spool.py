"""
The events the agent could not deliver to Central, kept on disk until it can.

When Central (or the network to it) is down, the agent goes on working - detection, alerts, the SOC queue and every page are local - but what it reports
to Central would be lost: the alert events (a WAN link that fell, a failed-login burst, a device that stopped answering) and the activity events (a firmware
upgrade finished, the agent restarted). The state of the network is not a problem - the next report carries the current one - but an event is a one-off.

So the uplink does not keep copies of whole reports any more (they were held in memory only, up to 50 of them, one megabyte each, and lost with a
restart); it keeps what cannot be rebuilt, the events, in `data/uplink_spool.json`: a report that could not be sent gives its events to the spool, and every
next report carries the oldest of the waiting events in front of its own (up to CHUNK per report, so a long outage is caught up over a few reports and a
single report never grows past the relay's limit). An event leaves the spool only when the report that carried it was accepted. The spool survives a restart
of the agent, keeps at most MAX_ALERTS alert and MAX_ACTIVITY activity events (the oldest are dropped, and counted) and nothing older than MAX_AGE_DAYS.
"""
import json
import os
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uplink_spool.json")
MAX_ALERTS = 5000
MAX_ACTIVITY = 500
MAX_AGE_DAYS = 7
CHUNK_ALERTS = 1000
CHUNK_ACTIVITY = 100

_lock = threading.Lock()
_data: Optional[dict] = None


def _blank() -> dict:
    return {"alerts": [], "activity": [], "since": None, "dropped": 0}


def _load() -> dict:
    global _data
    if _data is None:
        d = _blank()
        try:
            with open(_PATH, encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                d.update({k: saved[k] for k in d if k in saved})
        except Exception:
            pass
        _data = d
    return _data


def _persist() -> None:
    d = _load()
    try:
        if not d["alerts"] and not d["activity"]:
            if os.path.exists(_PATH):
                os.remove(_PATH)
            return
        os.makedirs(os.path.dirname(_PATH), exist_ok=True)
        tmp = _PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, separators=(",", ":"))
        os.replace(tmp, _PATH)
    except OSError as e:
        print(f"[uplink_spool] could not persist: {e}")


def _event_time(e: dict) -> Optional[datetime]:
    v = e.get("detected_at")
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", ""))
        except ValueError:
            return None
    ts = e.get("ts")
    if isinstance(ts, (int, float)):
        return datetime.utcfromtimestamp(ts)
    return None


def add(alerts: Optional[List[dict]], activity: Optional[List[dict]]) -> None:
    """Events that could not be delivered; they go to the end of the queue (newer than what already waits)."""
    alerts = [e for e in (alerts or []) if isinstance(e, dict)]
    activity = [e for e in (activity or []) if isinstance(e, dict)]
    if not alerts and not activity:
        return
    with _lock:
        d = _load()
        if d["since"] is None:
            d["since"] = datetime.utcnow().isoformat() + "Z"
        d["alerts"].extend(alerts)
        d["activity"].extend(activity)
        cut = datetime.utcnow() - timedelta(days=MAX_AGE_DAYS)
        for k in ("alerts", "activity"):
            kept = [e for e in d[k] if (_event_time(e) or datetime.utcnow()) >= cut]
            d["dropped"] += len(d[k]) - len(kept)
            d[k] = kept
        for k, mx in (("alerts", MAX_ALERTS), ("activity", MAX_ACTIVITY)):
            if len(d[k]) > mx:
                d["dropped"] += len(d[k]) - mx
                d[k] = d[k][-mx:]
        _persist()


def peek() -> Tuple[List[dict], List[dict]]:
    """The oldest waiting events (copies of the queue's head, not removed)."""
    with _lock:
        d = _load()
        return list(d["alerts"][:CHUNK_ALERTS]), list(d["activity"][:CHUNK_ACTIVITY])


def ack(n_alerts: int, n_activity: int) -> None:
    """The first n events of each kind were delivered (or given up on): they leave the queue."""
    if not n_alerts and not n_activity:
        return
    with _lock:
        d = _load()
        del d["alerts"][:n_alerts]
        del d["activity"][:n_activity]
        if not d["alerts"] and not d["activity"]:
            d["since"] = None
        _persist()


def note_dropped(n: int) -> None:
    with _lock:
        _load()["dropped"] += max(0, n)
        _persist()


def stats() -> dict:
    with _lock:
        d = _load()
        return {"alerts": len(d["alerts"]), "activity": len(d["activity"]), "since": d["since"], "dropped": d["dropped"]}


def clear() -> None:
    global _data
    with _lock:
        _data = _blank()
        _persist()
