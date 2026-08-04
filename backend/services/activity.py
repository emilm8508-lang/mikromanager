"""
Local persistent queue of activity events (firmware upgraded, backup done,
agent restarted after update, etc.). Flushed to central OVH via uplink,
which appends unencrypted metadata to the envelope.

Persisted to a small JSON file so events survive process restarts (e.g.
firmware upgrade succeeded but backend was restarting when uplink ran).
"""
import json
import os
import time
from typing import List

_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "activity_pending.json"
)


def record(event_type: str, **payload) -> None:
    """Append an activity event to the pending queue."""
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    events = _load()
    events.append({"type": event_type, "ts": int(time.time()), **payload})
    events = events[-100:]  # cap for safety
    try:
        with open(_PATH, "w") as f:
            json.dump(events, f)
    except Exception as e:
        print(f"[activity] persist error: {e}")


def drain() -> List[dict]:
    """Return all pending events and clear the queue."""
    events = _load()
    try:
        os.remove(_PATH)
    except FileNotFoundError:
        pass
    return events


def _load() -> List[dict]:
    if not os.path.exists(_PATH):
        return []
    try:
        with open(_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []
