"""
Escalation of alerts nobody has picked up.

An alert that stays "new" - nobody acknowledged it, took it or closed it - for too long is a bigger problem than the alert itself: the person who should have
looked at it did not. Per severity the agent has a list of times (minutes since the alert opened); when an unacknowledged alert passes the next one it is escalated
one level: an event `soc_escalated` goes to Central with the level in `count`, so a Central alert rule for that event type with "minimum count" 1 notifies the first
channel (say, the team's), one with minimum count 2 the next (the manager's), and so on - the existing rules and channels, no new notification machinery.

An alert in maintenance (services/maintenance.py) is not escalated; acknowledging it, taking it or closing it stops the escalation. Escalation is on by default but
harmless until Central has a rule for `soc_escalated`. The levels are kept in `data/escalation.json`.
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, SocAlert

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "escalation.json")
DEFAULTS = {"enabled": True, "baselined": False, "levels": {"critical": [15, 60, 240], "high": [60, 240], "medium": [], "low": [], "info": []}}
SEVERITIES = ("critical", "high", "medium", "low", "info")
_settings: Dict = json.loads(json.dumps(DEFAULTS))


def load_settings() -> Dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        s["enabled"] = bool(saved.get("enabled", True))
        s["baselined"] = bool(saved.get("baselined", False))
        for sev in SEVERITIES:
            if isinstance(saved.get("levels", {}).get(sev), list):
                s["levels"][sev] = [int(x) for x in saved["levels"][sev]][:6]
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[escalation] could not read the settings: {e}")
    _settings.clear()
    _settings.update(s)
    return _settings


def settings() -> Dict:
    return json.loads(json.dumps(_settings))


def update_settings(body: Dict) -> Dict:
    new = settings()
    if body.get("enabled") is not None:
        new["enabled"] = bool(body["enabled"])
    for sev, lst in (body.get("levels") or {}).items():
        if sev not in SEVERITIES:
            raise ValueError("unknown severity")
        try:
            mins = [int(x) for x in lst]
        except (TypeError, ValueError):
            raise ValueError("the levels are minutes")
        if len(mins) > 6 or any(m < 1 or m > 10080 for m in mins) or mins != sorted(set(mins)):
            raise ValueError("up to 6 increasing times, each between 1 minute and 7 days")
        new["levels"][sev] = mins
    new["baselined"] = _settings.get("baselined", False)
    _settings.clear()
    _settings.update(new)
    _persist()
    return settings()


def _persist() -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f)
    os.replace(tmp, _PATH)


def level_for(severity: str, age_min: float) -> int:
    """How many of the severity's times an alert of this age has passed."""
    return sum(1 for m in _settings["levels"].get(severity, []) if age_min >= m)


def collect_events(now: Optional[datetime] = None) -> List[dict]:
    """The escalations due now (one event per alert, for the highest level it has reached); moves the alerts' levels up."""
    if not _settings.get("enabled"):
        return []
    now = now or datetime.utcnow()
    from services import maintenance
    events: List[dict] = []
    first = not _settings.get("baselined")
    with SessionLocal() as db:
        for a in db.execute(select(SocAlert).where(SocAlert.status == "new")).scalars().all():
            lv = level_for(a.severity, (now - a.first_seen).total_seconds() / 60)
            if lv <= (a.esc_level or 0):
                continue
            if first:                                   # the first run takes the alerts that are already old as they are: no flood of escalations on the day this is switched on
                a.esc_level = lv
                continue
            if maintenance.covers_alert(a.asset_id, a.device_name, a.ip):
                continue
            a.esc_level = lv
            events.append({"type": "soc_escalated", "count": lv, "alert_id": a.id, "device_name": a.device_name, "title": a.title, "severity": a.severity, "rule": a.rule,
                           "minutes": int((now - a.first_seen).total_seconds() / 60), "detected_at": now.isoformat()})
            try:
                from services import soc
                soc._log(a, "auto", "escalated_unacked", lv, now)
            except Exception:
                pass
        db.commit()
    if first:
        _settings["baselined"] = True
        _persist()
    return events
