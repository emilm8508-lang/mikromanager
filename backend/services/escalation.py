"""
Escalation of alerts nobody has picked up.

An alert that stays "new" - nobody acknowledged it, took it or closed it - for too long is a bigger problem than the alert itself: the person who should have
looked at it did not. Per severity the agent has a list of times (minutes since the alert opened); when an unacknowledged alert passes the next one it is escalated
one level: an event `soc_escalated` goes to Central with the level in `count`, so a Central alert rule for that event type with "minimum count" 1 notifies the first
channel (say, the team's), one with minimum count 2 the next (the manager's), and so on - the existing rules and channels, no new notification machinery.

An alert in maintenance (services/maintenance.py) is not escalated; acknowledging it, taking it or closing it stops the escalation. Escalation is on by default but
harmless until Central has a rule for `soc_escalated`. The levels are kept in `data/escalation.json`.

3.88 - escalation groups: alerts of some equipment go to other people on other times. A group matches an alert's asset by its groups (servers,
network, printers, ... and the operator's own tags), its type, its criticality, or a part of its name; all conditions set must hold, and the first
group that matches wins. A group has its own times per severity (a severity it does not set keeps the general times) and a route - a short name like
"network-team". Its escalations go to Central as the event type `soc_escalated.<route>` (Central's alert rules are matched by event type, so a rule for
that type with "minimum count" N sends level N of that group to its own channel); "exclusive" (the default) sends them only there, without the general
`soc_escalated`.
"""
import re
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, SocAlert

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "escalation.json")
DEFAULTS = {"enabled": True, "baselined": False, "levels": {"critical": [15, 60, 240], "high": [60, 240], "medium": [], "low": [], "info": []}, "groups": []}
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_GROUPS = 20
_ROUTE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_ASSET_TYPES = ("windows", "linux", "network", "printer", "virtual", "server", "other")
_CRIT = ("low", "medium", "high", "critical")
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
        for g in saved.get("groups") or []:
            try:
                s["groups"].append(clean_group(g))
            except (ValueError, TypeError) as e:
                print(f"[escalation] a saved group skipped: {e}")
        s["groups"] = s["groups"][:MAX_GROUPS]
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[escalation] could not read the settings: {e}")
    _settings.clear()
    _settings.update(s)
    return _settings


def settings() -> Dict:
    return json.loads(json.dumps(_settings))


def _minutes(lst) -> List[int]:
    try:
        mins = [int(x) for x in lst]
    except (TypeError, ValueError):
        raise ValueError("the levels are minutes")
    if len(mins) > 6 or any(m < 1 or m > 10080 for m in mins) or mins != sorted(set(mins)):
        raise ValueError("up to 6 increasing times, each between 1 minute and 7 days")
    return mins


def clean_group(g: Dict) -> Dict:
    """One escalation group, validated. Raises ValueError with what is wrong."""
    name = " ".join(str(g.get("name") or "").split())[:60]
    if not name:
        raise ValueError("a group needs a name")
    route = str(g.get("route") or "").strip().lower()
    if not _ROUTE_RE.match(route):
        raise ValueError("route: 1-32 small letters, digits, - or _ (it becomes the event type soc_escalated.<route>)")
    m = g.get("match") or {}
    match = {"groups": [str(x).strip()[:40] for x in (m.get("groups") or []) if str(x).strip()][:10],
             "types": [x for x in (m.get("types") or []) if x in _ASSET_TYPES],
             "criticality": [x for x in (m.get("criticality") or []) if x in _CRIT],
             "name": (str(m.get("name") or "").strip()[:60] or None)}
    if not (match["groups"] or match["types"] or match["criticality"] or match["name"]):
        raise ValueError("a group needs at least one condition (asset group, type, criticality or a part of the name)")
    levels = {}
    for sev, lst in (g.get("levels") or {}).items():
        if sev not in SEVERITIES:
            raise ValueError("unknown severity")
        if lst is not None:
            levels[sev] = _minutes(lst)
    return {"name": name, "route": route, "match": match, "levels": levels, "exclusive": bool(g.get("exclusive", True))}


def update_settings(body: Dict) -> Dict:
    new = settings()
    if body.get("enabled") is not None:
        new["enabled"] = bool(body["enabled"])
    for sev, lst in (body.get("levels") or {}).items():
        if sev not in SEVERITIES:
            raise ValueError("unknown severity")
        new["levels"][sev] = _minutes(lst)
    if body.get("groups") is not None:
        groups = [clean_group(g) for g in body["groups"]]
        if len(groups) > MAX_GROUPS:
            raise ValueError(f"at most {MAX_GROUPS} groups")
        if len({g["route"] for g in groups}) != len(groups):
            raise ValueError("every group needs its own route")
        new["groups"] = groups
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


def level_for(severity: str, age_min: float, group: Optional[Dict] = None) -> int:
    """How many of the severity's times an alert of this age has passed (the group's times when it sets them for the severity)."""
    times = (group or {}).get("levels", {}).get(severity)
    if times is None:
        times = _settings["levels"].get(severity, [])
    return sum(1 for m in times if age_min >= m)


def group_for(asset: Optional[Dict], device_name: Optional[str]) -> Optional[Dict]:
    """The first escalation group whose conditions all hold for the alert's asset (an alert without an asset matches by name only)."""
    for g in _settings.get("groups") or []:
        m = g["match"]
        if (m["groups"] or m["types"] or m["criticality"]) and not asset:
            continue
        if m["groups"] and not set(m["groups"]) & set(asset.get("groups") or []):
            continue
        if m["types"] and asset.get("type") not in m["types"]:
            continue
        if m["criticality"] and asset.get("criticality") not in m["criticality"]:
            continue
        if m["name"]:
            name = ((asset or {}).get("name") or device_name or "").lower()
            if m["name"].lower() not in name:
                continue
        return g
    return None


def _asset_info(db, asset_id: Optional[int], cache: Dict) -> Optional[Dict]:
    if not asset_id:
        return None
    if asset_id not in cache:
        from models.database import Asset
        from services import assets
        a = db.get(Asset, asset_id)
        cache[asset_id] = {"groups": assets._groups(a), "type": a.asset_type, "criticality": a.criticality, "name": a.name} if a else None
    return cache[asset_id]


def collect_events(now: Optional[datetime] = None) -> List[dict]:
    """The escalations due now (one event per alert, for the highest level it has reached); moves the alerts' levels up."""
    if not _settings.get("enabled"):
        return []
    now = now or datetime.utcnow()
    from services import maintenance
    events: List[dict] = []
    first = not _settings.get("baselined")
    cache: Dict = {}
    with SessionLocal() as db:
        for a in db.execute(select(SocAlert).where(SocAlert.status == "new")).scalars().all():
            grp = group_for(_asset_info(db, a.asset_id, cache), a.device_name) if _settings.get("groups") else None
            lv = level_for(a.severity, (now - a.first_seen).total_seconds() / 60, grp)
            if lv <= (a.esc_level or 0):
                continue
            if first:                                   # the first run takes the alerts that are already old as they are: no flood of escalations on the day this is switched on
                a.esc_level = lv
                continue
            if maintenance.covers_alert(a.asset_id, a.device_name, a.ip):
                continue
            a.esc_level = lv
            ev = {"type": "soc_escalated", "count": lv, "alert_id": a.id, "device_name": a.device_name, "title": a.title, "severity": a.severity, "rule": a.rule,
                  "minutes": int((now - a.first_seen).total_seconds() / 60), "detected_at": now.isoformat()}
            if grp:
                events.append({**ev, "type": f"soc_escalated.{grp['route']}", "route": grp["route"], "group": grp["name"]})
            if not grp or not grp["exclusive"]:
                events.append(ev)
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
