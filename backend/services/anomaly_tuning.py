"""
The anomaly detector learns from its labels (stage 7 of docs/plan-jakosc-danych.md).

Seen in production: the detector's precision was 0.07 at sanmed, 0.20 at mcprojekt and 0.26 at psb - most labelled events were false,
many of them the same thing again (regular CPU spikes on glpi2 and DC1, labelled "false" every time). The labels were only counted.
Now, per series, from the events labelled in the last 90 days:

  * threshold   a series with 2+ false events and no true one opens only above the highest score its false events reached (+10 %, at
                most 12); with true events too, never above 90 % of the lowest true peak - a real problem stays detectable;
  * quiet hours false events of a series that keep coming at the same hour of the day (2+ within the hour) make that hour need twice
                the threshold - the scheduled job (a backup, an antivirus scan, a report) stops alarming, the rest of the day does not;
  * report      the precision per host and per series, and what was tuned.

The tuning is rebuilt every hour (data/anomaly_tuning.json) and the operator can clear it (DELETE /api/anomalies/tuning).
Pure decisions in tune(); I/O around it.
"""
import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "anomaly_tuning.json")
DAYS = 90
MIN_FALSE = 2
Z_MAX = 12.0
_state = {"at": 0.0, "tuning": {}, "report": {}}


def tune(events: List[dict], z_open: float) -> Dict[str, dict]:
    """events: [{"verdict": "true"|"false", "started_at": datetime, "series": [{"key", "score"}]}] -> {series key: {"z", "quiet_hours", "false", "true"}}."""
    false_peaks: Dict[str, List[float]] = defaultdict(list)
    true_peaks: Dict[str, List[float]] = defaultdict(list)
    false_hours: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        v = e.get("verdict")
        if v not in ("true", "false"):
            continue
        for s in e.get("series") or []:
            k, sc = s.get("key"), s.get("score")
            if not k or sc is None or sc < z_open:
                continue                                     # a series that was only near the edge did not open the event
            if v == "false":
                false_peaks[k].append(float(sc))
                false_hours[k][e["started_at"].hour] += 1
            else:
                true_peaks[k].append(float(sc))
    out: Dict[str, dict] = {}
    for k in set(false_peaks) | set(true_peaks):
        f, t = false_peaks.get(k, []), true_peaks.get(k, [])
        z = None
        if len(f) >= MIN_FALSE:
            z = min(Z_MAX, max(f) * 1.1)
            if t:
                z = min(z, min(t) * 0.9)
            z = z if z > z_open else None
        quiet = sorted(h for h, n in false_hours.get(k, {}).items() if n >= MIN_FALSE)
        if t:
            true_hours = set()
            for e in events:
                if e.get("verdict") == "true" and any(s.get("key") == k for s in e.get("series") or []):
                    true_hours.add(e["started_at"].hour)
            quiet = [h for h in quiet if h not in true_hours]
        if z or quiet:
            out[k] = {"z": round(z, 2) if z else None, "quiet_hours": quiet, "false": len(f), "true": len(t)}
    return out


def threshold(key: str, hour: int, z_open: float, tuning: Optional[Dict[str, dict]] = None) -> float:
    t = (tuning if tuning is not None else _state["tuning"]).get(key)
    if not t:
        return z_open
    z = t.get("z") or z_open
    if hour in (t.get("quiet_hours") or []):
        z = max(z, 2 * z_open)
    return z


def precision_report(events: List[dict]) -> dict:
    """Precision per host and per series over the labelled events: {"hosts": [...], "series": [...]}."""
    by_host: Dict[str, Counter] = defaultdict(Counter)
    by_series: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        v = e.get("verdict")
        if v not in ("true", "false"):
            by_host[e.get("host") or "?"]["unlabelled"] += 1
            continue
        by_host[e.get("host") or "?"][v] += 1
        for s in e.get("series") or []:
            if s.get("key"):
                by_series[s["key"]][v] += 1

    def rows(d):
        out = []
        for k, c in d.items():
            lab = c["true"] + c["false"]
            out.append({"name": k, "true": c["true"], "false": c["false"], "unlabelled": c["unlabelled"],
                        "precision": round(c["true"] / lab, 2) if lab else None})
        return sorted(out, key=lambda r: (r["precision"] if r["precision"] is not None else 2, -(r["false"])))
    return {"hosts": rows(by_host)[:50], "series": rows(by_series)[:50]}


def _events(days: int = DAYS) -> List[dict]:
    from services import anomaly
    return [{"verdict": e["verdict"], "started_at": datetime.fromisoformat(e["started_at"].rstrip("Z")), "series": e["series"], "host": e["host"]}
            for e in anomaly.list_events(days=days)]


def refresh(force: bool = False) -> dict:
    """Rebuilds the tuning from the labels (at most hourly unless forced) and keeps it on disk."""
    if not force and time.time() - _state["at"] < 3600:
        return _state
    from services import anomaly
    try:
        evs = _events()
    except Exception as e:
        print(f"[anomaly_tuning] could not read the events: {type(e).__name__}: {e}")
        return _state
    if _cleared_after():
        evs = [e for e in evs if e["started_at"] > _cleared_after()]
    _state["tuning"] = tune(evs, anomaly.Z_OPEN)
    _state["report"] = precision_report(evs)
    _state["at"] = time.time()
    try:
        os.makedirs(os.path.dirname(_PATH), exist_ok=True)
        data = _load()
        data.update(tuning=_state["tuning"], at=datetime.utcnow().isoformat() + "Z")
        with open(_PATH + ".tmp", "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(_PATH + ".tmp", _PATH)
    except OSError:
        pass
    return _state


def _load() -> dict:
    try:
        with open(_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _cleared_after() -> Optional[datetime]:
    c = _load().get("cleared_at")
    return datetime.fromisoformat(c.rstrip("Z")) if c else None


def clear() -> dict:
    """Forget the tuning: only labels given from now on count."""
    data = {"tuning": {}, "cleared_at": datetime.utcnow().isoformat() + "Z"}
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(_PATH + ".tmp", _PATH)
    _state.update(at=0.0, tuning={}, report={})
    return status()


def status() -> dict:
    return {"tuning": _state["tuning"], "report": _state["report"], "at": datetime.utcfromtimestamp(_state["at"]).isoformat() + "Z" if _state["at"] else None}
