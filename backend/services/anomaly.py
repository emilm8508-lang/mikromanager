"""
Anomaly detection on the metric history (stage 1 of the ML work): "this host behaves unlike itself".

Every metric series the agent records (services/metrics.py: CPU / memory of routers and hosts, temperatures, UPS, the BMC's power draw,
temperatures and fans) gets its own learned normal range, separately for every hour of the week, from its last 28 days:

  * the profile of a series: for each hour of the week (hour of the day while there are less than 14 days of history) the median and
    the MAD (median absolute deviation) of the readings of that hour and the hour before and after. Median and MAD, not mean and
    standard deviation, so the incidents in the history do not widen the normal range they are judged against;
  * the score of a reading: how many robust standard deviations (1.4826 x MAD) it is away from the median of its hour, in the
    direction that matters for the kind (CPU, memory and temperature only upwards, UPS charge and runtime only downwards, power and fan
    speed both ways). A floor on the deviation (3 points of a percentage, 1.5 degC, 5 % of the median of watts / RPM) keeps a series
    that hardly ever moves from alarming on noise;
  * an anomaly opens when a series of a host scores >= Z_OPEN (4) on two cycles in a row (20 minutes) and closes when every series of
    the host is back under Z_CLOSE (2.5) on two cycles in a row. One open event per host, with every series that was out of range.

A series needs MIN_SPAN_DAYS (3) of history before it is judged ("learning" until then). Each open event raises a SOC alert
(rule "ml.anomaly"); the operator's verdict on an event - a real problem or a false alarm, here or by marking the SOC alert a false
positive, also from Central - is kept with the event, so the detector can be measured (precision over the labelled events).

No machine-learning library is needed for this stage; the multivariate model (Isolation Forest) comes when there are labels to
measure it against.
"""
import json
import os
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, AnomalyEvent, MetricSample, MetricSeries, SocAlert

HISTORY_DAYS = 28
MIN_SPAN_DAYS = 3
WEEKLY_SPAN_DAYS = 14
MIN_BUCKET = 12                 # readings a profile slot needs; with fewer the series' whole last week is used
RECENT_MIN = 35                 # the "current" value: the median of the readings of the last 35 minutes
PROFILE_TTL_SEC = 6 * 3600      # a profile changes slowly; it is rebuilt every 6 hours
Z_OPEN = float(os.environ.get("MIKROTIK_ANOMALY_Z", "4.0"))
Z_CLOSE = 2.5
CYCLES_OPEN = 2
CYCLES_CLOSE = 2
SKIP_KINDS = ("disk",)          # disks have their own forecast (metrics.check_forecasts)
RULE = "ml.anomaly"

_profiles: Dict[str, Tuple[float, Optional[dict]]] = {}     # key -> (built at, profile or None while learning)
_hot: Dict[str, int] = {}                                    # key -> consecutive cycles over Z_OPEN
_cool: Dict[str, int] = {}                                   # host key -> consecutive cycles with everything under Z_CLOSE
_last: dict = {"at": None, "series": 0, "learning": 0, "judged": 0, "error": None}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def host_key(key: str) -> str:
    """"win:3:cpu" -> "win:3", "bmc:2:inlet_c" -> "bmc:2"."""
    parts = key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else key


def direction(kind: str, unit: str) -> str:
    if kind in ("cpu", "mem", "temp", "ups_temp", "net", "sec"):       # traffic and security events: more is the risk
        return "up"
    if kind in ("ups_charge", "ups_runtime"):
        return "down"
    return "both"


def floor(unit: str, median: float) -> float:
    """The smallest deviation that counts as one robust standard deviation."""
    u = (unit or "").strip()
    if u == "%":
        return 3.0
    if u in ("°C", "C"):
        return 1.5
    if u == "W":
        return max(5.0, abs(median) * 0.05)
    if u.upper() == "RPM":
        return max(100.0, abs(median) * 0.03)
    if u == "MB":                                   # NetFlow traffic of a host per 10 minutes: bursty by nature
        return max(5.0, abs(median) * 0.3)
    if u in ("hosts", "ports", "conn", "events", "IPs"):
        return max(5.0, abs(median) * 0.3)
    return max(1.0, abs(median) * 0.05)


def _slot(t: datetime, weekly: bool) -> int:
    return t.weekday() * 24 + t.hour if weekly else t.hour


def _robust(vals: List[float]) -> Tuple[float, float]:
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    return med, 1.4826 * mad


def build_profile(pts: List[Tuple[datetime, float]], unit: str) -> Optional[dict]:
    """The learned normal range of a series from its history, or None while it has less than MIN_SPAN_DAYS of it."""
    if len(pts) < 20 or (pts[-1][0] - pts[0][0]) < timedelta(days=MIN_SPAN_DAYS):
        return None
    weekly = (pts[-1][0] - pts[0][0]) >= timedelta(days=WEEKLY_SPAN_DAYS)
    n = 168 if weekly else 24
    by: Dict[int, List[float]] = {}
    for t, v in pts:
        by.setdefault(_slot(t, weekly), []).append(v)
    last_week = [v for t, v in pts if t >= pts[-1][0] - timedelta(days=7)]
    fallback = _robust(last_week)
    slots = {}
    for s in range(n):
        vals = by.get((s - 1) % n, []) + by.get(s, []) + by.get((s + 1) % n, [])
        med, sd = _robust(vals) if len(vals) >= MIN_BUCKET else fallback
        slots[s] = (med, max(sd, floor(unit, med)))
    return {"weekly": weekly, "slots": slots, "span_days": round((pts[-1][0] - pts[0][0]).total_seconds() / 86400, 1)}


def expected(profile: dict, t: datetime) -> Tuple[float, float]:
    """(median, robust standard deviation) of the series at time t."""
    return profile["slots"][_slot(t, profile["weekly"])]


def score(value: float, med: float, sd: float, dirn: str) -> float:
    z = (value - med) / sd if sd else 0.0
    return z if dirn == "up" else -z if dirn == "down" else abs(z)


def _profile(db, s: MetricSeries, now: datetime) -> Optional[dict]:
    cached = _profiles.get(s.key)
    if cached and now.timestamp() - cached[0] < PROFILE_TTL_SEC:
        return cached[1]
    rows = db.execute(select(MetricSample.at, MetricSample.value).where(
        MetricSample.key == s.key, MetricSample.at >= now - timedelta(days=HISTORY_DAYS), MetricSample.at < now - timedelta(minutes=RECENT_MIN),
    ).order_by(MetricSample.at)).all()
    p = build_profile([(a, v) for a, v in rows], s.unit or "")
    _profiles[s.key] = (now.timestamp(), p)
    return p


def judge(now: Optional[datetime] = None) -> Dict[str, List[dict]]:
    """Scores the current value of every series: {host key: [one dict per series that is out of range]}, plus the counters in _last."""
    now = now or _now()
    out: Dict[str, List[dict]] = {}
    learning = judged = 0
    with SessionLocal() as db:
        series = [s for s in db.execute(select(MetricSeries)).scalars().all() if s.kind not in SKIP_KINDS]
        for s in series:
            if not s.last_at or now - s.last_at > timedelta(minutes=RECENT_MIN):
                _hot.pop(s.key, None)
                continue
            p = _profile(db, s, now)
            if p is None:
                learning += 1
                continue
            recent = [v for (v,) in db.execute(select(MetricSample.value).where(
                MetricSample.key == s.key, MetricSample.at >= now - timedelta(minutes=RECENT_MIN))).all()]
            if not recent:
                continue
            judged += 1
            cur = statistics.median(recent)      # most of the last readings must be out of range, a single spike is not enough
            med, sd = expected(p, now)
            z = score(cur, med, sd, direction(s.kind, s.unit or ""))
            hk = host_key(s.key)
            item = {"key": s.key, "name": s.name, "label": s.name.split(" · ", 1)[-1], "unit": s.unit or "", "kind": s.kind,
                    "value": round(cur, 2), "expected": round(med, 2), "low": round(med - Z_OPEN * sd, 2), "high": round(med + Z_OPEN * sd, 2),
                    "score": round(z, 2)}
            if z >= Z_OPEN:
                _hot[s.key] = _hot.get(s.key, 0) + 1
            else:
                _hot.pop(s.key, None)
            if z >= Z_CLOSE:
                item["hot"] = _hot.get(s.key, 0)
                out.setdefault(hk, []).append(item)
            else:
                out.setdefault(hk, [])
    _last.update(at=_iso(now), series=len(series), learning=learning, judged=judged)
    return out


def _host_name(items: List[dict], fallback: str) -> str:
    return (items[0]["name"].split(" · ")[0] if items else None) or fallback


def _severity(items: List[dict]) -> str:
    top = max((i["score"] for i in items), default=0)
    return "high" if top >= 2 * Z_OPEN or len([i for i in items if i["score"] >= Z_OPEN]) >= 3 else "medium"


def _message(items: List[dict]) -> str:
    parts = [f"{i['label']} {i['value']:g}{i['unit']} (usually {i['expected']:g}{i['unit']}, score {i['score']:.1f})" for i in sorted(items, key=lambda x: -x["score"])[:4]]
    return "Unusual compared with the same hour of earlier weeks: " + "; ".join(parts)


def run_cycle(now: Optional[datetime] = None) -> dict:
    """One detection pass (called by metrics.run_cycle every 10 minutes): opens, updates and closes the events and their SOC alerts."""
    from services import soc
    now = now or _now()
    scored = judge(now)
    opened = closed = 0
    with SessionLocal() as db:
        open_events = {e.host_key: e for e in db.execute(select(AnomalyEvent).where(AnomalyEvent.ended_at.is_(None))).scalars().all()}
        for hk, items in scored.items():
            firing = [i for i in items if i.get("hot", 0) >= CYCLES_OPEN]
            ev = open_events.get(hk)
            name = _host_name(items, hk) if items else (ev.host_name if ev else hk)
            if firing:
                _cool.pop(hk, None)
                peak = max(i["score"] for i in items)
                cat = ("hardware" if hk.startswith(("bmc:", "ups:")) else "network" if hk.startswith("net:")
                       else "security" if hk.startswith("wz:") else "resource")
                if ev is None:
                    ev = AnomalyEvent(host_key=hk, host_name=name, category=cat, severity=_severity(items), started_at=now, last_seen=now,
                                      peak_score=peak, series=json.dumps(items))
                    db.add(ev)
                    open_events[hk] = ev
                    opened += 1
                else:
                    ev.last_seen = now
                    if peak > (ev.peak_score or 0):
                        ev.peak_score, ev.series, ev.severity = peak, json.dumps(items), _severity(items)
                soc.raise_alert(rule=RULE, device=name, title="Unusual behaviour (anomaly)", severity=ev.severity, category="detection" if cat == "security" else cat, fp_detail=hk,
                                detail={"message": _message(items), "description": f"anomaly score {peak:.1f}"}, source="rules", now=now)
            elif ev is not None:
                if all(i["score"] < Z_CLOSE for i in items):
                    _cool[hk] = _cool.get(hk, 0) + 1
                else:
                    _cool.pop(hk, None)
                if _cool.get(hk, 0) >= CYCLES_CLOSE:
                    ev.ended_at = now
                    _cool.pop(hk, None)
                    soc.resolve(rule=RULE, device=ev.host_name, fp_detail=hk)
                    closed += 1
        # a host whose series all went silent: close after 2 hours, there is nothing to judge it by
        for hk, ev in open_events.items():
            if ev.ended_at is None and hk not in scored and now - ev.last_seen > timedelta(hours=2):
                ev.ended_at = ev.last_seen
                soc.resolve(rule=RULE, device=ev.host_name, fp_detail=hk)
                closed += 1
        db.commit()
    return {"judged": _last["judged"], "learning": _last["learning"], "opened": opened, "closed": closed}


# ── Reading, labels, measurement ─────────────────────────────────────────────

def _alert_status(db, ev: AnomalyEvent) -> Optional[str]:
    """The status of the SOC alert this event raised (the same fingerprint, opened around the event's start)."""
    fp = f"{RULE}|{(ev.host_name or '').strip().lower()}|{ev.host_key}"[:240]
    row = db.execute(select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.first_seen <= (ev.ended_at or ev.last_seen) + timedelta(minutes=15))
                     .order_by(SocAlert.id.desc()).limit(1)).scalars().first()
    return row.status if row else None


def effective_verdict(db, ev: AnomalyEvent) -> Optional[str]:
    """The operator's label: set on the event, or "false" when its SOC alert was marked a false positive (here or from Central)."""
    if ev.verdict in ("true", "false"):
        return ev.verdict
    return "false" if _alert_status(db, ev) == "false_positive" else None


def _event_row(db, ev: AnomalyEvent) -> dict:
    return {"id": ev.id, "host_key": ev.host_key, "host": ev.host_name, "category": ev.category, "severity": ev.severity,
            "started_at": _iso(ev.started_at), "last_seen": _iso(ev.last_seen), "ended_at": _iso(ev.ended_at),
            "minutes": round(((ev.ended_at or ev.last_seen) - ev.started_at).total_seconds() / 60),
            "peak_score": round(ev.peak_score or 0, 2), "series": json.loads(ev.series or "[]"),
            "verdict": effective_verdict(db, ev), "verdict_set": ev.verdict, "verdict_by": ev.verdict_by, "verdict_at": _iso(ev.verdict_at)}


def list_events(days: int = 90, open_only: bool = False) -> List[dict]:
    since = _now() - timedelta(days=days)
    with SessionLocal() as db:
        q = select(AnomalyEvent).where(AnomalyEvent.started_at >= since)
        if open_only:
            q = q.where(AnomalyEvent.ended_at.is_(None))
        return [_event_row(db, e) for e in db.execute(q.order_by(AnomalyEvent.started_at.desc())).scalars().all()]


def set_verdict(event_id: int, verdict: Optional[str], who: str) -> dict:
    """Labels an event. "false" also marks its open SOC alert a false positive, so the two agree."""
    if verdict not in (None, "true", "false"):
        raise ValueError("verdict must be true, false or null")
    from services import soc
    with SessionLocal() as db:
        ev = db.get(AnomalyEvent, event_id)
        if not ev:
            raise KeyError(event_id)
        ev.verdict, ev.verdict_by, ev.verdict_at = verdict, (who if verdict else None), (_now() if verdict else None)
        fp = f"{RULE}|{(ev.host_name or '').strip().lower()}|{ev.host_key}"[:240]
        alert_ids = [a.id for a in db.execute(select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.status.in_(("new", "ack", "in_progress")))).scalars().all()]
        db.commit()
        if verdict == "false" and alert_ids:
            soc.update(alert_ids, status="false_positive", who=who)
        return _event_row(db, ev)


def stats(days: int = 90) -> dict:
    """How the detector did: events, how many are labelled, and the precision over the labelled ones (true / (true + false))."""
    since = _now() - timedelta(days=days)
    with SessionLocal() as db:
        evs = db.execute(select(AnomalyEvent).where(AnomalyEvent.started_at >= since)).scalars().all()
        verdicts = [effective_verdict(db, e) for e in evs]
    t, f = verdicts.count("true"), verdicts.count("false")
    return {"days": days, "events": len(evs), "open": sum(1 for e in evs if e.ended_at is None), "labelled": t + f, "true": t, "false": f,
            "precision": round(t / (t + f), 3) if t + f else None, "z_open": Z_OPEN, "z_close": Z_CLOSE, "min_span_days": MIN_SPAN_DAYS, **{k: _last[k] for k in ("at", "series", "learning", "judged")}}


def band(key: str, days: float = 3) -> dict:
    """The readings of a series over the last `days` with its learned normal range at each of them, for the chart."""
    now = _now()
    with SessionLocal() as db:
        s = db.get(MetricSeries, key)
        if not s:
            raise KeyError(key)
        rows = db.execute(select(MetricSample.at, MetricSample.value).where(
            MetricSample.key == key, MetricSample.at >= now - timedelta(days=HISTORY_DAYS)).order_by(MetricSample.at)).all()
    pts = [(a, v) for a, v in rows]
    p = build_profile([x for x in pts if x[0] < now - timedelta(minutes=RECENT_MIN)], s.unit or "")
    dirn = direction(s.kind, s.unit or "")
    out = []
    for a, v in pts:
        if a < now - timedelta(days=days):
            continue
        row = {"t": _iso(a), "v": round(v, 2)}
        if p:
            med, sd = expected(p, a)
            row.update(m=round(med, 2), lo=round(med - Z_OPEN * sd, 2) if dirn != "up" else None, hi=round(med + Z_OPEN * sd, 2) if dirn != "down" else None,
                       z=round(score(v, med, sd, dirn), 2))
        out.append(row)
    return {"key": key, "name": s.name, "unit": s.unit, "kind": s.kind, "direction": dirn, "learning": p is None,
            "span_days": p["span_days"] if p else None, "points": out}


def public_summary() -> dict:
    """For Central (inside the SOC part of the snapshot): the open anomalies with what is unusual, and the detector's numbers."""
    st = stats(30)
    with SessionLocal() as db:
        open_ = [_event_row(db, e) for e in db.execute(select(AnomalyEvent).where(AnomalyEvent.ended_at.is_(None))).scalars().all()]
    return {
        "series": st["series"], "learning": st["learning"], "events_30d": st["events"], "labelled": st["labelled"], "true": st["true"], "false": st["false"],
        "precision": st["precision"], "at": st["at"],
        "open": [{"h": e["host"], "c": e["category"], "sev": e["severity"], "since": e["started_at"], "z": e["peak_score"],
                  "items": [{k: i[k] for k in ("label", "unit", "value", "expected", "low", "high", "score")} for i in sorted(e["series"], key=lambda x: -x["score"])[:4]]}
                 for e in open_][:30],
    }
