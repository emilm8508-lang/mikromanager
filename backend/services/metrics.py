"""
Metrics with history, thresholds that last, and a forecast: "the disk of the file server will be full in 9 days".

The agent already reads the resources of the devices and hosts it manages (CPU, memory, disk, temperature of routers, Windows and Linux hosts) but keeps only the latest
value, so it can say "the disk is 91% full" and not that it was 70% a month ago and grows by 0.7 points a day. This module records what is already in the database
every 10 minutes (no new connections to any device) as a history of series, and uses it for three things:

  * charts: any series over a day, a week or a month;
  * forecast: a straight line fitted to the last week of a disk series; when it grows steadily (not noise) and will reach 100% within 14 days, an alert "Disk will be
    full in ~N days" is raised (medium; high within 3 days) and closed when the trend breaks;
  * thresholds that last: rules of your own - "CPU above 90% for 15 minutes", "temperature above 45 for 10 minutes", "UPS charge below 40%" - that alert only when the
    value stays across the limit for the whole time, which a single reading above a static limit does not tell.

Other parts of the agent that measure something (the UPS monitor, services/ups_monitor.py) put their readings in through `record()`. Samples are kept 14 days at full
resolution and one per hour up to 90 days.
"""
import asyncio
import json
import math
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, delete, func

from models.database import SessionLocal, MetricSample, MetricSeries, Device, WindowsHost, WindowsHostDisk, LinuxHost, LinuxHostDisk

_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "metrics_rules.json")
INTERVAL_SEC = 600
RAW_DAYS = 14
KEEP_DAYS = 90
FORECAST_DAYS = 7
FORECAST_HORIZON_DAYS = 14
MIN_SLOPE = 0.2                  # % of the disk per day: slower growth is not worth an alert
MIN_R2 = 0.6                     # how well a straight line fits: below this the series is noise, not a trend
MIN_CURRENT = 50.0
KINDS = ("cpu", "mem", "disk", "temp", "ups_charge", "ups_load", "ups_runtime", "ups_temp", "other")
SEVERITIES = ("low", "medium", "high", "critical")

_task: Optional[asyncio.Task] = None
_last = {"at": None, "series": 0, "error": None}
_last_rollup = [0.0]


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── Recording ────────────────────────────────────────────────────────────────

def record(key: str, value: Optional[float], *, name: str, kind: str, asset_id: Optional[int] = None, unit: str = "%", now: Optional[datetime] = None, db=None) -> None:
    """One reading of one series. Creates the series on first use."""
    if value is None:
        return
    try:
        v = float(value)
    except (TypeError, ValueError):
        return
    if math.isnan(v) or math.isinf(v):
        return
    now = now or _now()
    own = db is None
    if own:
        db = SessionLocal()
    try:
        s = db.get(MetricSeries, key)
        if s is None:
            s = MetricSeries(key=key, name=name[:120], kind=kind if kind in KINDS else "other", asset_id=asset_id, unit=unit)
            db.add(s)
        else:
            s.name = name[:120]
        s.last_value, s.last_at = v, now
        db.add(MetricSample(key=key, at=now, value=v))
        if own:
            db.commit()
    finally:
        if own:
            db.close()


def sample_resources(now: Optional[datetime] = None) -> int:
    """Records the latest resource readings the agent already holds: routers, Windows hosts, Linux hosts. Returns how many readings were stored."""
    now = now or _now()
    n = 0
    with SessionLocal() as db:
        for d in db.execute(select(Device)).scalars().all():
            nm = d.name or d.ip
            for col, kind, label in (("cpu_load_pct", "cpu", "CPU"), ("mem_used_pct", "mem", "memory"), ("disk_used_pct", "disk", "disk"), ("temperature_c", "temp", "temperature")):
                v = getattr(d, col, None)
                if v is not None and d.last_resources_check_at and now - d.last_resources_check_at < timedelta(hours=3):
                    record(f"dev:{d.id}:{kind}", v, name=f"{nm} · {label}", kind=kind, unit="°C" if kind == "temp" else "%", now=now, db=db)
                    n += 1
        for h in db.execute(select(WindowsHost)).scalars().all():
            nm = h.hostname or h.ip
            fresh = h.last_resources_check_at and now - h.last_resources_check_at < timedelta(hours=3)
            if not fresh:
                continue
            for col, kind, label in (("cpu_used_pct", "cpu", "CPU"), ("mem_used_pct", "mem", "memory")):
                v = getattr(h, col, None)
                if v is not None:
                    record(f"win:{h.id}:{kind}", v, name=f"{nm} · {label}", kind=kind, now=now, db=db)
                    n += 1
            for dk in db.execute(select(WindowsHostDisk).where(WindowsHostDisk.host_id == h.id)).scalars().all():
                if dk.pct is not None and dk.last_seen_at and now - dk.last_seen_at < timedelta(hours=3):
                    record(f"win:{h.id}:disk:{dk.drive_letter}", dk.pct, name=f"{nm} · {dk.drive_letter}", kind="disk", now=now, db=db)
                    n += 1
        for h in db.execute(select(LinuxHost)).scalars().all():
            nm = h.hostname or h.ip
            fresh = h.last_resources_check_at and now - h.last_resources_check_at < timedelta(hours=3)
            if not fresh:
                continue
            for col, kind, label in (("cpu_used_pct", "cpu", "CPU"), ("mem_used_pct", "mem", "memory")):
                v = getattr(h, col, None)
                if v is not None:
                    record(f"lin:{h.id}:{kind}", v, name=f"{nm} · {label}", kind=kind, now=now, db=db)
                    n += 1
            for dk in db.execute(select(LinuxHostDisk).where(LinuxHostDisk.host_id == h.id)).scalars().all():
                if dk.pct is not None and dk.last_seen_at and now - dk.last_seen_at < timedelta(hours=3):
                    record(f"lin:{h.id}:disk:{dk.mount_point}", dk.pct, name=f"{nm} · {dk.mount_point}", kind="disk", now=now, db=db)
                    n += 1
        db.commit()
    return n


def rollup(now: Optional[datetime] = None) -> int:
    """Thins what is older than RAW_DAYS to one sample per hour and drops what is older than KEEP_DAYS. Returns the number of samples removed."""
    now = now or _now()
    removed = 0
    with SessionLocal() as db:
        removed += db.execute(delete(MetricSample).where(MetricSample.at < now - timedelta(days=KEEP_DAYS))).rowcount or 0
        old = db.execute(select(MetricSample.id, MetricSample.key, MetricSample.at).where(MetricSample.at < now - timedelta(days=RAW_DAYS)).order_by(MetricSample.key, MetricSample.at)).all()
        seen, drop = set(), []
        for i, k, at in old:
            hk = (k, at.strftime("%Y%m%d%H"))
            if hk in seen:
                drop.append(i)
            else:
                seen.add(hk)
        for a in range(0, len(drop), 500):
            removed += db.execute(delete(MetricSample).where(MetricSample.id.in_(drop[a:a + 500]))).rowcount or 0
        db.commit()
    return removed


# ── Reading ──────────────────────────────────────────────────────────────────

def points(key: str, days: float = 7, max_points: int = 400, now: Optional[datetime] = None) -> List[Tuple[datetime, float]]:
    now = now or _now()
    with SessionLocal() as db:
        rows = db.execute(select(MetricSample.at, MetricSample.value).where(MetricSample.key == key, MetricSample.at >= now - timedelta(days=days)).order_by(MetricSample.at)).all()
    pts = [(a, v) for a, v in rows]
    if len(pts) > max_points:                                       # evenly thinned, the last point kept
        step = len(pts) / max_points
        pts = [pts[int(i * step)] for i in range(max_points - 1)] + [pts[-1]]
    return pts


def trend(pts: List[Tuple[datetime, float]], limit: float = 100.0) -> dict:
    """A straight line through the points: {slope per day, r2, current, days_to_limit (None when it is not rising or the fit is poor)}."""
    n = len(pts)
    if n < 6:
        return {"slope": None, "r2": None, "current": pts[-1][1] if pts else None, "days_to_limit": None, "span_days": 0}
    t0 = pts[0][0]
    xs = [(a - t0).total_seconds() / 86400.0 for a, _ in pts]
    ys = [v for _, v in pts]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx < 1e-9:
        return {"slope": None, "r2": None, "current": ys[-1], "days_to_limit": None, "span_days": 0}
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    syy = sum((y - my) ** 2 for y in ys)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 1e-12 else 0.0
    cur = slope * xs[-1] + (my - slope * mx)                         # the line's value now: less jumpy than the last reading
    days = (limit - cur) / slope if slope > 1e-9 and cur < limit else None
    return {"slope": round(slope, 3), "r2": round(r2, 3), "current": ys[-1], "days_to_limit": round(days, 1) if days is not None else None, "span_days": round(xs[-1], 1)}


def series_list(now: Optional[datetime] = None) -> List[dict]:
    now = now or _now()
    with SessionLocal() as db:
        rows = db.execute(select(MetricSeries)).scalars().all()
        samples: Dict[str, list] = {}
        for k, a, v in db.execute(select(MetricSample.key, MetricSample.at, MetricSample.value).where(MetricSample.at >= now - timedelta(days=FORECAST_DAYS)).order_by(MetricSample.key, MetricSample.at)).all():
            samples.setdefault(k, []).append((a, v))
    out = []
    for s in rows:
        pts = samples.get(s.key, [])
        t = trend(pts, 100.0) if s.kind in ("disk", "mem") else trend(pts)
        out.append({"key": s.key, "name": s.name, "kind": s.kind, "unit": s.unit, "asset_id": s.asset_id, "value": s.last_value, "at": _iso(s.last_at), "slope": t["slope"], "r2": t["r2"],
                    "days_to_full": t["days_to_limit"] if s.kind == "disk" else None, "samples": len(pts), "stale": bool(s.last_at and now - s.last_at > timedelta(hours=6))})
    out.sort(key=lambda r: (r["days_to_full"] is None, r["days_to_full"] if r["days_to_full"] is not None else 0, r["name"].lower()))
    return out


# ── Forecast alerts ──────────────────────────────────────────────────────────

def check_forecasts(now: Optional[datetime] = None) -> List[str]:
    """Raises (and closes) the "disk will be full" alerts. Returns the keys that are alerting."""
    from services import soc
    now = now or _now()
    alerting = []
    with SessionLocal() as db:
        disks = db.execute(select(MetricSeries).where(MetricSeries.kind == "disk")).scalars().all()
    for s in disks:
        if s.last_at and now - s.last_at > timedelta(hours=6):
            continue
        t = trend(points(s.key, FORECAST_DAYS, 1000, now))
        d = t["days_to_limit"]
        rising = (t["slope"] or 0) >= MIN_SLOPE and (t["r2"] or 0) >= MIN_R2 and (s.last_value or 0) >= MIN_CURRENT and t["span_days"] >= 2
        if rising and d is not None and d <= FORECAST_HORIZON_DAYS:
            sev = "high" if d <= 3 else "medium"
            soc.raise_alert(rule="metric.disk_forecast", device=s.name.split(" · ")[0], title="Disk will be full soon", severity=sev, category="resource", fp_detail=s.key,
                            detail={"message": f"{s.name}: {s.last_value:.0f}% now, +{t['slope']:.1f} points a day, full in ~{d:.0f} days", "description": s.name}, source="rules", now=now)
            alerting.append(s.key)
        elif not rising or d is None or d > FORECAST_HORIZON_DAYS * 1.5:
            soc.resolve(rule="metric.disk_forecast", device=s.name.split(" · ")[0], fp_detail=s.key)
    return alerting


# ── Thresholds that last ─────────────────────────────────────────────────────

def load_rules() -> List[dict]:
    try:
        with open(_RULES_PATH, encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, list) else []
    except Exception:
        return []


def save_rules(rules: List[dict]) -> List[dict]:
    clean = []
    for i, r in enumerate(list(rules)[:50]):
        name = str(r.get("name") or "").strip()[:80]
        kind = str(r.get("kind") or "")
        op = str(r.get("op") or ">")
        sev = str(r.get("severity") or "medium")
        if not name or kind not in KINDS or op not in (">", "<") or sev not in SEVERITIES:
            raise ValueError("a rule needs a name, a kind, > or <, and a severity")
        try:
            thr, mins = float(r.get("threshold")), int(r.get("minutes") or 0)
        except (TypeError, ValueError):
            raise ValueError("the threshold is a number and the duration is in minutes")
        if not (0 <= mins <= 1440):
            raise ValueError("the duration is between 0 and 1440 minutes")
        pat = str(r.get("match") or "").strip()[:80]
        if pat:
            try:
                re.compile(pat, re.I)
            except re.error as e:
                raise ValueError(f"bad name filter: {e}")
        clean.append({"id": f"m{i + 1}", "name": name, "kind": kind, "op": op, "threshold": thr, "minutes": mins, "severity": sev, "match": pat, "enabled": bool(r.get("enabled", True))})
    os.makedirs(os.path.dirname(_RULES_PATH), exist_ok=True)
    tmp = _RULES_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False)
    os.replace(tmp, _RULES_PATH)
    return clean


def _violates(op: str, v: float, thr: float) -> bool:
    return v > thr if op == ">" else v < thr


def check_rules(now: Optional[datetime] = None) -> List[str]:
    """Evaluates the rules: a rule alerts for a series when every reading of the last `minutes` is across the threshold (and there are at least two)."""
    from services import soc
    now = now or _now()
    rules = [r for r in load_rules() if r.get("enabled", True)]
    if not rules:
        return []
    alerting = []
    with SessionLocal() as db:
        series = db.execute(select(MetricSeries)).scalars().all()
    for r in rules:
        for s in series:
            if s.kind != r["kind"] or (r.get("match") and not re.search(r["match"], s.name, re.I)):
                continue
            dev = s.name.split(" · ")[0]
            if s.last_at and now - s.last_at > timedelta(hours=1):
                soc.resolve(rule=f"metric.{r['id']}", device=dev, fp_detail=s.key)              # nothing fresh to judge by: not alerting
                continue
            win = max(int(r["minutes"]), 1)
            with SessionLocal() as db:
                vals = [v for (v,) in db.execute(select(MetricSample.value).where(MetricSample.key == s.key, MetricSample.at >= now - timedelta(minutes=win + 1)).order_by(MetricSample.at)).all()]
            sustained = len(vals) >= (1 if int(r["minutes"]) == 0 else 2) and all(_violates(r["op"], v, r["threshold"]) for v in vals)
            if sustained:
                soc.raise_alert(rule=f"metric.{r['id']}", device=dev, title=r["name"], severity=r["severity"], category="resource", fp_detail=s.key,
                                detail={"message": f"{s.name}: {vals[-1]:.1f}{s.unit} (limit {r['op']} {r['threshold']:g}{s.unit}" + (f" for {r['minutes']} min)" if r["minutes"] else ")"), "description": s.name}, source="rules", now=now)
                alerting.append(f"{r['id']}|{s.key}")
            else:
                soc.resolve(rule=f"metric.{r['id']}", device=dev, fp_detail=s.key)
    return alerting


# ── The loop ─────────────────────────────────────────────────────────────────

async def run_cycle(now: Optional[datetime] = None) -> dict:
    now = now or _now()
    n = sample_resources(now)
    fc = check_forecasts(now)
    ru = check_rules(now)
    if time.time() - _last_rollup[0] > 86400:
        _last_rollup[0] = time.time()
        rollup(now)
    _last.update(at=_iso(now), series=n, error=None)
    return {"samples": n, "forecasts": len(fc), "rules": len(ru)}


async def _loop():
    await asyncio.sleep(150)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[metrics] cycle error: {e}")
        await asyncio.sleep(INTERVAL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None


def status() -> dict:
    return dict(_last)
