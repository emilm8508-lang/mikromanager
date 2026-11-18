"""
What will run out, and when: one list of the forecasts the agent can make from what it already measures.

  disk         a disk series growing steadily to 100% (services/metrics.py has the "disk will be full" alert since 3.x);
  memory       a memory series growing steadily to 100% - usually a leak; alerted here (metric.mem_forecast) within MEM_ALERT_DAYS;
  dhcp_pool    a DHCP pool's usage growing to 100% (services/ipam.py alerts it within 7 days);
  certificate  a TLS certificate expiring - of the TLS checks (services/tls_scan.py) and of the https application checks
               (services/app_checks.py); both have their own alerts.

"Growing steadily" is the same straight-line fit as the disk forecast: over the last FIT_DAYS, at least two days of readings, a fit of
at least metrics.MIN_R2 and a minimum growth per day (MIN_SLOPE per kind) - a memory series that goes up and down every day is noise, not a
trend. Each item: what, where, the value now, the growth per day, the days left and the date. Nothing new is read from any device.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, MetricSeries, MetricSample, TlsCheck

FIT_DAYS = 7
HORIZON_DAYS = 90
MIN_SLOPE = {"disk": 0.2, "mem": 0.5, "dhcp_pool": 0.5}
MIN_CURRENT = {"disk": 30.0, "mem": 50.0, "dhcp_pool": 20.0}
MEM_ALERT_DAYS = 7
INTERVAL_SEC = 3600

_task: Optional[asyncio.Task] = None


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _kind_of(s: MetricSeries) -> Optional[str]:
    if s.key.startswith("ipam:pool:"):
        return "dhcp_pool"
    if s.kind in ("disk", "mem"):
        return s.kind
    return None


def growth(kind: str, pts, now: datetime) -> Optional[dict]:
    """The forecast of one series, or None when it is not growing steadily towards 100% within the horizon."""
    from services import metrics
    t = metrics.trend(pts, 100.0)
    d = t["days_to_limit"]
    if (d is None or (t["slope"] or 0) < MIN_SLOPE[kind] or (t["r2"] or 0) < metrics.MIN_R2 or t["span_days"] < 2
            or (t["current"] or 0) < MIN_CURRENT[kind] or d > HORIZON_DAYS):
        return None
    return {"value": round(t["current"], 1) if t["current"] is not None else None, "per_day": t["slope"], "days": d, "r2": t["r2"],
            "date": _iso(now + timedelta(days=d))}


def series_forecasts(now: Optional[datetime] = None) -> List[dict]:
    now = now or _now()
    with SessionLocal() as db:
        rows = [s for s in db.execute(select(MetricSeries)).scalars().all() if _kind_of(s)]
        keys = [s.key for s in rows]
        pts: Dict[str, list] = {}
        if keys:
            for k, a, v in db.execute(select(MetricSample.key, MetricSample.at, MetricSample.value)
                                      .where(MetricSample.key.in_(keys), MetricSample.at >= now - timedelta(days=FIT_DAYS)).order_by(MetricSample.key, MetricSample.at)).all():
                pts.setdefault(k, []).append((a, v))
    out = []
    for s in rows:
        if s.last_at and now - s.last_at > timedelta(hours=12):
            continue                                     # not measured any more: no forecast from old data
        kind = _kind_of(s)
        g = growth(kind, pts.get(s.key, []), now)
        if g:
            where, _, what = (s.name or s.key).partition(" · ")
            out.append({"kind": kind, "key": s.key, "name": s.name, "where": where if what else s.name, "what": what or None, "asset_id": s.asset_id, "unit": s.unit or "%", **g})
    return out


def cert_forecasts(now: Optional[datetime] = None, horizon: int = HORIZON_DAYS) -> List[dict]:
    now = now or _now()
    out = []
    with SessionLocal() as db:
        from services import tls_scan
        for c in db.execute(select(TlsCheck).where(TlsCheck.not_after.is_not(None), TlsCheck.not_after <= now + timedelta(days=horizon))).scalars().all():
            try:
                where = tls_scan._device_name(db, c.ip)
            except Exception:
                where = c.ip
            d = round((c.not_after - now).total_seconds() / 86400, 1)
            out.append({"kind": "certificate", "key": f"tls:{c.ip}:{c.port}", "name": c.subject or f"{c.ip}:{c.port}", "where": where or c.ip,
                        "what": f"{c.ip}:{c.port}" + (f" · {c.subject}" if c.subject else ""), "asset_id": None, "unit": None,
                        "value": None, "per_day": None, "days": d, "date": _iso(c.not_after), "self_signed": bool(c.self_signed)})
    try:
        from services import app_checks
        for x in app_checks.overview(now)["items"]:
            if x.get("cert_days") is not None and x["cert_days"] <= horizon:
                out.append({"kind": "certificate", "key": f"app:{x['id']}", "name": x["name"], "where": x["name"], "what": x["target"], "asset_id": None,
                            "unit": None, "value": None, "per_day": None, "days": x["cert_days"], "date": _iso(now + timedelta(days=x["cert_days"]))})
    except Exception as e:
        print(f"[forecasts] app checks: {type(e).__name__}: {e}")
    return out


def overview(horizon: int = HORIZON_DAYS, now: Optional[datetime] = None) -> dict:
    now = now or _now()
    horizon = max(1, min(int(horizon), 365))
    items = [x for x in series_forecasts(now) + cert_forecasts(now, horizon) if x["days"] is not None and x["days"] <= horizon]
    items.sort(key=lambda x: (x["days"], x["kind"], (x["name"] or "").lower()))
    counts = {k: sum(1 for x in items if x["kind"] == k) for k in ("disk", "mem", "dhcp_pool", "certificate")}
    return {"items": items, "counts": counts, "horizon": horizon, "within_7": sum(1 for x in items if x["days"] <= 7), "at": _iso(now)}


def check_memory(now: Optional[datetime] = None) -> List[str]:
    """Raises / closes metric.mem_forecast: a memory series that will be full within MEM_ALERT_DAYS."""
    from services import soc
    now = now or _now()
    alerting = []
    growing = {x["key"]: x for x in series_forecasts(now) if x["kind"] == "mem"}
    with SessionLocal() as db:
        mem = [(s.key, s.name) for s in db.execute(select(MetricSeries).where(MetricSeries.kind == "mem")).scalars().all()]
    for key, name in mem:
        dev = (name or key).split(" · ")[0]
        x = growing.get(key)
        if x and x["days"] <= MEM_ALERT_DAYS:
            soc.raise_alert(rule="metric.mem_forecast", device=dev, title="Memory will run out", severity="high" if x["days"] <= 2 else "medium", category="resource",
                            fp_detail=key, detail={"message": f"{name}: {x['value']}% now, +{x['per_day']} points a day, full in ~{x['days']:.0f} days - a memory leak?",
                                                   "description": name}, source="rules", now=now)
            alerting.append(key)
        elif not x or x["days"] > MEM_ALERT_DAYS * 1.5:
            soc.resolve(rule="metric.mem_forecast", device=dev, fp_detail=key, now=now)
    return alerting


def _no_ip(v: Optional[str]) -> Optional[str]:
    import ipaddress
    try:
        ipaddress.ip_address(str(v or ""))
        return None                                      # a bare address does not go to Central
    except ValueError:
        return v


def public_summary() -> dict:
    """For Central: the counts and the nearest items (what and where, no addresses)."""
    o = overview(30)
    return {"within_30": len(o["items"]), "within_7": o["within_7"], "counts": o["counts"],
            "next": [{"k": x["kind"], "n": _no_ip(x["where"]), "w": x["what"] if x["kind"] != "certificate" else None, "days": x["days"]} for x in o["items"][:12]],
            "at": o["at"]}


async def _loop():
    await asyncio.sleep(600)
    while True:
        try:
            check_memory()
        except Exception as e:
            print(f"[forecasts] memory check error: {e}")
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
