"""
Business services: what people use, defined as the equipment it needs, with the SLA of it (the NetXMS idea of "business services").

An alert says "the switch in the server room does not answer". The owner of the shop wants to know "can customers order?". A business service is that
question: a name, the devices it relies on and a rule -

  all   every member is needed: down as soon as one is missing (a service on a single server and its database host);
  any   one is enough (two redundant gateways): degraded while some are missing, down when none is up;
  min N at least N members have to be up: degraded while it still has N, down below that.

and its state follows from the availability of the members (services/availability.py: a member that is "unreachable" behind a failed switch is not up
either, and the service says which of its members are missing). The history of the state gives what an SLA needs: the share of the time the service was
not down in the last 24 hours / 7 days / 30 days and in the current month against the target, the minutes of downtime that are still allowed this month
and the list of outages with what was missing. An alert `bizservice_problem` (medium while degraded, critical when down) is raised for the service and
closed by its recovery; a service whose members are all unreachable because of one failed device is one more alert about the same fault, not a
different one - it tells the business what that fault means.

States: ok | degraded | down | unknown (none of the members has been checked yet). The SLA counts "down" as the downtime; "degraded" works.
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete

from models.database import SessionLocal, Asset, AvailState, BizService, BizState, BizEvent

MODES = ("all", "any", "min")
KEEP_DAYS = 400
_pending: List[dict] = []
_PENDING_MAX = 200


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _members(s: BizService) -> List[int]:
    try:
        return [int(x) for x in json.loads(s.members or "[]")]
    except Exception:
        return []


def decide(mode: str, min_up: Optional[int], up: int, total: int) -> str:
    """The state of a service with `up` of `total` members up."""
    if total == 0:
        return "unknown"
    if up == total:
        return "ok"
    if mode == "any":
        return "degraded" if up > 0 else "down"
    if mode == "min":
        return "degraded" if up >= max(1, min(min_up or total, total)) else "down"
    return "down"                                   # all


# ── Evaluation ───────────────────────────────────────────────────────────────

def evaluate(now: Optional[datetime] = None) -> dict:
    """Recomputes the state of every service from the availability of its members; writes the changes to the history and raises / closes the alerts.
    Called after every availability cycle."""
    now = now or _now()
    events: List[dict] = []
    changed = 0
    with SessionLocal() as db:
        services = db.execute(select(BizService)).scalars().all()
        astate = {r.asset_id: r for r in db.execute(select(AvailState)).scalars().all()}
        names = {a.id: (a.name or a.ip or str(a.id)) for a in db.execute(select(Asset)).scalars().all()}
        states = {r.service_id: r for r in db.execute(select(BizState)).scalars().all()}
        for s in services:
            members = _members(s)
            known = [m for m in members if m in astate]
            up = sum(1 for m in known if astate[m].state == "up")
            missing = [names.get(m, str(m)) for m in known if astate[m].state != "up"]
            new = decide(s.mode, s.min_up, up, len(known)) if known else "unknown"
            row = states.get(s.id)
            if row is None:
                row = BizState(service_id=s.id, state="unknown", since=now, first_check=now, alerted=False)
                db.add(row)
                states[s.id] = row
            row.last_check = now
            row.detail = json.dumps({"up": up, "total": len(members), "known": len(known), "missing": missing}, ensure_ascii=False)
            if new == row.state:
                continue
            db.add(BizEvent(service_id=s.id, at=now, state=new, root_name=", ".join(missing)[:200] or None))
            changed += 1
            prev, row.state = row.state, new
            if prev == "unknown":
                row.first_check = now               # the observation starts when the first member is known
            if new in ("degraded", "down"):
                if row.problem_since is None:
                    row.problem_since = now
                events.append({"type": "bizservice_problem", "device_name": s.name, "state": new, "to_state": new, "affected": missing[:10], "count": 1,
                               "detected_at": now.isoformat()})
                row.alerted = True
            elif new == "ok":
                if row.alerted:
                    events.append({"type": "bizservice_ok", "device_name": s.name, "count": 1, "detected_at": now.isoformat(),
                                   "duration_sec": int((now - (row.problem_since or now)).total_seconds())})
                row.alerted, row.problem_since = False, None
            row.since = now
        db.execute(delete(BizEvent).where(BizEvent.at < now - timedelta(days=KEEP_DAYS)))
        db.commit()
    if events:
        _pending.extend(events)
        del _pending[:-_PENDING_MAX]
        try:
            from services import soc
            soc.ingest(events)
        except Exception as e:
            print(f"[business_services] soc ingest error: {e}")
    return {"changed": changed, "events": len(events)}


def collect_alert_events() -> List[dict]:
    out = list(_pending)
    _pending.clear()
    return out


# ── Reading ──────────────────────────────────────────────────────────────────

def _seconds(ivs, start: datetime, end: datetime, states) -> float:
    total = 0.0
    for a, b, st, _r in ivs:
        a, b = max(a, start), min(b, end)
        if b > a and st in states:
            total += (b - a).total_seconds()
    return total


def _history(db, sid: int, first_check: datetime, now: datetime, state_now: str, days: int):
    """Intervals of the last `days` days (at most since the first check): [(from, to, state, missing)]."""
    from services import availability
    since = max(first_check, now - timedelta(days=days))
    evs = db.execute(select(BizEvent).where(BizEvent.service_id == sid, BizEvent.at >= since).order_by(BizEvent.id)).scalars().all()
    before = db.execute(select(BizEvent).where(BizEvent.service_id == sid, BizEvent.at < since).order_by(BizEvent.id.desc()).limit(1)).scalars().first()
    ivs = availability._intervals(evs, since, now, state_now, initial=before.state if before else "ok")
    if before is not None and ivs and not evs:
        ivs = [(since, now, before.state, before.root_name)]
    return since, ivs


def _view(db, s: BizService, st: Optional[BizState], names: Dict[int, str], now: datetime) -> dict:
    from services import availability
    members = _members(s)
    detail = {}
    try:
        detail = json.loads(st.detail) if st and st.detail else {}
    except Exception:
        pass
    out = {"id": s.id, "name": s.name, "description": s.description, "mode": s.mode, "min_up": s.min_up, "target": s.target, "members": members,
           "member_names": [names.get(m, str(m)) for m in members], "state": st.state if st else "unknown", "since": _iso(st.since) if st else None,
           "up": detail.get("up", 0), "total": len(members), "missing": detail.get("missing", []), "uptime": {}, "month": None}
    if st is None:
        return out
    good = ("ok", "degraded")
    for key, days in availability.WINDOWS:
        since, ivs = _history(db, s.id, st.first_check, now, st.state, days)
        out["uptime"][key] = availability._uptime(ivs, since, now, good)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_end = (month_start + timedelta(days=32)).replace(day=1)
    since, ivs = _history(db, s.id, st.first_check, now, st.state, 32)
    since = max(since, month_start)
    down = _seconds(ivs, since, now, ("down",))
    month = {"uptime": availability._uptime(ivs, since, now, good), "down_min": round(down / 60, 1)}
    if s.target is not None:
        allowed = (1 - s.target / 100.0) * (month_end - month_start).total_seconds()
        month.update(target=s.target, allowed_min=round(allowed / 60, 1), left_min=round((allowed - down) / 60, 1),
                     met=(month["uptime"] is None or month["uptime"] >= s.target))
    out["month"] = month
    return out


def list_services() -> dict:
    now = _now()
    with SessionLocal() as db:
        names = {a.id: (a.name or a.ip or str(a.id)) for a in db.execute(select(Asset)).scalars().all()}
        states = {r.service_id: r for r in db.execute(select(BizState)).scalars().all()}
        items = [_view(db, s, states.get(s.id), names, now) for s in db.execute(select(BizService).order_by(BizService.name)).scalars().all()]
    order = {"down": 0, "degraded": 1, "unknown": 2, "ok": 3}
    items.sort(key=lambda r: (order.get(r["state"], 3), r["name"].lower()))
    return {"items": items, "down": sum(1 for r in items if r["state"] == "down"), "degraded": sum(1 for r in items if r["state"] == "degraded"),
            "ok": sum(1 for r in items if r["state"] == "ok")}


def get_service(sid: int, days: int = 30) -> Optional[dict]:
    from services import availability
    now = _now()
    days = max(1, min(int(days), KEEP_DAYS))
    with SessionLocal() as db:
        s = db.get(BizService, sid)
        if s is None:
            return None
        names = {a.id: (a.name or a.ip or str(a.id)) for a in db.execute(select(Asset)).scalars().all()}
        st = db.get(BizState, sid)
        out = _view(db, s, st, names, now)
        out["days"] = days
        out["outages"] = []
        if st is not None:
            since, ivs = _history(db, sid, st.first_check, now, st.state, days)
            out["outages"] = [{"from": _iso(a), "to": None if (b >= now and st.state != "ok" and i == len(ivs) - 1) else _iso(b), "seconds": int((b - a).total_seconds()),
                               "kind": state, "missing": missing}
                              for i, (a, b, state, missing) in enumerate(ivs) if state in ("down", "degraded") and b > a][::-1]
        astate = {r.asset_id: r for r in db.execute(select(AvailState).where(AvailState.asset_id.in_(_members(s) or [0]))).scalars().all()}
        out["member_states"] = [{"id": m, "name": names.get(m, str(m)), "state": astate[m].state if m in astate else None,
                                 "root": names.get(astate[m].root_asset_id) if m in astate and astate[m].root_asset_id else None} for m in _members(s)]
        return out


# ── Changes ──────────────────────────────────────────────────────────────────

def _clean(name: str, description: Optional[str], mode: str, min_up: Optional[int], target: Optional[float], members: List[int]) -> dict:
    name = (name or "").strip()
    if not name or len(name) > 80:
        raise ValueError("name required (80 characters at most)")
    if mode not in MODES:
        raise ValueError("unknown mode")
    ids = list(dict.fromkeys(int(m) for m in members or []))
    if not ids or len(ids) > 200:
        raise ValueError("choose 1 to 200 devices")
    if target is not None and not (0 < float(target) <= 100):
        raise ValueError("the target is a percentage between 0 and 100")
    if mode == "min":
        if min_up is None or not (1 <= int(min_up) <= len(ids)):
            raise ValueError("min_up must be between 1 and the number of devices")
    else:
        min_up = None
    return {"name": name, "description": (description or "").strip()[:300] or None, "mode": mode, "min_up": int(min_up) if min_up is not None else None,
            "target": float(target) if target is not None else None, "members": json.dumps(ids)}


def _ensure_watched(db, ids: List[int]) -> None:
    """A member has to be monitored: a device the automatic rule does not cover (a workstation) is switched on; one without an address cannot be."""
    from services import availability
    parents = availability._parents()
    for a in db.execute(select(Asset).where(Asset.id.in_(ids))).scalars().all():
        if not a.ip:
            raise ValueError(f"{a.name or a.key} has no IP address, so its availability cannot be checked")
        if not availability.is_watched(a, parents):
            a.monitor = 1
    found = {a for (a,) in db.execute(select(Asset.id).where(Asset.id.in_(ids))).all()}
    if found != set(ids):
        raise ValueError("unknown device in the list")


def save(sid: Optional[int], *, name: str, description: Optional[str], mode: str, min_up: Optional[int], target: Optional[float], members: List[int]) -> int:
    f = _clean(name, description, mode, min_up, target, members)
    with SessionLocal() as db:
        _ensure_watched(db, json.loads(f["members"]))
        dup = db.execute(select(BizService).where(BizService.name == f["name"])).scalars().first()
        if dup is not None and dup.id != sid:
            raise ValueError("a service with this name exists")
        s = db.get(BizService, sid) if sid else None
        if sid and s is None:
            raise LookupError("service not found")
        if s is None:
            s = BizService(**f)
            db.add(s)
        else:
            for k, v in f.items():
                setattr(s, k, v)
        db.commit()
        new_id = s.id
    evaluate()
    return new_id


def delete_service(sid: int) -> bool:
    with SessionLocal() as db:
        s = db.get(BizService, sid)
        if s is None:
            return False
        name = s.name
        db.execute(delete(BizEvent).where(BizEvent.service_id == sid))
        db.execute(delete(BizState).where(BizState.service_id == sid))
        db.delete(s)
        db.commit()
    try:
        from services import soc
        with SessionLocal() as db:
            soc._close_recovered(db, soc.fingerprint("bizsvc", name, {}), _now(), {})          # its alert goes with it
            db.commit()
    except Exception as e:
        print(f"[business_services] closing the alert failed: {e}")
    return True


def public_summary() -> dict:
    """The compact view for Central: each service with its state, since when, what is missing and the SLA numbers (names only, no addresses)."""
    d = list_services()
    return {"ok": d["ok"], "degraded": d["degraded"], "down": d["down"],
            "items": [{"n": r["name"], "s": r["state"], "since": r["since"], "up": r["up"], "total": r["total"], "missing": r["missing"][:6], "mode": r["mode"], "min": r["min_up"],
                       "u30": r["uptime"].get("30d"), "month": r["month"]} for r in d["items"]][:60]}
