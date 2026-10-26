"""
Availability of the equipment, with the topology taken into account (the NetXMS idea of "down" and "unreachable").

A monitor that pings everything tells you, when a switch fails, that the switch and the forty things behind it are down - forty-one alerts for one
fault. The agent already knows what hangs on what (the switch port a host was learned on, the access point of a Wi-Fi client, the router of a segment,
the Hyper-V host of a VM: services/topology_map.py), so here a device that does not answer is

  down         - it does not answer and nothing it hangs on is down either: it is the fault itself, the one that is alerted;
  unreachable  - it does not answer but the device it hangs on does not either: a consequence, written to the history with the device that is the
                 cause, not alerted on its own (the alert of the root cause lists what is behind it).

What is watched (`Asset.monitor`): 1 = on, 0 = off, none = automatic - network gear, servers, and everything others hang on (so a switch, an access
point or a hypervisor is always watched, a workstation only when asked). A device is up when it answers a ping or any of a few well-known TCP ports
(a router hardened to Winbox only does not answer ICMP and is not down). The history of changes (`AvailEvent`) gives the uptime of 24 h / 7 d / 30 d
and the list of outages with their cause. Alerts: `asset_down` / `asset_up` events - they go through the SOC layer at once and, with the other
alert events, to Central.
"""
import asyncio
import json
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, delete

from models.database import SessionLocal, Asset, AvailState, AvailEvent

INTERVAL_SEC = 60
KEEP_DAYS = 400
MAX_CHAIN = 8
TCP_PORTS = (443, 22, 80, 8291, 3389, 445, 8728, 53)
WINDOWS = (("24h", 1), ("7d", 7), ("30d", 30))

_task: Optional[asyncio.Task] = None
_pending: List[dict] = []                 # alert events for Central (drained by the uplink)
_PENDING_MAX = 500
_last: Dict[str, object] = {"at": None, "checked": 0, "duration_sec": None, "error": None}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── What is watched ──────────────────────────────────────────────────────────

def _parents() -> set:
    """Assets something else is attached to (per the last map)."""
    from services import topology_map
    return {a.get("to_id") for a in topology_map.attachments().values() if isinstance(a.get("to_id"), int)}


def is_watched(a: Asset, parents: Optional[set] = None) -> bool:
    if not a.ip:
        return False
    if a.monitor is not None:
        return bool(a.monitor)
    if a.asset_type in ("network", "server") or a.role == "server":
        return True
    return a.id in (parents if parents is not None else _parents())


def _targets() -> List[dict]:
    parents = _parents()
    with SessionLocal() as db:
        return [{"id": a.id, "name": a.name or a.ip, "ip": a.ip} for a in db.execute(select(Asset)).scalars().all() if is_watched(a, parents)]


# ── Probing ──────────────────────────────────────────────────────────────────

def _tcp_sync(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return True
    except OSError:
        return False


async def _answers(ip: str) -> Tuple[bool, str]:
    from services import edge_selfcheck
    loop = asyncio.get_event_loop()
    ok, _method, detail = await edge_selfcheck._check_one(loop, ip, None)
    if ok:
        return True, "ping OK"
    opened = await asyncio.gather(*[loop.run_in_executor(None, _tcp_sync, ip, p) for p in TCP_PORTS])
    for p, o in zip(TCP_PORTS, opened):
        if o:
            return True, f"TCP {p} open (no ping answer)"
    return False, "no answer to ping nor to TCP " + "/".join(str(p) for p in TCP_PORTS[:4])


async def _probe(t: dict, sem: asyncio.Semaphore) -> Tuple[int, bool, str]:
    async with sem:
        try:
            ok, detail = await _answers(t["ip"])
            if not ok:                       # one more try after a moment, so a single lost packet is not an outage
                await asyncio.sleep(3)
                ok, detail = await _answers(t["ip"])
        except Exception as e:
            ok, detail = False, f"check error: {type(e).__name__}: {e}"
        return t["id"], ok, detail


# ── Topology ─────────────────────────────────────────────────────────────────

def _chain(asset_id: int, attach: Dict[int, dict]) -> List[int]:
    """What the asset hangs on, nearest first: its switch / access point / router / Hyper-V host, then what that hangs on ..."""
    out: List[int] = []
    cur = asset_id
    while len(out) < MAX_CHAIN:
        up = (attach.get(cur) or {}).get("to_id")
        if not isinstance(up, int) or up in out or up == asset_id:
            break
        out.append(up)
        cur = up
    return out


def upstream_down(db, asset_id: Optional[int]) -> Optional[Tuple[int, str]]:
    """The device that is down above this asset (the topmost one of its chain), or None. For the alerts other sources raise (PRTG, Checkmk,
    a watched host) about something behind a device that is down."""
    if not asset_id:
        return None
    try:
        from services import topology_map
        chain = _chain(asset_id, topology_map.attachments())
        if not chain:
            return None
        down = {r.asset_id for r in db.execute(select(AvailState).where(AvailState.asset_id.in_(chain), AvailState.state == "down")).scalars().all()}
        for a in reversed(chain):
            if a in down:
                row = db.get(Asset, a)
                return a, (row.name or row.ip or str(a)) if row else str(a)
    except Exception:
        pass
    return None


# ── The cycle ────────────────────────────────────────────────────────────────

def _emit(events: List[dict]) -> None:
    if not events:
        return
    _pending.extend(events)
    del _pending[:-_PENDING_MAX]
    try:
        from services import soc
        soc.ingest(events)               # at once - the SOC layer is not waiting for an uplink (the same event is not taken twice)
    except Exception as e:
        print(f"[availability] soc ingest error: {e}")


def _outage_start(db, asset_id: int, now: datetime) -> datetime:
    """When the outage that has just ended began: the change after the last time it was up."""
    up = db.execute(select(AvailEvent).where(AvailEvent.asset_id == asset_id, AvailEvent.state == "up").order_by(AvailEvent.id.desc()).limit(1)).scalars().first()
    q = select(AvailEvent).where(AvailEvent.asset_id == asset_id, AvailEvent.state != "up")
    if up is not None:
        q = q.where(AvailEvent.id > up.id)
    first = db.execute(q.order_by(AvailEvent.id).limit(1)).scalars().first()
    return first.at if first else now


async def run_cycle(now: Optional[datetime] = None) -> dict:
    t0 = _now()
    now = now or t0
    from services import topology_map
    topology_map.kick()                      # the placement is as old as the last map; this starts a rebuild when it is due
    targets = _targets()
    sem = asyncio.Semaphore(20)
    results = {aid: (ok, detail) for aid, ok, detail in await asyncio.gather(*[_probe(t, sem) for t in targets])}
    attach = topology_map.attachments()
    failing = {aid for aid, (ok, _d) in results.items() if not ok}
    names = {t["id"]: t["name"] for t in targets}
    ips = {t["id"]: t["ip"] for t in targets}

    # the new state of every asset that was checked
    new: Dict[int, Tuple[str, Optional[int]]] = {}
    for aid in results:
        if aid not in failing:
            new[aid] = ("up", None)
            continue
        above = [a for a in _chain(aid, attach) if a in failing]
        new[aid] = ("unreachable", above[-1]) if above else ("down", None)       # the topmost failing one is the cause
    behind: Dict[int, List[str]] = {}
    for aid, (st, root) in new.items():
        if st == "unreachable" and root is not None:
            behind.setdefault(root, []).append(names.get(aid) or str(aid))

    events: List[dict] = []
    with SessionLocal() as db:
        rows = {r.asset_id: r for r in db.execute(select(AvailState).where(AvailState.asset_id.in_(list(results) or [0]))).scalars().all()}
        for aid, (st, root) in new.items():
            ok, detail = results[aid]
            row = rows.get(aid)
            if row is None:
                row = AvailState(asset_id=aid, state="up", since=now, first_check=now, alerted=False)
                db.add(row)
                rows[aid] = row
            row.last_check, row.detail = now, detail[:200]
            if st == row.state and root == row.root_asset_id:
                continue
            prev = row.state
            root_name = names.get(root) if root else None
            if st != prev:
                db.add(AvailEvent(asset_id=aid, at=now, state=st, root_asset_id=root, root_name=root_name, detail=detail[:200]))
            if st == "up":
                if row.alerted:
                    events.append({"type": "asset_up", "device_name": names.get(aid), "ip": ips.get(aid), "asset_id": aid,
                                   "duration_sec": int((now - _outage_start(db, aid, now)).total_seconds()), "count": 1, "detected_at": now.isoformat()})
                row.alerted = False
            elif st == "down" and not row.alerted:
                events.append({"type": "asset_down", "device_name": names.get(aid), "ip": ips.get(aid), "asset_id": aid, "count": 1,
                               "detected_at": now.isoformat(), "detail": detail, "affected": sorted(behind.get(aid, []))[:10]})
                row.alerted = True
            if st != prev:
                row.since = now
            row.state, row.root_asset_id = st, root
        db.execute(delete(AvailEvent).where(AvailEvent.at < now - timedelta(days=KEEP_DAYS)))
        db.commit()
    _emit(events)
    _last.update(at=_iso(_now()), checked=len(targets), duration_sec=round((_now() - t0).total_seconds(), 1), error=None)
    return {"checked": len(targets), "down": sum(1 for s, _ in new.values() if s == "down"),
            "unreachable": sum(1 for s, _ in new.values() if s == "unreachable"), "events": len(events)}


async def _loop():
    await asyncio.sleep(45)                  # the first map of the topology builds in the meantime
    while True:
        try:
            await run_cycle()
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[availability] cycle error: {e}")
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


def collect_alert_events() -> List[dict]:
    """The asset_down / asset_up events since the last report, for Central (and its Telegram / rules)."""
    out = list(_pending)
    _pending.clear()
    return out


# ── Reading: uptime and outages ──────────────────────────────────────────────

def _intervals(events: List[AvailEvent], first: datetime, now: datetime, state_now: str) -> List[Tuple[datetime, datetime, str, Optional[str]]]:
    """[(from, to, state, root name)] covering first..now from the changes (the state before the first change is "up")."""
    out = []
    cur, since, root = "up", first, None
    for e in events:
        if e.state == cur:
            continue
        if e.at > since:
            out.append((since, e.at, cur, root))
        cur, since, root = e.state, max(e.at, since), e.root_name
    out.append((since, now, cur if events else state_now, root))
    return out


def _uptime(intervals, start: datetime, end: datetime) -> Optional[float]:
    total = up = 0.0
    for a, b, st, _r in intervals:
        a, b = max(a, start), min(b, end)
        if b <= a:
            continue
        total += (b - a).total_seconds()
        if st == "up":
            up += (b - a).total_seconds()
    return round(100.0 * up / total, 3) if total > 0 else None


def overview() -> dict:
    """Every watched asset with its state, since when, the uptime of 24 h / 7 d / 30 d and where the cause is."""
    now = _now()
    parents = _parents()
    with SessionLocal() as db:
        assets = {a.id: a for a in db.execute(select(Asset)).scalars().all()}
        states = {r.asset_id: r for r in db.execute(select(AvailState)).scalars().all()}
        evs: Dict[int, List[AvailEvent]] = {}
        for e in db.execute(select(AvailEvent).where(AvailEvent.at >= now - timedelta(days=30)).order_by(AvailEvent.id)).scalars().all():
            evs.setdefault(e.asset_id, []).append(e)
        rows = []
        for aid, a in assets.items():
            st = states.get(aid)
            watched = is_watched(a, parents)
            if not watched:
                continue
            if st is None:
                rows.append({"id": aid, "name": a.name or a.ip, "ip": a.ip, "type": a.asset_type, "watched": watched, "mode": a.monitor,
                             "state": None, "since": None, "uptime": {}, "root": None, "detail": None, "last_check": None})
                continue
            ivs = _intervals(evs.get(aid, []), max(st.first_check, now - timedelta(days=30)), now, st.state)
            up = {k: _uptime(ivs, max(st.first_check, now - timedelta(days=d)), now) for k, d in WINDOWS}
            root = assets.get(st.root_asset_id) if st.root_asset_id else None
            rows.append({"id": aid, "name": a.name or a.ip, "ip": a.ip, "type": a.asset_type, "watched": watched, "mode": a.monitor,
                         "state": st.state, "since": _iso(st.since), "uptime": up, "root": (root.name or root.ip) if root else None,
                         "root_id": st.root_asset_id, "detail": st.detail, "last_check": _iso(st.last_check)})
    order = {"down": 0, "unreachable": 1, "up": 2, None: 3}
    rows.sort(key=lambda r: (order.get(r["state"], 3), (r["name"] or "").lower()))
    return {"items": rows, "down": sum(1 for r in rows if r["state"] == "down"), "unreachable": sum(1 for r in rows if r["state"] == "unreachable"),
            "up": sum(1 for r in rows if r["state"] == "up"), "last": _last, "interval_sec": INTERVAL_SEC}


def outages(asset_id: int, days: int = 30) -> dict:
    """The outages of one asset in the last `days`: [{from, to, seconds, kind: down|unreachable, cause}], the newest first, and its uptime."""
    now = _now()
    days = max(1, min(int(days), KEEP_DAYS))
    with SessionLocal() as db:
        st = db.get(AvailState, asset_id)
        if st is None:
            return {"outages": [], "uptime": None, "state": None}
        evs = db.execute(select(AvailEvent).where(AvailEvent.asset_id == asset_id, AvailEvent.at >= now - timedelta(days=days)).order_by(AvailEvent.id)).scalars().all()
        start = max(st.first_check, now - timedelta(days=days))
        # the state at the start of the window is the one the first change left behind
        before = db.execute(select(AvailEvent).where(AvailEvent.asset_id == asset_id, AvailEvent.at < now - timedelta(days=days)).order_by(AvailEvent.id.desc()).limit(1)).scalars().first()
        ivs = _intervals(evs, start, now, st.state)
        if before is not None and ivs and ivs[0][2] == "up" and before.state != "up":
            ivs[0] = (ivs[0][0], ivs[0][1], before.state, before.root_name)
        rows = [{"from": _iso(a), "to": None if b >= now and st.state != "up" and i == len(ivs) - 1 else _iso(b), "seconds": int((b - a).total_seconds()),
                 "kind": s, "cause": r}
                for i, (a, b, s, r) in enumerate(ivs) if s != "up" and b > a]
        return {"outages": rows[::-1], "uptime": _uptime(ivs, start, now), "state": st.state, "since": _iso(st.since), "days": days}


def set_monitor(asset_id: int, mode: Optional[int]) -> bool:
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if a is None:
            return False
        a.monitor = None if mode is None else (1 if mode else 0)
        db.commit()
    return True


def affected_by(asset_id: int) -> List[dict]:
    """What is unreachable because of this asset now: [{id, name, ip}]."""
    with SessionLocal() as db:
        ids = [r.asset_id for r in db.execute(select(AvailState).where(AvailState.root_asset_id == asset_id, AvailState.state == "unreachable")).scalars().all()]
        return [{"id": a.id, "name": a.name or a.ip, "ip": a.ip} for a in db.execute(select(Asset).where(Asset.id.in_(ids or [0]))).scalars().all()]


def public_summary() -> dict:
    """The compact view for Central: the counts and what is down / unreachable (names and the cause, no addresses)."""
    o = overview()
    return {"up": o["up"], "down": o["down"], "unreachable": o["unreachable"],
            "bad": [{"n": r["name"], "s": r["state"], "since": r["since"], "root": r["root"]} for r in o["items"] if r["state"] in ("down", "unreachable")][:40],
            "at": _iso(_now())}
