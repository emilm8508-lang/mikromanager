"""
Loss of communication with the assets that matter: which sources of data each asset is expected to deliver, when each last did, and one
alert per asset when they stop (stage 3 of docs/plan-jakosc-danych.md - the user's priority).

Before this, a device was "down" only when it stopped answering a ping, and the coverage page raised one "Source silent" alert per kind of
source - seen in production: 2be3's HYPERV security logs silent since 27.10 as an alert counted 4960 times, routers of four clients sending no
log lines at all, nothing saying which asset lost which feed. Here, per asset:

  sources   icmp (availability), routeros_api (the router's resources read over its API), syslog (a datagram from its address), netflow (a
            packet from it as an exporter), winrm / ssh (a managed host's readings), host_logs (its security logs read), redfish (its BMC).
            Each delivery updates last_seen; a source that delivered on EXPECT_DAYS different days is expected from then on (the operator can
            say otherwise per asset and source). Wazuh keepalives are not read yet - the agent only has Wazuh's indexer, not its manager API.
  states    down      no ping answer and no other expected source delivering
            silent    it answers (or ping is not one of its sources) but none of its expected data sources delivers
            degraded  some expected sources deliver, some do not
            stale     the data come, but the last reading failed (a host check ending in error, a BMC answering with an error)
  timing    a source is late after max(the criticality's threshold, 2.5 x the source's normal interval, 3 x its learned gap): critical 4 min,
            important 15 min, normal 1 h by default (data/comm_watch.json, per client). An asset marked "ignore" is not watched.
  alerts    one SOC alert per asset ("comm.loss"), raised when the state turns bad and only touched afterwards (no growing count), closed
            after RECOVER_SEC of good state with the length of the outage; Central gets "comm_lost" (count 3 / 2 / 1 for critical / important
            / normal, so a Central rule with minimum count 3 notifies at once and one with 2 can be slower) and "comm_restored" events.
  causes    an asset behind a device that is down or silent (the topology chain of services/availability.py) is grouped under it: no alert of
            its own, its row names the cause. A device that is down is alerted by availability (asset_down), not here a second time.

Pure decisions in evaluate() / thresholds(); the I/O (reading the sources, the database, SOC) around them.
"""
import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Asset, AssetSource, AssetComm, AvailState

INTERVAL_SEC = 120
RECOVER_SEC = 240
EXPECT_DAYS = 3
SOURCES = ("icmp", "routeros_api", "syslog", "netflow", "winrm", "ssh", "host_logs", "redfish")
# how often each source normally delivers (seconds): the floor of its threshold
BASE_INTERVAL = {"icmp": 60, "routeros_api": 3 * 3600, "syslog": 900, "netflow": 300, "winrm": 6 * 3600, "ssh": 6 * 3600,
                 "host_logs": 600, "redfish": 6 * 3600}
DEFAULTS = {"enabled": True, "thresholds": {"critical": 240, "important": 900, "normal": 3600}, "expect_days": EXPECT_DAYS}
SEVERITY = {"critical": "critical", "important": "high", "normal": "medium"}
RANK = {"critical": 3, "important": 2, "normal": 1}
# what an asset of each kind should deliver, for the coverage report (recommended, not alarmed until expected)
RECOMMENDED = {"router": ("icmp", "routeros_api", "syslog", "netflow"), "network": ("icmp", "routeros_api", "syslog"),
               "windows_server": ("icmp", "winrm", "host_logs"), "linux_server": ("icmp", "ssh", "host_logs"), "bmc": ("redfish",)}

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "comm_watch.json")
_task: Optional[asyncio.Task] = None
_pending: List[dict] = []
_last: Dict[str, object] = {"at": None, "assets": 0, "bad": 0, "error": None, "duration_sec": None}


def settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        s["enabled"] = bool(saved.get("enabled", True))
        for k in ("critical", "important", "normal"):
            v = (saved.get("thresholds") or {}).get(k)
            if isinstance(v, (int, float)) and 60 <= v <= 7 * 86400:
                s["thresholds"][k] = int(v)
        if isinstance(saved.get("expect_days"), int) and 1 <= saved["expect_days"] <= 30:
            s["expect_days"] = saved["expect_days"]
    except (OSError, ValueError):
        pass
    return s


def update_settings(new: dict) -> dict:
    s = settings()
    if "enabled" in new:
        s["enabled"] = bool(new["enabled"])
    for k, v in (new.get("thresholds") or {}).items():
        if k not in s["thresholds"]:
            raise ValueError(f"unknown level: {k}")
        if not isinstance(v, (int, float)) or not 60 <= v <= 7 * 86400:
            raise ValueError("a threshold is between 60 seconds and 7 days")
        s["thresholds"][k] = int(v)
    if not s["thresholds"]["critical"] <= s["thresholds"]["important"] <= s["thresholds"]["normal"]:
        raise ValueError("a more important asset must not wait longer than a less important one")
    if "expect_days" in new:
        if not isinstance(new["expect_days"], int) or not 1 <= new["expect_days"] <= 30:
            raise ValueError("expect_days is 1-30")
        s["expect_days"] = new["expect_days"]
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f)
    os.replace(tmp, _PATH)
    return s


# ── pure decisions ───────────────────────────────────────────────────────────

def threshold(source: str, level: str, gap_avg: Optional[float], cfg: dict) -> float:
    base = BASE_INTERVAL.get(source, 900) * 2.5
    learned = (gap_avg or 0) * 3
    return max(float(cfg["thresholds"].get(level, cfg["thresholds"]["normal"])), base, learned)


def is_expected(src: dict, expect_days: int) -> bool:
    if src.get("expected_override") is not None:
        return bool(src["expected_override"])
    return (src.get("days_seen") or 0) >= expect_days


def evaluate(sources: Iterable[dict], level: str, avail_state: Optional[str], now: datetime, cfg: dict) -> Tuple[str, List[dict]]:
    """(state, problems) for one asset. sources: [{source, last_seen, gap_avg, days_seen, expected_override, error, error_at}];
    avail_state: the ping monitor's up / down / unreachable or None when the asset is not pinged."""
    expected = [s for s in sources if is_expected(s, cfg["expect_days"])]
    late, failing, fine = [], [], []
    for s in expected:
        if s["source"] == "icmp":
            continue                                  # judged by the ping monitor's own state below
        last = s.get("last_seen")
        if last is None or (now - last).total_seconds() > threshold(s["source"], level, s.get("gap_avg"), cfg):
            late.append({"source": s["source"], "last_seen": last.isoformat() + "Z" if last else None, "error": s.get("error")})
        elif s.get("error") and s.get("error_at") and s["error_at"] >= last:
            failing.append({"source": s["source"], "last_seen": last.isoformat() + "Z", "error": s["error"]})
        else:
            fine.append(s["source"])
    pinged = any(s["source"] == "icmp" for s in expected)
    no_ping = pinged and avail_state in ("down", "unreachable")
    if no_ping and not fine:
        return "down", late + failing
    if late and not fine and not failing:
        return "silent", late
    if late:
        return "degraded", late + failing
    if failing:
        return "stale", failing
    return "ok", []


# ── reading the sources ──────────────────────────────────────────────────────

def _observe(db, now: datetime) -> Dict[Tuple[int, str], Tuple[Optional[datetime], Optional[str]]]:
    """{(asset_id, source): (delivered at, error)} from everything the agent already keeps."""
    from models.database import Device, WindowsHost, LinuxHost, DellServer, HostLogCursor
    obs: Dict[Tuple[int, str], Tuple[Optional[datetime], Optional[str]]] = {}
    assets = db.execute(select(Asset)).scalars().all()
    by_ref: Dict[Tuple[str, int], int] = {}
    by_ip: Dict[str, int] = {}
    for a in assets:
        for k, v in json.loads(a.refs or "{}").items():
            if isinstance(v, int):
                by_ref[(k, v)] = a.id
        if a.ip:
            by_ip.setdefault(a.ip, a.id)
        for x in json.loads(a.details or "{}").get("_addrs") or []:      # a router's other addresses (services/iface_roles.py)
            if isinstance(x, dict) and x.get("ip"):
                by_ip.setdefault(x["ip"], a.id)

    def put(aid: Optional[int], source: str, at: Optional[datetime], err: Optional[str] = None):
        if aid is None or (at is None and not err):
            return
        cur = obs.get((aid, source))
        if cur is None or (at and (cur[0] is None or at > cur[0])):
            obs[(aid, source)] = (at, err)

    for st in db.execute(select(AvailState)).scalars().all():
        if st.state == "up":
            put(st.asset_id, "icmp", st.last_check)
    for d in db.execute(select(Device)).scalars().all():
        put(by_ref.get(("device_id", d.id)), "routeros_api", d.last_resources_check_at)
    for h in db.execute(select(WindowsHost).where(WindowsHost.managed.is_(True))).scalars().all():
        put(by_ref.get(("windows_host_id", h.id)), "winrm", h.last_resources_check_at,
            (h.last_error or "error")[:200] if h.last_status not in (None, "ok") else None)
    for h in db.execute(select(LinuxHost).where(LinuxHost.managed.is_(True))).scalars().all():
        put(by_ref.get(("linux_host_id", h.id)), "ssh", getattr(h, "last_resources_check_at", None) or h.last_seen_at,
            (getattr(h, "last_error", None) or "error")[:200] if getattr(h, "last_status", None) not in (None, "ok") else None)
    for c in db.execute(select(HostLogCursor)).scalars().all():
        put(by_ref.get((f"{c.kind}_host_id", c.host_id)), "host_logs", c.last_ok_at, (c.last_error or "")[:200] or None)
    for s in db.execute(select(DellServer)).scalars().all():
        aid = by_ref.get(("dell_server_id", s.id))
        if s.last_status == "ok":
            put(aid, "redfish", s.last_check_at)
        elif s.last_status:
            put(aid, "redfish", None, (s.last_error or s.last_status)[:200])
    try:
        from services import syslog_receiver
        for ip, ts in list(syslog_receiver.last_by_ip.items()):
            put(by_ip.get(ip), "syslog", datetime.utcfromtimestamp(ts))
    except Exception:
        pass
    try:
        from services import netflow
        for ip, e in list(netflow._exporters.items()):
            if e.get("last"):
                put(by_ip.get(ip), "netflow", datetime.fromisoformat(e["last"].rstrip("Z")))
    except Exception:
        pass
    return obs


def _record(db, obs: dict, now: datetime) -> Dict[int, List[AssetSource]]:
    rows = {(r.asset_id, r.source): r for r in db.execute(select(AssetSource)).scalars().all()}
    for (aid, source), (at, err) in obs.items():
        r = rows.get((aid, source))
        if r is None:
            # the first sight of a source: when its last delivery is already more than a day old, it worked before the watch began and has
            # stopped - expected from the start (seen: 2be3's HYPERV security logs, silent since 27.10, would otherwise never be expected)
            stopped = at is not None and (now - at).total_seconds() > 86400
            r = AssetSource(asset_id=aid, source=source, days_seen=settings()["expect_days"] - 1 if stopped else 0)
            db.add(r)
            rows[(aid, source)] = r
        if at and (r.last_seen is None or at > r.last_seen):
            if r.last_seen is not None:
                gap = (at - r.last_seen).total_seconds()
                r.gap_avg = gap if r.gap_avg is None else 0.8 * r.gap_avg + 0.2 * gap
            r.first_seen = r.first_seen or at
            r.last_seen = at
            day = at.strftime("%Y-%m-%d")
            if r.last_day != day:
                r.last_day = day
                r.days_seen = (r.days_seen or 0) + 1
        if err:
            r.error, r.error_at = err, now
        elif at and r.error and (r.error_at is None or at > r.error_at):
            r.error = r.error_at = None
    db.flush()
    by_asset: Dict[int, List[AssetSource]] = {}
    for r in rows.values():
        by_asset.setdefault(r.asset_id, []).append(r)
    return by_asset


# ── the cycle ────────────────────────────────────────────────────────────────

def _level(a: Asset, row: Optional[dict] = None) -> str:
    from services import asset_type as at
    lv = at.normalize_level(a.criticality)
    if lv:
        return lv
    det = json.loads(a.details or "{}")
    return at.suggest(asset_type=a.asset_type, dclass=det.get("_class"), name=a.name, role=a.role)[0]


def _causes(bad: set, attach: Dict[int, dict]) -> Dict[int, int]:
    """asset -> the topmost asset above it that is bad too (its problem is that one's)."""
    from services import availability
    out = {}
    for aid in bad:
        above = [x for x in availability._chain(aid, attach) if x in bad]
        if above:
            out[aid] = above[-1]
    return out


def run_cycle(now: Optional[datetime] = None) -> dict:
    t0 = datetime.utcnow()
    now = now or t0
    cfg = settings()
    if not cfg["enabled"]:
        return {"skipped": "off"}
    from services import soc
    events: List[dict] = []
    actions: List[tuple] = []                 # SOC writes, done after this transaction is committed (SQLite: one writer at a time)
    with SessionLocal() as db:
        obs = _observe(db, now)
        by_asset = _record(db, obs, now)
        assets = {a.id: a for a in db.execute(select(Asset)).scalars().all()}
        avail = {r.asset_id: r.state for r in db.execute(select(AvailState)).scalars().all()}
        comm = {r.asset_id: r for r in db.execute(select(AssetComm)).scalars().all()}
        results: Dict[int, Tuple[str, List[dict], str]] = {}
        for aid, srcs in by_asset.items():
            a = assets.get(aid)
            if a is None:
                continue
            level = _level(a)
            if level == "ignore":
                continue
            st, probs = evaluate([{"source": s.source, "last_seen": s.last_seen, "gap_avg": s.gap_avg, "days_seen": s.days_seen,
                                   "expected_override": s.expected_override, "error": s.error, "error_at": s.error_at} for s in srcs],
                                 level, avail.get(aid), now, cfg)
            results[aid] = (st, probs, level)
        try:
            from services import topology_map
            attach = topology_map.attachments()
        except Exception:
            attach = {}
        bad = {aid for aid, (st, _p, _l) in results.items() if st != "ok"} | {aid for aid, s in avail.items() if s in ("down", "unreachable")}
        causes = _causes(bad, attach)
        for aid, (st, probs, level) in results.items():
            a = assets[aid]
            row = comm.get(aid)
            if row is None:
                row = AssetComm(asset_id=aid, state="ok", since=now, alerted=False)
                db.add(row)
                comm[aid] = row
            cause_id = causes.get(aid)
            row.cause = (assets[cause_id].name or assets[cause_id].ip) if cause_id in assets else None
            row.missing = json.dumps(probs) if probs else None
            name = a.name or a.ip or str(aid)
            if st != row.state:
                row.since = now
            row.state = st
            if st == "ok":
                if row.alerted:
                    row.ok_since = row.ok_since or now
                    if (now - row.ok_since).total_seconds() >= RECOVER_SEC:          # back, and staying back: close and report the outage
                        dur = int((now - (row.bad_since or row.ok_since)).total_seconds())
                        actions.append(("resolve", {"rule": "comm.loss", "device": name}))
                        events.append({"type": "comm_restored", "device_name": name, "ip": a.ip, "asset_id": aid, "count": RANK.get(level, 1),
                                       "criticality": level, "duration_sec": dur, "detected_at": now.isoformat()})
                        row.alerted, row.bad_since, row.ok_since = False, None, None
                else:
                    row.bad_since = row.ok_since = None
                continue
            row.ok_since = None
            if row.bad_since is None:
                # the outage began when the missing data last came, not when the threshold noticed it
                starts = [datetime.fromisoformat(p["last_seen"].rstrip("Z")) for p in probs if p.get("last_seen")]
                row.bad_since = min(starts) if starts else now
            if st == "down" or cause_id is not None:
                continue                         # the ping monitor alerts a device that is down; an asset behind a bad one is grouped under it
            detail = {"message": f"{name}: {st} - " + ", ".join(p["source"] + (f" (last {p['last_seen'][:16].replace('T', ' ')})" if p.get("last_seen") else " (never)")
                                                             for p in probs),
                      "state": st, "criticality": level, "missing": probs[:8],
                      "grouped": sorted((assets[x].name or assets[x].ip) for x, c in causes.items() if c == aid and x in assets)[:20]}
            kw = {"rule": "comm.loss", "device": name, "title": "Communication lost" if st == "silent" else "Data sources missing",
                  "severity": SEVERITY.get(level, "medium"), "category": "availability", "detail": detail, "ip": a.ip, "asset_id": aid, "now": now}
            if not row.alerted:
                actions.append(("raise", kw))
                events.append({"type": "comm_lost", "device_name": name, "ip": a.ip, "asset_id": aid, "count": RANK.get(level, 1), "criticality": level,
                               "state": st, "missing": [p["source"] for p in probs], "detected_at": now.isoformat()})
                row.alerted = True
            else:
                actions.append(("raise", {**kw, "count": 0}))          # the standing alert is touched (detail, last seen), not counted again
        db.commit()
    for kind, kw in actions:
        try:
            soc.raise_alert(**kw) if kind == "raise" else soc.resolve(**kw)
        except Exception as e:
            print(f"[comm_watch] soc {kind} error: {type(e).__name__}: {e}")
    if events:
        _pending.extend(events)
        del _pending[:-500]
    _last.update(at=datetime.utcnow().isoformat() + "Z", assets=len(results), bad=sum(1 for v in results.values() if v[0] != "ok"), error=None,
                 duration_sec=round((datetime.utcnow() - t0).total_seconds(), 2))
    return {"assets": len(results), "events": len(events)}


def collect_alert_events() -> List[dict]:
    out = list(_pending)
    _pending.clear()
    return out


def set_expected(asset_id: int, source: str, expected: Optional[bool]) -> dict:
    if source not in SOURCES:
        raise ValueError(f"unknown source: {source}")
    with SessionLocal() as db:
        if db.get(Asset, asset_id) is None:
            raise ValueError("no such asset")
        r = db.execute(select(AssetSource).where(AssetSource.asset_id == asset_id, AssetSource.source == source)).scalars().first()
        if r is None:
            r = AssetSource(asset_id=asset_id, source=source, days_seen=0)
            db.add(r)
        r.expected_override = None if expected is None else (1 if expected else 0)
        db.commit()
    return {"ok": True}


def _kind(a: Asset) -> Optional[str]:
    det = json.loads(a.details or "{}")
    refs = json.loads(a.refs or "{}")
    if det.get("_class") in ("gateway", "router"):
        return "router"
    if a.asset_type == "network":
        return "network"
    if refs.get("dell_server_id") and not refs.get("windows_host_id") and not refs.get("linux_host_id"):
        return "bmc"
    if a.role == "server" or a.asset_type in ("server", "virtual"):
        return "windows_server" if (a.asset_type == "windows" or "windows" in (a.os_name or "").lower()) else "linux_server"
    return None


def coverage(levels: Tuple[str, ...] = ("critical", "important")) -> List[dict]:
    """The assets of these levels with their sources: expected and delivering, expected and late, recommended but never seen."""
    now = datetime.utcnow()
    cfg = settings()
    out = []
    with SessionLocal() as db:
        srcs: Dict[int, List[AssetSource]] = {}
        for r in db.execute(select(AssetSource)).scalars().all():
            srcs.setdefault(r.asset_id, []).append(r)
        comm = {r.asset_id: r for r in db.execute(select(AssetComm)).scalars().all()}
        for a in db.execute(select(Asset)).scalars().all():
            level = _level(a)
            if level not in levels:
                continue
            have = {s.source: s for s in srcs.get(a.id, [])}
            rows = []
            for name, s in sorted(have.items()):
                exp = is_expected({"expected_override": s.expected_override, "days_seen": s.days_seen}, cfg["expect_days"])
                late = s.last_seen is None or (now - s.last_seen).total_seconds() > threshold(name, level, s.gap_avg, cfg)
                rows.append({"source": name, "expected": exp, "override": s.expected_override, "last_seen": s.last_seen.isoformat() + "Z" if s.last_seen else None,
                             "state": "late" if (exp and late) else "error" if s.error else "ok" if not late else "quiet", "error": s.error})
            kind = _kind(a)
            missing = [x for x in RECOMMENDED.get(kind or "", ()) if x not in have]
            c = comm.get(a.id)
            out.append({"id": a.id, "name": a.name or a.ip, "ip": a.ip, "criticality": level, "kind": kind, "state": c.state if c else None,
                        "since": c.since.isoformat() + "Z" if c and c.since else None, "cause": c.cause if c else None, "sources": rows,
                        "never_seen": missing})
    order = {"down": 0, "silent": 1, "degraded": 2, "stale": 3, "ok": 4, None: 5}
    out.sort(key=lambda r: (order.get(r["state"], 5), -RANK.get(r["criticality"], 0), (r["name"] or "").lower()))
    return out


def public_summary() -> dict:
    """For Central: the counts per state and the important / critical assets with a problem or a gap (names, no addresses)."""
    cov = coverage()
    return {"at": _last.get("at"), "states": {s: sum(1 for r in cov if r["state"] == s) for s in ("down", "silent", "degraded", "stale", "ok")},
            "items": [{"n": r["name"], "c": r["criticality"], "s": r["state"], "since": r["since"], "cause": r["cause"],
                       "late": [x["source"] for x in r["sources"] if x["state"] == "late"],
                       "err": [x["source"] for x in r["sources"] if x["state"] == "error"],
                       "never": r["never_seen"],
                       "seen": {x["source"]: x["last_seen"] for x in r["sources"]}} for r in cov
                      if r["state"] not in ("ok", None) or r["never_seen"]][:80]}


def status() -> dict:
    return dict(_last)


async def _loop():
    await asyncio.sleep(180)
    while True:
        try:
            await asyncio.get_event_loop().run_in_executor(None, run_cycle)
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[comm_watch] cycle error: {type(e).__name__}: {e}")
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
