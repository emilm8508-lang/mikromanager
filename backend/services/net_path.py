"""
The path to a target, hop by hop, with the latency and loss of each hop, and where a problem starts (the "NetPath" idea).

services/net_quality.py says "the internet link loses 8% of the packets". The next question is where: in our own router, at the ISP's
first router, or somewhere far away. Every 15 minutes, for each link-quality target of your own (data/net_quality.json, by default
1.1.1.1), the path is traced (services/traceroute.py - the system's tracert / traceroute) and every hop that answers gets a short
burst of pings (the same measurement as the link quality): latency, jitter, loss per hop.

Where the problem starts - the culprit hop: a router that answers slowly or drops its own pings while the hops after it are fine only
protects itself (routers rate-limit ICMP addressed to them); that is not a fault. A hop counts only when loss (or a latency jump)
starts there and lasts in every answering hop after it, up to the target:
  loss      the first hop from which every later answering hop loses at least the loss limit, the target included;
  latency   the first hop where the latency jumps by at least LAT_JUMP_MS over the hop before, and every later hop stays that high.

The path is the sequence of answering hops. "Changed" means a router answered that no trace of the last day saw (3.94.2): an ISP balancing
its traffic over several paths alternates between routers already seen, which is not a change. Before, a trace that differed from the most
frequent path counted - at aluplasti that was 85 of 96 traces a day. The newest BASELINE_GAP of traces is left out of what counts as seen, so
a real move to new routers stays "changed" for a while (and is alerted after two traces) before it becomes the known path.

Kept: every trace for 14 days (NetPathTrace). Alerts, each after two traces in a row, closed after a good one:
  metric.path_degraded  loss / latency starts at hop N (medium) - the hop's address is in the detail;
  metric.path_changed   the path differs from the usual one (low).
Nothing but ICMP / the system's traceroute is sent.
"""
import asyncio
import json
import os
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import delete, select

from models.database import SessionLocal, NetPathTrace

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "net_path.json")
INTERVAL_SEC = 900
KEEP_DAYS = 14
MAX_TARGETS = 10
MAX_HOPS = 20
HOP_PINGS = 5
PARALLEL = 4
LAT_JUMP_MS = 50.0
STREAK = 2
BASELINE_GAP_MIN = 45

_task: Optional[asyncio.Task] = None
_last: Dict[str, object] = {"at": None, "targets": 0, "duration_sec": None, "error": None}
_streak: Dict[Tuple[str, str], int] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def load_settings() -> dict:
    s = {"enabled": True}
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict) and isinstance(saved.get("enabled"), bool):
            s["enabled"] = saved["enabled"]
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[net_path] settings unreadable, defaults used: {type(e).__name__}: {e}")
    return s


def save_settings(body: dict) -> dict:
    s = load_settings()
    if "enabled" in body:
        s["enabled"] = bool(body["enabled"])
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(s, f)
    return s


# ── Analysis (pure) ──────────────────────────────────────────────────────────

def signature(hops: List[dict]) -> str:
    """The path as the answering hops in order; a silent hop is "-" (its position still counts)."""
    return ">".join(h.get("ip") or "-" for h in hops)


def _same_path(a: str, b: str) -> bool:
    """Two paths are the same when every hop answering in both is the same router (a hop silent in one trace is not a change)."""
    pa, pb = a.split(">"), b.split(">")
    if len(pa) != len(pb):
        return False
    return all(x == y or x == "-" or y == "-" for x, y in zip(pa, pb))


def usual(signatures: List[str]) -> Optional[str]:
    """The most frequent path of a list (the newest wins a tie)."""
    if not signatures:
        return None
    c = Counter(signatures)
    best = max(c.values())
    for sig in reversed(signatures):
        if c[sig] == best:
            return sig
    return None


def new_routers(sig: str, known: List[str], target: Optional[str] = None) -> List[str]:
    """The answering hops of a path that none of the known paths had (the target itself does not count)."""
    seen = {ip for s in known for ip in s.split(">") if ip and ip != "-"}
    return [ip for ip in sig.split(">") if ip and ip != "-" and ip != target and ip not in seen]


def culprit(hops: List[dict], loss_limit: float) -> Tuple[Optional[int], Optional[str]]:
    """(hop number, "loss" | "latency") where a problem starts and lasts to the end, or (None, None)."""
    measured = [h for h in hops if h.get("ip") and h.get("loss") is not None]
    if not measured:
        return None, None
    # loss: the earliest hop from which every later measured hop (the target included) loses at least the limit
    for i, h in enumerate(measured):
        if all((x["loss"] or 0) >= loss_limit for x in measured[i:]):
            return h["n"], "loss"
    # latency: a jump over the previous answering hop that every later hop keeps
    prev = None
    for i, h in enumerate(measured):
        if h.get("rtt") is None:
            continue
        if prev is not None and h["rtt"] - prev >= LAT_JUMP_MS:
            floor = h["rtt"] - LAT_JUMP_MS / 2
            if all(x.get("rtt") is not None and x["rtt"] >= floor for x in measured[i:]):
                return h["n"], "latency"
        prev = h["rtt"]
    return None, None


# ── Tracing ──────────────────────────────────────────────────────────────────

async def trace_one(ip: str) -> dict:
    from services import traceroute, net_quality
    t = await traceroute.trace(ip, max_hops=MAX_HOPS, timeout=90.0)
    if t.get("error"):
        return {"error": t["error"], "hops": [], "reached": False}
    hops = [{"n": h["n"], "ip": h["ip"]} for h in t["hops"]]
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(PARALLEL)

    async def measure(h):
        if not h["ip"]:
            return
        async with sem:
            m = await loop.run_in_executor(None, net_quality._ping_burst_sync, h["ip"], HOP_PINGS)
        if not m.get("error"):
            h.update(rtt=m["rtt"], jitter=m["jitter"], loss=m["loss"])
    await asyncio.gather(*[measure(h) for h in hops])
    return {"error": None, "hops": hops, "reached": bool(t.get("reached"))}


def _targets() -> List[dict]:
    from services import net_quality
    s = net_quality.load_settings()
    return [{"ip": t["ip"], "name": t.get("name") or t["ip"]} for t in s["targets"]][:MAX_TARGETS]


def _judge(t: dict, rec: dict, now: datetime) -> List[str]:
    from services import soc
    out = []
    checks = (
        ("metric.path_degraded", rec["culprit"] is not None, "medium", "Path degraded",
         f"{t['name']} ({t['ip']}): {rec['culprit_kind']} starts at hop {rec['culprit']} ({rec.get('culprit_ip') or '?'}) and lasts to the target"),
        ("metric.path_changed", rec["changed"], "low", "Path changed",
         f"{t['name']} ({t['ip']}): routers not seen in the last day answer on the path: {', '.join(rec.get('new_routers') or [])} ({rec['hop_count']} hops)"),
    )
    for rule, bad, sev, title, msg in checks:
        k = (t["ip"], rule)
        if bad:
            _streak[k] = _streak.get(k, 0) + 1
            if _streak[k] >= STREAK:
                soc.raise_alert(rule=rule, device=t["name"], ip=t["ip"], title=title, severity=sev, category="resource", fp_detail=t["ip"],
                                detail={"message": msg, "description": f"{t['name']} · path"}, count=0 if _streak[k] > STREAK else 1, source="rules", now=now)
                out.append(rule)
        else:
            _streak.pop(k, None)
            soc.resolve(rule=rule, device=t["name"], fp_detail=t["ip"], now=now)
    return out


async def run_cycle(now: Optional[datetime] = None) -> dict:
    if not load_settings()["enabled"]:
        _last.update(at=_iso(_now()), targets=0, error=None)
        return {"enabled": False}
    from services import net_quality
    started = _now()
    now = now or started
    limit = net_quality.load_settings()["limits"]["loss_pct"]
    targets = _targets()
    done = 0
    for t in targets:                                    # one at a time: a trace is slow and noisy enough on its own
        r = await trace_one(t["ip"])
        if r["error"]:
            print(f"[net_path] {t['ip']}: {r['error']}")
            continue
        try:
            record(t, r["hops"], r["reached"], now, limit)
            done += 1
        except Exception as e:
            print(f"[net_path] {t['ip']}: {type(e).__name__}: {e}")
    with SessionLocal() as db:
        db.execute(delete(NetPathTrace).where(NetPathTrace.at < now - timedelta(days=KEEP_DAYS)))
        db.commit()
    _last.update(at=_iso(_now()), targets=done, duration_sec=round((_now() - started).total_seconds(), 1), error=None)
    return {"targets": done}


def record(t: dict, hops: List[dict], reached: bool, now: datetime, loss_limit: float) -> dict:
    sig = signature(hops)
    with SessionLocal() as db:
        known = db.execute(select(NetPathTrace.signature).where(NetPathTrace.target_ip == t["ip"], NetPathTrace.at >= now - timedelta(days=1),
                                                                NetPathTrace.at <= now - timedelta(minutes=BASELINE_GAP_MIN))).scalars().all()
        fresh = new_routers(sig, list(known), t["ip"])
        changed = bool(known and fresh)
        n, kind = culprit(hops, loss_limit)
        db.add(NetPathTrace(target_ip=t["ip"], target_name=t["name"], at=now, hops=json.dumps(hops), signature=sig[:2000], reached=reached,
                            changed=changed, culprit=n, culprit_kind=kind))
        db.commit()
    rec = {"changed": changed, "culprit": n, "culprit_kind": kind, "culprit_ip": next((h["ip"] for h in hops if h["n"] == n), None), "hop_count": len(hops),
           "new_routers": fresh[:6]}
    _judge(t, rec, now)
    return rec


# ── Reading ──────────────────────────────────────────────────────────────────

def _row(r: NetPathTrace) -> dict:
    return {"at": _iso(r.at), "hops": json.loads(r.hops or "[]"), "reached": r.reached, "changed": r.changed, "culprit": r.culprit, "culprit_kind": r.culprit_kind}


def overview(now: Optional[datetime] = None) -> dict:
    """Per target: the last trace with its hops, and the path changes / culprits of the last 24 hours."""
    now = now or _now()
    items = []
    with SessionLocal() as db:
        for t in _targets():
            rows = db.execute(select(NetPathTrace).where(NetPathTrace.target_ip == t["ip"], NetPathTrace.at >= now - timedelta(days=1))
                              .order_by(NetPathTrace.at.desc())).scalars().all()
            last = rows[0] if rows else db.execute(select(NetPathTrace).where(NetPathTrace.target_ip == t["ip"]).order_by(NetPathTrace.at.desc()).limit(1)).scalars().first()
            events = [{"at": _iso(r.at), "changed": r.changed, "culprit": r.culprit, "culprit_kind": r.culprit_kind, "hop_count": len(json.loads(r.hops or "[]"))}
                      for r in rows if r.changed or r.culprit is not None][:30]
            items.append({"ip": t["ip"], "name": t["name"], "last": _row(last) if last else None, "traces_24h": len(rows),
                          "changes_24h": sum(1 for r in rows if r.changed), "degraded_24h": sum(1 for r in rows if r.culprit is not None), "events": events})
    return {"enabled": load_settings()["enabled"], "items": items, "last": dict(_last), "interval_sec": INTERVAL_SEC}


def history(target_ip: str, limit: int = 50) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(NetPathTrace).where(NetPathTrace.target_ip == target_ip).order_by(NetPathTrace.at.desc()).limit(max(1, min(limit, 500)))).scalars().all()
    return [_row(r) for r in rows]


def public_summary() -> dict:
    """For Central: per own target the hop count, whether it is reached, where a problem starts (hop number and kind) and the changes of
    the last day - no addresses."""
    o = overview()
    return {"targets": [{"n": x["name"], "hops": len(x["last"]["hops"]) if x["last"] else None, "reached": x["last"]["reached"] if x["last"] else None,
                         "culprit": x["last"]["culprit"] if x["last"] else None, "kind": x["last"]["culprit_kind"] if x["last"] else None,
                         "changes24": x["changes_24h"], "degraded24": x["degraded_24h"], "at": x["last"]["at"] if x["last"] else None} for x in o["items"]],
            "at": o["last"].get("at")}


async def _loop():
    await asyncio.sleep(240)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[net_path] cycle error: {e}")
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
