"""
Quality of the connection: latency, jitter and packet loss, measured (the "network monitoring" part a ping up / down does not answer).

services/availability.py says whether a device answers. A link can answer and still be bad - 12% of the packets lost, 300 ms to the internet,
a Wi-Fi bridge whose delay jumps between 2 and 80 ms - and that is what people feel as "the network is slow". Here, every 5 minutes, each
target gets a short burst of pings (10 by default) and three numbers are taken from it:

  rtt     the average round-trip time of the answers, in ms;
  jitter  the average difference between two consecutive answers' times, in ms (how much the delay jumps - what calls and video feel);
  loss    the share of the pings with no answer, in %.

Targets: the network equipment availability already watches (routers, switches, access points - automatically, up to MAX_AUTO), and the
targets of your own in data/net_quality.json (by default one on the internet, 1.1.1.1, for the quality of the link out). The readings go
into the metric history (services/metrics.py, kinds rtt / jitter / loss): charts, thresholds of your own and - for rtt - the anomaly
detector's learned normal range come with it.

Alerts (through the SOC layer), each after two bad measurements in a row so one bad burst is not an alert, closed after a good one:
  metric.net_loss     loss at or above the limit (medium; high from 20%). A device of the network that does not answer at all (100%) is
                      left to the availability alert - it is the same fault; a target of your own at 100% is alerted here.
  metric.net_latency  the average rtt at or above the limit (medium);
  metric.net_jitter   jitter at or above the limit (low).
No new connection to any device beyond ICMP echo, no credentials. A device under a maintenance window is muted by the SOC layer as usual.
"""
import asyncio
import ipaddress
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Asset, AvailState, MetricSeries

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "net_quality.json")
INTERVAL_SEC = 300
MAX_AUTO = 40
MAX_OWN = 20
PARALLEL = 6
STREAK = 2                       # bad measurements in a row before an alert

DEFAULTS = {
    "enabled": True,
    "auto": True,                # the network equipment availability watches
    "count": 10,                 # pings per measurement
    "targets": [{"name": "Internet (1.1.1.1)", "ip": "1.1.1.1"}],
    "limits": {"loss_pct": 5.0, "rtt_ms": 100.0, "rtt_ms_own": 150.0, "jitter_ms": 30.0},
}

_task: Optional[asyncio.Task] = None
_last: Dict[str, object] = {"at": None, "targets": 0, "duration_sec": None, "error": None}
_results: Dict[str, dict] = {}          # ip -> the last measurement
_streak: Dict[Tuple[str, str], int] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── Settings ─────────────────────────────────────────────────────────────────

def _clean_ip(v) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(v or "").strip()))
    except ValueError:
        return None


def load_settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_PATH, encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            for k in ("enabled", "auto"):
                if isinstance(saved.get(k), bool):
                    s[k] = saved[k]
            if isinstance(saved.get("count"), int):
                s["count"] = max(3, min(20, saved["count"]))
            if isinstance(saved.get("targets"), list):
                s["targets"] = [t for t in saved["targets"] if isinstance(t, dict) and _clean_ip(t.get("ip"))][:MAX_OWN]
            for k, v in (saved.get("limits") or {}).items():
                if k in s["limits"] and isinstance(v, (int, float)) and v > 0:
                    s["limits"][k] = float(v)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[net_quality] settings unreadable, defaults used: {type(e).__name__}: {e}")
    return s


def save_settings(body: dict) -> dict:
    """Validates and saves; raises ValueError with what is wrong."""
    s = load_settings()
    if "enabled" in body:
        s["enabled"] = bool(body["enabled"])
    if "auto" in body:
        s["auto"] = bool(body["auto"])
    if "count" in body:
        c = int(body["count"])
        if not 3 <= c <= 20:
            raise ValueError("count: 3 to 20 pings")
        s["count"] = c
    if "targets" in body:
        out, seen = [], set()
        for t in body["targets"] or []:
            ip = _clean_ip((t or {}).get("ip"))
            if not ip:
                raise ValueError(f"not an IP address: {(t or {}).get('ip')!r}")
            if ip in seen:
                continue
            seen.add(ip)
            out.append({"name": (str(t.get("name") or "").strip() or ip)[:60], "ip": ip})
        if len(out) > MAX_OWN:
            raise ValueError(f"at most {MAX_OWN} targets")
        s["targets"] = out
    for k, v in (body.get("limits") or {}).items():
        if k not in s["limits"]:
            continue
        v = float(v)
        if v <= 0 or (k == "loss_pct" and v > 100):
            raise ValueError(f"{k}: a positive number" + (" up to 100" if k == "loss_pct" else ""))
        s["limits"][k] = v
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)
    return s


# ── Measuring ────────────────────────────────────────────────────────────────

# a reply line has a TTL (Windows: "Reply from 1.1.1.1: bytes=32 time=12ms TTL=57", in Polish "czas=12ms", "czas<1ms";
# Linux: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"). "Destination host unreachable" lines have none - they are losses.
_TIME = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.I)
_TTL = re.compile(r"\bttl[=:]\s*\d+", re.I)


def parse_ping(output: str) -> List[float]:
    """The round-trip times of the answers in a ping output, in order (ms). "<1ms" counts as 0.5."""
    out = []
    for line in (output or "").splitlines():
        if not _TTL.search(line):
            continue
        m = _TIME.search(line)
        if not m:
            continue
        v = float(m.group(1).replace(",", "."))
        before = line[:m.start() + 1]
        out.append(0.5 if before.endswith("<") and v <= 1 else v)
    return out


def summarize(times: List[float], sent: int) -> dict:
    sent = max(1, sent)
    got = min(len(times), sent)
    loss = round(100.0 * (sent - got) / sent, 1)
    if not times:
        return {"rtt": None, "jitter": None, "loss": loss, "min": None, "max": None, "sent": sent, "received": 0}
    jit = sum(abs(b - a) for a, b in zip(times, times[1:])) / (len(times) - 1) if len(times) > 1 else 0.0
    return {"rtt": round(sum(times) / len(times), 2), "jitter": round(jit, 2), "loss": loss, "min": round(min(times), 2), "max": round(max(times), 2),
            "sent": sent, "received": got}


def _ping_burst_sync(ip: str, count: int) -> dict:
    ip = _clean_ip(ip)
    if not ip:
        return {"error": "not an IP address"}
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", str(count), "-w", "1000", ip]
    else:
        cmd = ["ping", "-n", "-c", str(count), "-i", "0.5", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 1.5 + 10, errors="replace")
    except Exception as e:
        return {"error": f"ping could not run: {type(e).__name__}: {e}"}
    return summarize(parse_ping(r.stdout), count)


def _targets(s: dict) -> List[dict]:
    """The targets of this cycle: the own ones first, then the network equipment availability watches (not the ones that are down -
    availability has those)."""
    out, seen = [], set()
    for t in s["targets"]:
        ip = _clean_ip(t.get("ip"))
        if ip and ip not in seen:
            seen.add(ip)
            out.append({"ip": ip, "name": t.get("name") or ip, "asset_id": None, "own": True})
    if s["auto"]:
        from services import availability
        parents = availability._parents()
        with SessionLocal() as db:
            down = {st.asset_id for st in db.execute(select(AvailState)).scalars().all() if st.state in ("down", "unreachable")}
            assets = db.execute(select(Asset).where(Asset.asset_type == "network", Asset.ip.is_not(None))).scalars().all()
            auto = [a for a in assets if not a.state and availability.is_watched(a, parents) and a.id not in down]
        auto.sort(key=lambda a: (a.id not in parents, (a.name or a.ip or "").lower()))
        for a in auto:
            ip = _clean_ip(a.ip)
            if ip and ip not in seen and len(out) < len(s["targets"]) + MAX_AUTO:
                seen.add(ip)
                out.append({"ip": ip, "name": a.name or ip, "asset_id": a.id, "own": False})
    return out


def _key(ip: str, what: str) -> str:
    return f"nq:{ip}:{what}"


def _record(t: dict, m: dict, now: datetime) -> None:
    from services import metrics
    with SessionLocal() as db:
        for what, kind, unit, label in (("rtt", "rtt", "ms", "RTT"), ("jitter", "jitter", "ms", "jitter"), ("loss", "loss", "%", "loss")):
            metrics.record(_key(t["ip"], what), m.get(what), name=f"{t['name']} · {label}", kind=kind, asset_id=t["asset_id"], unit=unit, now=now, db=db)
        db.commit()


def _judge(t: dict, m: dict, limits: dict, now: datetime) -> List[str]:
    """Raises / closes the three alerts of one target. Returns the rules alerting."""
    from services import soc
    out = []
    rtt_lim = limits["rtt_ms_own"] if t["own"] else limits["rtt_ms"]
    loss = m.get("loss")
    checks = (
        ("metric.net_loss", loss is not None and loss >= limits["loss_pct"] and (t["own"] or loss < 100),
         "high" if (loss or 0) >= 20 else "medium", "Packet loss",
         f"{t['name']} ({t['ip']}): {loss}% of {m.get('sent')} pings lost (limit {limits['loss_pct']:g}%)"),
        ("metric.net_latency", m.get("rtt") is not None and m["rtt"] >= rtt_lim, "medium", "High latency",
         f"{t['name']} ({t['ip']}): average {m.get('rtt')} ms, max {m.get('max')} ms (limit {rtt_lim:g} ms)"),
        ("metric.net_jitter", m.get("jitter") is not None and m["jitter"] >= limits["jitter_ms"], "low", "High jitter",
         f"{t['name']} ({t['ip']}): jitter {m.get('jitter')} ms (limit {limits['jitter_ms']:g} ms)"),
    )
    for rule, bad, sev, title, msg in checks:
        k = (t["ip"], rule)
        if bad:
            _streak[k] = _streak.get(k, 0) + 1
            if _streak[k] >= STREAK:
                soc.raise_alert(rule=rule, device=t["name"], ip=t["ip"], title=title, severity=sev, category="resource", fp_detail=t["ip"],
                                detail={"message": msg, "description": f"{t['name']} · {title.lower()}"}, asset_id=t["asset_id"], count=0 if _streak[k] > STREAK else 1,
                                source="rules", now=now)
                out.append(rule)
        else:
            _streak.pop(k, None)
            soc.resolve(rule=rule, device=t["name"], fp_detail=t["ip"], now=now)
    return out


async def run_cycle(now: Optional[datetime] = None) -> dict:
    s = load_settings()
    if not s["enabled"]:
        _last.update(at=_iso(_now()), targets=0, error=None)
        return {"enabled": False}
    started = _now()
    now = now or started
    targets = _targets(s)
    sem = asyncio.Semaphore(PARALLEL)
    loop = asyncio.get_event_loop()

    async def one(t):
        async with sem:
            return t, await loop.run_in_executor(None, _ping_burst_sync, t["ip"], s["count"])

    alerting = 0
    for t, m in await asyncio.gather(*[one(t) for t in targets]):
        m = {**m, "at": _iso(now), "name": t["name"], "asset_id": t["asset_id"], "own": t["own"]}
        _results[t["ip"]] = m
        if m.get("error"):
            continue
        try:
            _record(t, m, now)
            alerting += len(_judge(t, m, s["limits"], now))
        except Exception as e:
            print(f"[net_quality] {t['ip']}: {type(e).__name__}: {e}")
    for ip in [ip for ip in _results if ip not in {t["ip"] for t in targets}]:
        _results.pop(ip, None)
    _last.update(at=_iso(_now()), targets=len(targets), duration_sec=round((_now() - started).total_seconds(), 1), error=None)
    return {"targets": len(targets), "alerting": alerting}


# ── Reading ──────────────────────────────────────────────────────────────────

def _p95(vals: List[float]) -> Optional[float]:
    if not vals:
        return None
    v = sorted(vals)
    return round(v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))], 2)


def overview(now: Optional[datetime] = None) -> dict:
    """Every target: the last measurement and the last 24 hours (average, 95th percentile of rtt, average loss, worst jitter)."""
    from services import metrics
    now = now or _now()
    s = load_settings()
    with SessionLocal() as db:
        series = {x.key: x for x in db.execute(select(MetricSeries).where(MetricSeries.key.like("nq:%"))).scalars().all()}
    # after a restart, until the first cycle: the targets measured in the last day, from the history ("nq:<ip>:<what>", an IPv6 has colons)
    ips = list(_results.keys()) or sorted({k[3:].rsplit(":", 1)[0] for k in series if now - (series[k].last_at or now) < timedelta(days=1)})
    items = []
    for ip in ips:
        r = _results.get(ip, {})
        day = {w: [v for _t, v in metrics.points(_key(ip, w), 1, 2000, now)] for w in ("rtt", "jitter", "loss")}
        ser = series.get(_key(ip, "loss")) or series.get(_key(ip, "rtt"))
        name = r.get("name") or (ser.name.split(" · ")[0] if ser else ip)
        rtt_lim = s["limits"]["rtt_ms_own"] if r.get("own") else s["limits"]["rtt_ms"]
        last = {w: (r.get(w) if r else (series[_key(ip, w)].last_value if _key(ip, w) in series else None)) for w in ("rtt", "jitter", "loss")}
        bad = []
        if last["loss"] is not None and last["loss"] >= s["limits"]["loss_pct"]:
            bad.append("loss")
        if last["rtt"] is not None and last["rtt"] >= rtt_lim:
            bad.append("latency")
        if last["jitter"] is not None and last["jitter"] >= s["limits"]["jitter_ms"]:
            bad.append("jitter")
        items.append({"ip": ip, "name": name, "asset_id": r.get("asset_id") if r else (ser.asset_id if ser else None),
                      "own": bool(r.get("own")) if r else bool(ser is not None and ser.asset_id is None), "at": r.get("at"), "error": r.get("error"),
                      "rtt": last["rtt"], "jitter": last["jitter"], "loss": last["loss"], "min": r.get("min"), "max": r.get("max"),
                      "rtt_avg_24h": round(sum(day["rtt"]) / len(day["rtt"]), 2) if day["rtt"] else None, "rtt_p95_24h": _p95(day["rtt"]),
                      "loss_avg_24h": round(sum(day["loss"]) / len(day["loss"]), 2) if day["loss"] else None,
                      "jitter_max_24h": round(max(day["jitter"]), 2) if day["jitter"] else None,
                      "keys": {w: _key(ip, w) for w in ("rtt", "jitter", "loss")}, "bad": bad})
    items.sort(key=lambda x: (not x["bad"], not x["own"], -(x["loss"] or 0), -(x["rtt"] or 0), x["name"].lower()))
    return {"settings": s, "items": items, "last": dict(_last)}


def public_summary() -> dict:
    """For Central (inside the availability summary): counts and the targets out of their limits - names and numbers, no addresses."""
    o = overview()
    return {"targets": len(o["items"]), "bad": [{"n": x["name"], "rtt": x["rtt"], "j": x["jitter"], "loss": x["loss"], "what": x["bad"], "own": x["own"]}
                                                 for x in o["items"] if x["bad"]][:20],
            "own": [{"n": x["name"], "rtt": x["rtt"], "j": x["jitter"], "loss": x["loss"], "p95": x["rtt_p95_24h"], "loss24": x["loss_avg_24h"]}
                    for x in o["items"] if x["own"]][:MAX_OWN],
            "at": o["last"].get("at")}


async def _loop():
    await asyncio.sleep(90)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[net_quality] cycle error: {e}")
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
