"""
Application checks: "does the application answer, and how fast" - not only "does the server answer a ping".

A server can be up, its port open and the application behind it still broken: the web page answers 500, the login page no longer shows
the login form, the DNS server answers with nothing, the mail server does not greet. Here the operator defines checks of their own:

  http   a URL (http:// or https://): the status code (expected 200-399 unless set), the response time, optionally a phrase the page must
         contain; for https also the days until the certificate expires (read from the connection, by the name in the URL - SNI).
         Redirects are followed (at most 5). The certificate is verified unless "insecure" is set (an internal page with its own
         certificate) - then only its expiry is read.
  tcp    host:port connects; optionally the greeting must contain a phrase ("220" of a mail server, "SSH-", a database's banner).
  dns    a name resolves (by the system resolver, or by a DNS server given), optionally to an expected address.

Each check runs every `interval_min` minutes (1-60). Readings go into the metric history (services/metrics.py):
  app:<id>:resp   the response time in ms (kind resp: charts, thresholds of your own, the anomaly detector's learned range),
  app:<id>:up     100 when it worked, 0 when not (kind app_up: the availability of 24 h / 7 d).
Alerts (through the SOC layer), each after two bad results in a row, closed after a good one:
  app.down   the check failed (high);
  app.slow   the response time at or above the check's limit (medium);
  app.cert   an https certificate expiring within 14 days (medium; high within 3 days), or already expired (high).
Nothing of the response is kept but the status code, the time and an error text (cut); the page itself never leaves the agent.
"""
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import select

from models.database import SessionLocal, Asset

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "app_checks.json")
TICK_SEC = 30
MAX_CHECKS = 100
PARALLEL = 5
STREAK = 2
CERT_WARN_DAYS = 14
CERT_CRIT_DAYS = 3
KINDS = ("http", "tcp", "dns")
_ERR_MAX = 200

_task: Optional[asyncio.Task] = None
_last: Dict[str, object] = {"at": None, "ran": 0, "error": None}
_results: Dict[str, dict] = {}
_due: Dict[str, float] = {}
_streak: Dict[Tuple[str, str], int] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── The checks ───────────────────────────────────────────────────────────────

def _status_ok(spec: str, code: int) -> bool:
    """"200-399" (default), "200", "200,301,302", "200-299,401"."""
    for part in (spec or "200-399").split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if int(a) <= code <= int(b):
                return True
        elif part and int(part) == code:
            return True
    return False


def clean(c: dict) -> dict:
    """One check, validated. Raises ValueError with what is wrong."""
    kind = str(c.get("kind") or "").strip().lower()
    if kind not in KINDS:
        raise ValueError(f"kind: one of {', '.join(KINDS)}")
    target = str(c.get("target") or "").strip()
    if not target or len(target) > 500 or any(ch in target for ch in "\r\n\t "):
        raise ValueError("target: a URL, host:port or a name, without spaces")
    if kind == "http":
        u = urlparse(target)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("http: the target is a URL starting with http:// or https://")
    elif kind == "tcp":
        host, _, port = target.rpartition(":")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError("tcp: the target is host:port")
    elif kind == "dns":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", target):
            raise ValueError("dns: the target is a host name")
    status = str(c.get("expect_status") or "").strip()
    if status:
        try:
            _status_ok(status, 200)
        except ValueError:
            raise ValueError("expect_status: like 200-399 or 200,301")
    server = str(c.get("dns_server") or "").strip() or None
    expect_ip = str(c.get("expect_ip") or "").strip() or None
    for label, v in (("dns_server", server), ("expect_ip", expect_ip)):
        if v:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"{label}: an IP address")
    interval = int(c["interval_min"]) if c.get("interval_min") not in (None, "") else 2
    timeout = float(c["timeout_s"]) if c.get("timeout_s") not in (None, "") else 10.0
    limit = c.get("slow_ms")
    if not 1 <= interval <= 60:
        raise ValueError("interval_min: 1 to 60")
    if not 1 <= timeout <= 30:
        raise ValueError("timeout_s: 1 to 30")
    if limit not in (None, "") and float(limit) <= 0:
        raise ValueError("slow_ms: a positive number")
    cid = str(c.get("id") or "").strip()
    if not re.fullmatch(r"[a-f0-9]{8}", cid):
        cid = uuid.uuid4().hex[:8]
    name = (str(c.get("name") or "").strip() or target)[:80]
    return {"id": cid, "name": name, "kind": kind, "target": target, "enabled": bool(c.get("enabled", True)), "interval_min": interval,
            "timeout_s": timeout, "slow_ms": float(limit) if limit not in (None, "") else None,
            "expect_status": status or None, "contains": (str(c.get("contains") or "")[:200] or None),
            "insecure": bool(c.get("insecure", False)), "dns_server": server, "expect_ip": expect_ip}


def load() -> List[dict]:
    try:
        with open(_PATH, encoding="utf-8") as f:
            raw = json.load(f)
        out = []
        for c in (raw.get("checks") if isinstance(raw, dict) else raw) or []:
            try:
                out.append(clean(c))
            except (ValueError, TypeError) as e:
                print(f"[app_checks] a saved check skipped: {e}")
        return out[:MAX_CHECKS]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[app_checks] settings unreadable: {type(e).__name__}: {e}")
        return []


def save(checks: List[dict]) -> List[dict]:
    if len(checks) > MAX_CHECKS:
        raise ValueError(f"at most {MAX_CHECKS} checks")
    out, seen = [], set()
    for c in checks:
        c = clean(c)
        while c["id"] in seen:
            c["id"] = uuid.uuid4().hex[:8]
        seen.add(c["id"])
        out.append(c)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    with open(_PATH, "w", encoding="utf-8") as f:
        json.dump({"checks": out}, f, indent=1)
    for k in [k for k in _results if k not in seen]:
        _results.pop(k, None)
    _due.clear()                                         # changed checks run at the next tick
    return out


# ── Running one ──────────────────────────────────────────────────────────────

def _cut(s) -> str:
    s = str(s or "")
    return s if len(s) <= _ERR_MAX else s[:_ERR_MAX] + "..."


async def _http(c: dict) -> dict:
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=c["timeout_s"])
    ssl_arg = False if c["insecure"] else None           # None: aiohttp's default verification
    t0 = time.perf_counter()
    async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": "MikroManager-check/1"}) as s:
        async with s.get(c["target"], ssl=ssl_arg, allow_redirects=True, max_redirects=5) as r:
            body = b""
            if c["contains"]:
                body = await r.content.read(512 * 1024)
            else:
                await r.content.read(64 * 1024)
            ms = round((time.perf_counter() - t0) * 1000, 1)
            code = r.status
    ok = _status_ok(c["expect_status"] or "200-399", code)
    err = None if ok else f"HTTP {code} (expected {c['expect_status'] or '200-399'})"
    if ok and c["contains"] and c["contains"].encode("utf-8") not in body:
        ok, err = False, f"the page does not contain {c['contains']!r}"
    out = {"ok": ok, "ms": ms, "code": code, "error": err}
    u = urlparse(c["target"])
    if u.scheme == "https":
        na = await _cert_not_after(c["id"], u.hostname, u.port or 443, c["timeout_s"])
        if na:
            out["cert_not_after"] = na
    return out


_cert_cache: Dict[str, Tuple[float, datetime]] = {}
CERT_EVERY_SEC = 6 * 3600


def _cert_sync(host: str, port: int, timeout: float) -> Optional[datetime]:
    """The expiry of the certificate the server presents for this name (SNI) - one handshake, nothing verified, nothing sent."""
    from services import tls_scan
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
    return tls_scan.parse_cert(der)["not_after"] if der else None


async def _cert_not_after(cid: str, host: Optional[str], port: int, timeout: float) -> Optional[datetime]:
    """Read once in CERT_EVERY_SEC per check (a certificate does not change by the minute)."""
    hit = _cert_cache.get(cid)
    if hit and time.monotonic() - hit[0] < CERT_EVERY_SEC:
        return hit[1]
    try:
        na = await asyncio.get_event_loop().run_in_executor(None, _cert_sync, host, port, timeout)
    except Exception:
        return hit[1] if hit else None
    if na:
        _cert_cache[cid] = (time.monotonic(), na)
    return na


async def _tcp(c: dict) -> dict:
    host, _, port = c["target"].rpartition(":")
    host = host.strip("[]")
    t0 = time.perf_counter()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=c["timeout_s"])
    ms = round((time.perf_counter() - t0) * 1000, 1)
    try:
        if c["contains"]:
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=min(5.0, c["timeout_s"]))
            except asyncio.TimeoutError:
                banner = b""
            if c["contains"].encode("utf-8") not in banner:
                return {"ok": False, "ms": ms, "error": f"connected, the greeting does not contain {c['contains']!r}"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return {"ok": True, "ms": ms, "error": None}


def dns_query(name: str, server: str, timeout: float) -> List[str]:
    """One A query over UDP to the given server; the addresses of the answer. Raises on no answer / an error code."""
    qid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.strip(".").split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + struct.pack(">HH", 1, 1)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
    return parse_dns_answer(data, qid)


def parse_dns_answer(data: bytes, qid: int) -> List[str]:
    if len(data) < 12:
        raise ValueError("a short DNS answer")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise ValueError("a DNS answer to another query")
    rcode = flags & 0x0F
    if rcode:
        raise ValueError({3: "NXDOMAIN: the name does not exist", 2: "SERVFAIL"}.get(rcode, f"DNS error code {rcode}"))
    i = 12

    def skip_name(i):
        while True:
            if i >= len(data):
                raise ValueError("a broken DNS answer")
            ln = data[i]
            if ln == 0:
                return i + 1
            if ln & 0xC0 == 0xC0:
                return i + 2
            i += ln + 1
    for _ in range(qd):
        i = skip_name(i) + 4
    out = []
    for _ in range(an):
        i = skip_name(i)
        if i + 10 > len(data):
            raise ValueError("a broken DNS answer")
        typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        i += rdlen
        if typ == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rd))
    return out


async def _dns(c: dict) -> dict:
    loop = asyncio.get_event_loop()
    t0 = time.perf_counter()
    if c["dns_server"]:
        addrs = await loop.run_in_executor(None, dns_query, c["target"], c["dns_server"], c["timeout_s"])
    else:
        infos = await asyncio.wait_for(loop.getaddrinfo(c["target"], None, proto=socket.IPPROTO_TCP), timeout=c["timeout_s"])
        addrs = sorted({i[4][0] for i in infos})
    ms = round((time.perf_counter() - t0) * 1000, 1)
    if not addrs:
        return {"ok": False, "ms": ms, "error": "no address in the answer"}
    if c["expect_ip"] and c["expect_ip"] not in addrs:
        return {"ok": False, "ms": ms, "error": f"resolves to {', '.join(addrs[:4])}, not {c['expect_ip']}", "addrs": addrs[:8]}
    return {"ok": True, "ms": ms, "error": None, "addrs": addrs[:8]}


async def run_one(c: dict) -> dict:
    try:
        r = await asyncio.wait_for({"http": _http, "tcp": _tcp, "dns": _dns}[c["kind"]](c), timeout=c["timeout_s"] + 5)
    except asyncio.TimeoutError:
        r = {"ok": False, "ms": None, "error": f"no answer within {c['timeout_s']:g} s"}
    except Exception as e:
        r = {"ok": False, "ms": None, "error": _cut(f"{type(e).__name__}: {e}")}
    r["error"] = _cut(r.get("error")) if r.get("error") else None
    return r


# ── Recording and alerts ─────────────────────────────────────────────────────

def _asset_of(c: dict) -> Optional[int]:
    host = urlparse(c["target"]).hostname if c["kind"] == "http" else c["target"].rpartition(":")[0].strip("[]") if c["kind"] == "tcp" else None
    try:
        ip = str(ipaddress.ip_address(host or ""))
    except ValueError:
        return None
    with SessionLocal() as db:
        a = db.execute(select(Asset).where(Asset.ip == ip)).scalars().first()
        return a.id if a else None


def _record(c: dict, r: dict, now: datetime, asset_id: Optional[int]) -> None:
    from services import metrics
    with SessionLocal() as db:
        metrics.record(f"app:{c['id']}:resp", r.get("ms") if r["ok"] else None, name=f"{c['name']} · response", kind="resp", asset_id=asset_id, unit="ms", now=now, db=db)
        metrics.record(f"app:{c['id']}:up", 100.0 if r["ok"] else 0.0, name=f"{c['name']} · works", kind="app_up", asset_id=asset_id, unit="%", now=now, db=db)
        db.commit()


def _judge(c: dict, r: dict, now: datetime, asset_id: Optional[int]) -> List[str]:
    from services import soc
    out = []
    days = None
    if r.get("cert_not_after"):
        days = (r["cert_not_after"] - now).total_seconds() / 86400
    checks = (
        ("app.down", not r["ok"], "high", "Application check failed", f"{c['name']} ({c['target']}): {r.get('error') or 'failed'}", True),
        ("app.slow", bool(r["ok"] and c["slow_ms"] and r.get("ms") is not None and r["ms"] >= c["slow_ms"]), "medium", "Application slow",
         f"{c['name']} ({c['target']}): {r.get('ms')} ms (limit {c['slow_ms'] or 0:g} ms)", True),
        ("app.cert", days is not None and days <= CERT_WARN_DAYS, "high" if days is not None and days <= CERT_CRIT_DAYS else "medium", "Certificate expiring",
         f"{c['name']} ({c['target']}): the certificate " + (f"expired {abs(days):.0f} days ago" if days is not None and days < 0 else f"expires in {days or 0:.0f} days"),
         False),                                         # a certificate is a fact, not a flap: no streak needed
    )
    for rule, bad, sev, title, msg, needs_streak in checks:
        k = (c["id"], rule)
        if rule == "app.cert" and days is None and not r["ok"]:
            continue                                     # not read this time (the page did not answer): leave it as it was
        if bad:
            _streak[k] = _streak.get(k, 0) + 1
            if not needs_streak or _streak[k] >= STREAK:
                soc.raise_alert(rule=rule, device=c["name"], title=title, severity=sev, category="availability" if rule == "app.down" else "resource",
                                fp_detail=c["id"], detail={"message": msg, "description": f"{c['kind']} {c['target']}"}, asset_id=asset_id,
                                count=0 if _streak[k] > STREAK else 1, source="rules", now=now)
                out.append(rule)
        else:
            _streak.pop(k, None)
            soc.resolve(rule=rule, device=c["name"], fp_detail=c["id"], now=now)
    return out


async def run_due(now: Optional[datetime] = None, force: bool = False) -> dict:
    checks = [c for c in load() if c["enabled"]]
    mono = time.monotonic()
    due = [c for c in checks if force or _due.get(c["id"], 0) <= mono]
    sem = asyncio.Semaphore(PARALLEL)

    async def one(c):
        async with sem:
            return c, await run_one(c)
    alerting = 0
    for c, r in await asyncio.gather(*[one(c) for c in due]):
        _due[c["id"]] = mono + c["interval_min"] * 60 - 5
        at = now or _now()
        prev = _results.get(c["id"], {})
        _results[c["id"]] = {**r, "at": _iso(at), "since": prev.get("since") if prev.get("ok") == r["ok"] else _iso(at)}
        try:
            aid = _asset_of(c)
            _record(c, r, at, aid)
            alerting += len(_judge(c, r, at, aid))
        except Exception as e:
            print(f"[app_checks] {c['id']}: {type(e).__name__}: {e}")
    _last.update(at=_iso(_now()), ran=len(due), error=None)
    return {"ran": len(due), "alerting": alerting}


# ── Reading ──────────────────────────────────────────────────────────────────

def _avg(vals: List[float]) -> Optional[float]:
    return round(sum(vals) / len(vals), 2) if vals else None


def overview(now: Optional[datetime] = None) -> dict:
    from services import metrics
    now = now or _now()
    items = []
    for c in load():
        r = _results.get(c["id"], {})
        up24 = [v for _t, v in metrics.points(f"app:{c['id']}:up", 1, 5000, now)]
        up7 = [v for _t, v in metrics.points(f"app:{c['id']}:up", 7, 20000, now)]
        rt = sorted(v for _t, v in metrics.points(f"app:{c['id']}:resp", 1, 5000, now))
        cert = r.get("cert_not_after")
        items.append({**c, "ok": r.get("ok"), "ms": r.get("ms"), "code": r.get("code"), "error": r.get("error"), "at": r.get("at"), "since": r.get("since"),
                      "addrs": r.get("addrs"), "cert_days": round((cert - now).total_seconds() / 86400, 1) if cert else None,
                      "up_24h": _avg(up24), "up_7d": _avg(up7), "p95_24h": rt[min(len(rt) - 1, int(round(0.95 * (len(rt) - 1))))] if rt else None,
                      "keys": {"resp": f"app:{c['id']}:resp", "up": f"app:{c['id']}:up"}})
    items.sort(key=lambda x: (x["ok"] is not False, x["name"].lower()))
    return {"items": items, "last": dict(_last), "max": MAX_CHECKS}


def public_summary() -> dict:
    """For Central: counts and the checks that fail - names, kind and the error, no URLs or addresses."""
    o = overview()
    it = o["items"]
    return {"total": len(it), "ok": sum(1 for x in it if x["ok"]), "failing": sum(1 for x in it if x["ok"] is False),
            "bad": [{"n": x["name"], "k": x["kind"], "since": x["since"], "up24": x["up_24h"], "code": x["code"]} for x in it if x["ok"] is False][:30],
            "slow": [{"n": x["name"], "ms": x["ms"]} for x in it if x["ok"] and x["slow_ms"] and (x["ms"] or 0) >= x["slow_ms"]][:20],
            "cert": [{"n": x["name"], "days": x["cert_days"]} for x in it if x["cert_days"] is not None and x["cert_days"] <= CERT_WARN_DAYS][:20],
            "at": o["last"].get("at")}


async def _loop():
    await asyncio.sleep(60)
    while True:
        try:
            await run_due()
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[app_checks] cycle error: {e}")
        await asyncio.sleep(TICK_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None
