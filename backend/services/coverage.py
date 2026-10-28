"""
Coverage: which of the agent's sources of information are reporting, and which went quiet.

A SOC is only as good as its inputs, and the worst failure of an input is silence: a Wazuh connector whose password expired, a router whose configuration has not been read for
a week, the syslog port that nobody listens on, a UPS that stopped answering - each looks exactly like "nothing is wrong". This module lists every source the agent has
(connectors, router and host readings, the SOC's own monitors, scans) with when it last worked, how often it should, and its state:

  ok      worked within its expected interval (with a margin of 2.5 times)
  stale   did not - and a stale source raises a SOC alert of its own ("Source silent: ...") that closes when the source comes back
  error   its last attempt failed with an error that is shown
  off     not configured or switched off: not a problem, shown as such

Sources that are not instrumented in their own module are read from the data they leave (a timestamp in the database); the connectors (Wazuh, Checkmk, PRTG) report each poll
with `beat()`. Nothing is raised during the first minutes after the agent starts (the monitors have not had time to run), and a source that has never worked is judged
from the time the agent started.
"""
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, func

from models.database import SessionLocal, Device, WindowsHost, LinuxHost, DellServer, HypervHost, UpsTarget, HostLogCursor, ConfigCheck

MARGIN = 2.5
GRACE_SEC = 15 * 60
INTERVAL_SEC = 300

_started = time.time()
_beats: Dict[str, dict] = {}
_task: Optional[asyncio.Task] = None


def beat(source: str, ok: bool = True, error: Optional[str] = None) -> None:
    """A connector reports one poll: it worked, or it failed with this error."""
    b = _beats.setdefault(source, {"ok_at": None, "fail_at": None, "error": None})
    now = datetime.utcnow()
    if ok:
        b["ok_at"], b["error"], b["last_ok"] = now, None, True
    else:
        b["fail_at"], b["error"], b["last_ok"] = now, (error or "failed")[:200], False


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _parse(v) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v
    if isinstance(v, (int, float)) and v > 0:
        return datetime.utcfromtimestamp(v)
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "").split("+")[0])
        except ValueError:
            return None
    return None


def _item(id_: str, group: str, name: str, *, last_ok: Optional[datetime], expected_s: Optional[int], now: datetime, error: Optional[str] = None, detail: Optional[str] = None,
          off: bool = False, stale_items: Optional[List[str]] = None, total: Optional[int] = None) -> dict:
    """One line of the report with its state judged."""
    overdue = False
    if expected_s is not None:
        basis = last_ok or datetime.utcfromtimestamp(_started)
        overdue = (now - basis).total_seconds() > expected_s * MARGIN
    if off:
        state = "off"
    elif stale_items or overdue:
        state = "stale"                  # silent for too long - whatever the last error was; the error is shown next to it
    elif error:
        state = "error"                  # failing now, but it worked within its interval
    else:
        state = "ok"
    return {"id": id_, "group": group, "name": name, "state": state, "last_ok": _iso(last_ok), "expected_s": expected_s, "error": error, "detail": detail,
            "stale_items": (stale_items or [])[:20], "total": total}


def _stale(rows, ts_of, expected_s: int, now: datetime, name_of) -> List[str]:
    out = []
    for r in rows:
        t = ts_of(r)
        if t is None:
            t = datetime.utcfromtimestamp(_started)
        if (now - t).total_seconds() > expected_s * MARGIN:
            out.append(name_of(r))
    return out


def report(now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    items: List[dict] = []
    add = items.append

    # ── connectors and the link to Central
    try:
        from services import uplink
        u = uplink.status()
        add(_item("uplink", "link", "Central (uplink)", last_ok=_parse(u.get("last_sent")), expected_s=int(u.get("interval_sec") or 120), now=now, off=not u.get("enabled"),
                  error=u.get("last_error") if u.get("failing_since") else None, detail=f"waiting: {u.get('buffered_count', 0)} events" if u.get("buffered_count") else None))
    except Exception as e:
        add(_item("uplink", "link", "Central (uplink)", last_ok=None, expected_s=None, now=now, error=f"{type(e).__name__}: {e}"))
    for sid, label, mod, client in (("wazuh", "Wazuh", "wazuh_monitor", "wazuh_client"), ("checkmk", "Checkmk", "checkmk_monitor", "checkmk_client"), ("prtg", "PRTG", "prtg_monitor", "prtg_client")):
        try:
            import importlib
            configured = importlib.import_module(f"services.{client}").is_configured()
            poll = int(getattr(importlib.import_module(f"services.{mod}"), "POLL_MIN", 5))
        except Exception:
            configured, poll = False, 5
        b = _beats.get(sid) or {}
        add(_item(sid, "connectors", label, last_ok=b.get("ok_at"), expected_s=poll * 60, now=now, off=not configured, error=b.get("error") if b.get("last_ok") is False else None))

    # ── readings of devices and hosts
    try:
        from services import refresher
        r = refresher.status()
        add(_item("device_ping", "devices", "Router liveness", last_ok=_parse(r.get("last_ping")), expected_s=int(r.get("ping_interval_min") or 5) * 60, now=now))
        add(_item("device_refresh", "devices", "Router details (model, version, interfaces)", last_ok=_parse(r.get("last_run")), expected_s=int(refresher.INTERVAL_MIN) * 60, now=now))
    except Exception:
        pass
    with SessionLocal() as db:
        devs = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        wins = db.execute(select(WindowsHost).where(WindowsHost.managed.is_(True))).scalars().all()
        lins = db.execute(select(LinuxHost).where(LinuxHost.managed.is_(True))).scalars().all()
        dells = db.execute(select(DellServer)).scalars().all()
        hvs = db.execute(select(HypervHost)).scalars().all()
        ups = db.execute(select(UpsTarget).where(UpsTarget.enabled.is_(True))).scalars().all()
        cursors = db.execute(select(HostLogCursor)).scalars().all()
        checks = {c.device_id: c for c in db.execute(select(ConfigCheck)).scalars().all()}
        host_names = {("windows", h.id): (h.hostname or h.ip) for h in wins}
        host_names.update({("linux", h.id): (h.hostname or h.ip) for h in lins})
        last_res = max((d.last_resources_check_at for d in devs if d.last_resources_check_at), default=None)
        st = _stale(devs, lambda d: d.last_resources_check_at, 3 * 3600, now, lambda d: d.name or d.ip)
        add(_item("device_resources", "devices", "Router resources (CPU, memory, disk)", last_ok=last_res, expected_s=3 * 3600, now=now, off=not devs, stale_items=st, total=len(devs)))
        for label, rows, key in (("Windows hosts: resources", wins, "win"), ("Linux hosts: resources", lins, "lin")):
            st = _stale(rows, lambda h: h.last_resources_check_at, 6 * 3600, now, lambda h: h.hostname or h.ip)
            add(_item(f"{key}_resources", "devices", label, last_ok=max((h.last_resources_check_at for h in rows if h.last_resources_check_at), default=None), expected_s=6 * 3600, now=now,
                      off=not rows, stale_items=st, total=len(rows)))
        st = [(d.name or d.ip) for d in dells if d.last_status == "error" or _stale([d], lambda x: x.last_check_at, 6 * 3600, now, lambda x: x.name)]
        add(_item("dell", "devices", "Server BMC (iDRAC / iLO)", last_ok=max((d.last_check_at for d in dells if d.last_check_at and d.last_status == "ok"), default=None), expected_s=6 * 3600, now=now,
                  off=not dells, stale_items=st, total=len(dells)))
        st = _stale(hvs, lambda h: h.last_check_at, 6 * 3600, now, lambda h: f"Hyper-V #{h.id}")
        add(_item("hyperv", "devices", "Hyper-V hosts", last_ok=max((h.last_check_at for h in hvs if h.last_check_at), default=None), expected_s=6 * 3600, now=now, off=not hvs, stale_items=st, total=len(hvs)))

        # ── the SOC's own monitors
        from services import availability, metrics, syslog_receiver, host_logs, config_history, topology_map, vuln_scan, exploit_intel
        add(_item("availability", "soc", "Availability monitor", last_ok=_parse(availability._last.get("at")), expected_s=availability.INTERVAL_SEC, now=now, error=availability._last.get("error")))
        add(_item("metrics", "soc", "Metrics sampler", last_ok=_parse(metrics._last.get("at")), expected_s=metrics.INTERVAL_SEC, now=now, error=metrics._last.get("error")))
        sl = syslog_receiver.settings()
        listening = bool(syslog_receiver._transports)
        add(_item("syslog", "soc", "Syslog / SNMP trap receiver", last_ok=_parse(syslog_receiver._stats.get("last_at")), expected_s=None, now=now, off=not sl.get("enabled"),
                  error="; ".join(v for v in syslog_receiver._errors.values() if v) or (None if listening or not sl.get("enabled") else "not listening"),
                  detail=None if not sl.get("enabled") else f"{syslog_receiver._stats.get('received', 0)} received since start"))
        hl = host_logs.settings()
        hl_rows = [c for c in cursors if (c.kind, c.host_id) in host_names]
        st = [host_names[(c.kind, c.host_id)] for c in hl_rows if c.last_error and not c.last_ok_at] + _stale(hl_rows, lambda c: c.last_ok_at, int(hl.get("interval_min") or 10) * 60, now, lambda c: host_names[(c.kind, c.host_id)])
        add(_item("host_logs", "soc", "Windows / Linux security logs", last_ok=max((c.last_ok_at for c in hl_rows if c.last_ok_at), default=None), expected_s=int(hl.get("interval_min") or 10) * 60, now=now,
                  off=not hl.get("enabled") or not (wins or lins), stale_items=sorted(set(st)), total=len(wins) + len(lins)))
        st = _stale(ups, lambda u: u.last_ok, 600, now, lambda u: u.name)
        add(_item("ups", "soc", "UPS units", last_ok=max((u.last_ok for u in ups if u.last_ok), default=None), expected_s=600, now=now, off=not ups, stale_items=st, total=len(ups)))
        cfg_rows = [d for d in devs if (d.vendor or "mikrotik") in config_history.SUPPORTED]
        interval_s = int(float(config_history.settings().get("interval_hours") or 6) * 3600)
        st = _stale(cfg_rows, lambda d: (checks.get(d.id).last_check_at if checks.get(d.id) else None), interval_s, now, lambda d: d.name or d.ip)
        add(_item("config_history", "soc", "Router configuration history", last_ok=max((c.last_check_at for c in checks.values() if c.last_check_at and not c.last_error), default=None), expected_s=interval_s, now=now,
                  off=not config_history.settings().get("enabled") or not cfg_rows, stale_items=st, total=len(cfg_rows)))
        from services import tls_scan
        add(_item("tls", "soc", "TLS certificates", last_ok=_parse(tls_scan._last.get("at")), expected_s=tls_scan.INTERVAL_SEC, now=now, off=not tls_scan.settings().get("enabled"),
                  error=tls_scan._last.get("error")))
        mm = topology_map.map_state()
        add(_item("topology", "soc", "Network map", last_ok=_parse(mm.get("at")), expected_s=int(getattr(topology_map, "TTL", 900)), now=now))
        vs = vuln_scan.status()
        add(_item("vuln_scan", "soc", "Vulnerability scan", last_ok=_parse(vs.get("last_run")), expected_s=8 * 86400, now=now))
        ei = exploit_intel.status()
        add(_item("exploit_intel", "soc", "CISA KEV and EPSS", last_ok=_parse(ei.get("kev_at")), expected_s=2 * 86400, now=now, error=ei.get("error")))
    summary = {s: sum(1 for i in items if i["state"] == s) for s in ("ok", "stale", "error", "off")}
    return {"items": items, "summary": summary, "uptime_s": int(time.time() - _started), "at": _iso(now)}


# ── Alerts for silent sources ────────────────────────────────────────────────

def check_alerts(now: Optional[datetime] = None) -> List[str]:
    """Raises an alert for every source that is stale and closes it when the source works again. Returns the ids that are alerting."""
    from services import soc
    if time.time() - _started < GRACE_SEC:
        return []
    alerting = []
    for it in report(now)["items"]:
        rule = f"coverage.{it['id']}"
        if it["state"] == "stale":
            who = ", ".join(it["stale_items"][:5]) if it["stale_items"] else None
            soc.raise_alert(rule=rule, device=it["name"], title="Source silent", severity="medium", category="system", fp_detail="",
                            detail={"message": f"{it['name']}: no reading within {int((it['expected_s'] or 0) * MARGIN / 60)} min" + (f" ({who})" if who else ""),
                                    "description": it["name"]}, source="rules", now=now)
            alerting.append(it["id"])
        else:
            soc.resolve(rule=rule, device=it["name"])
    return alerting


async def _loop():
    await asyncio.sleep(GRACE_SEC + 30)
    while True:
        try:
            check_alerts()
        except Exception as e:
            print(f"[coverage] cycle error: {type(e).__name__}: {e}")
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
