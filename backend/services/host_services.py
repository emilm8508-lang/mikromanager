"""
Monitoring of services on specific hosts — Windows services (WinRM) and Linux
systemd units (SSH) of the hosts already managed by windows_manage.py /
linux_manage.py (same credentials, same per-host managed=True opt-in).

What this adds on top of the earlier "type a service name" watch list:
  - read the service list from the host and pick from it (discover()),
  - Linux as well as Windows,
  - per-service monitoring parameters: expected state (running / stopped),
    check interval, how many consecutive failed checks before it counts,
    alerting on/off, and pausing,
  - its own scheduler (a service can need minutes, the old pass ran every
    ~30 min), one batched call per host per due-check,
  - state-change history, and alert events (host_service_down/_up) that flow
    through the normal alert_events -> Central/Telegram pipeline.

Everything here is READ-ONLY on the target (Get-Service / WMI / `systemctl
show`) — it never starts, stops or restarts a service.

A check that fails as a whole (host unreachable, WinRM/SSH error) does NOT
touch any service's state or failure streak: that is a host problem (and the
host monitoring covers it), not evidence about the service.
"""
import asyncio
import json
import os
import re
import shlex
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import delete, select

from models.database import (
    SessionLocal, WindowsHost, WindowsHostService, LinuxHost, LinuxHostService, HostServiceEvent,
)
from services import vuln_scan as vs

TICK_SEC = 30
CHECK_TIMEOUT_SEC = 45
RETENTION_DAYS = 90
_ERROR_BACKOFF_SEC = 60

_PLATFORMS = {
    "windows": {"svc": WindowsHostService, "host": WindowsHost},
    "linux": {"svc": LinuxHostService, "host": LinuxHost},
}
_VALID_EXPECTED = ("running", "stopped")
_LINUX_UNIT_RE = re.compile(r"^[A-Za-z0-9@:_.\\-]{1,200}$")
_ALERT_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "hostservices_alert_state.json")

_task: Optional[asyncio.Task] = None
_lock = asyncio.Lock()
_errors: Dict[tuple, dict] = {}        # (platform, host_id) -> {"at": datetime, "msg": str}
_state = {"last_prune": 0.0}


# ── Normalization / state machine (pure, unit-tested) ───────────────────────

def normalize_windows(raw: Optional[str]) -> Optional[str]:
    key = (raw or "").replace(" ", "").lower()
    if not key:
        return None
    return {"running": "running", "stopped": "stopped"}.get(key, "other")


def normalize_linux(active_state: Optional[str], load_state: Optional[str] = None) -> Optional[str]:
    if (load_state or "").lower() == "not-found":
        return "not_found"
    return {"active": "running", "inactive": "stopped", "failed": "failed", None: None, "": None}.get(
        (active_state or "").lower() or None, "other")


def is_compliant(expected: str, state: Optional[str]) -> Optional[bool]:
    """Does the observed state satisfy what the operator expects? None = unknown."""
    if state is None:
        return None
    if expected == "stopped":
        return state in ("stopped", "failed", "not_found")
    return state == "running"


def apply_result(row, state: Optional[str], raw: Optional[str], now: datetime) -> Optional[dict]:
    """Updates `row` (any object with the service columns) from one check result
    and returns the transition event {"kind": "down"|"up", ...} when this
    check crossed the debounce threshold, else None. Pure apart from mutating row.
    A None state means the check had no answer for this service: only the check
    time moves, the previous state and failure streak stay as they were."""
    if state is None:
        row.last_checked_at = now
        return None
    if state != row.state:
        row.status_since = now
    row.state, row.status, row.last_checked_at = state, raw, now
    ok = is_compliant(row.expected_state, state)
    if ok is None:
        return None
    if ok:
        row.fail_streak = 0
        if row.alerted:
            dur = int((now - row.alerted_at).total_seconds()) if row.alerted_at else None
            event = {"kind": "up", "duration_sec": dur, "alert": bool(row.alert_sent)}
            row.alerted, row.alert_sent, row.alerted_at = False, False, None
            return event
        return None
    row.fail_streak = (row.fail_streak or 0) + 1
    if not row.alerted and row.fail_streak >= max(1, row.alert_after_fails or 1):
        row.alerted, row.alerted_at = True, now
        row.alert_sent = bool(row.alert_enabled)
        return {"kind": "down", "duration_sec": None, "alert": bool(row.alert_enabled)}
    return None


# ── Windows (WinRM) ─────────────────────────────────────────────────────────

def _winrm_session(ip: str, port: int, username: str, password: str, domain: Optional[str]):
    import winrm
    scheme = "https" if port == 5986 else "http"
    return winrm.Session(
        f"{scheme}://{ip}:{port}/wsman", auth=(vs._ntlm_user(username, domain), password),
        transport="ntlm", server_cert_validation="ignore",
        read_timeout_sec=CHECK_TIMEOUT_SEC + 5, operation_timeout_sec=CHECK_TIMEOUT_SEC,
    )


def _run_ps_json(ip, port, username, password, domain, script: str) -> dict:
    session = _winrm_session(ip, port, username, password, domain)
    try:
        result = vs._run_ps_safe(session, script)
        if result.status_code != 0:
            return {"ok": False, "error": result.std_err.decode("utf-8", errors="ignore")[-500:] or "PowerShell error"}
        raw = result.std_out.decode("utf-8", errors="ignore").strip()
        if not raw:
            return {"ok": True, "items": []}
        parsed = json.loads(raw)
        return {"ok": True, "items": [parsed] if isinstance(parsed, dict) else parsed}   # ConvertTo-Json yields a bare object for one item
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        vs._close_winrm(session)


def _windows_check_sync(ip, port, username, password, domain, names: List[str]) -> dict:
    # Status is cast to string explicitly: ConvertTo-Json would otherwise emit
    # the ServiceControllerStatus enum as a bare number on Windows PowerShell 5.1.
    names_ps = ",".join("'" + n.replace("'", "''") + "'" for n in names)
    script = (f"Get-Service -Name {names_ps} -ErrorAction SilentlyContinue | "
              "Select-Object Name,DisplayName,@{n='Status';e={[string]$_.Status}} | ConvertTo-Json -Compress")
    res = _run_ps_json(ip, port, username, password, domain, script)
    if not res["ok"]:
        return res
    found = {}
    for s in res["items"]:
        if isinstance(s, dict) and s.get("Name"):
            found[s["Name"].lower()] = {"display": s.get("DisplayName"), "raw": s.get("Status")}
    out = {}
    for n in names:
        m = found.get(n.lower())
        out[n] = ({"state": normalize_windows(m["raw"]), "raw": m["raw"], "display": m["display"]} if m
                  else {"state": "not_found", "raw": "not_found", "display": None})
    return {"ok": True, "services": out}


def _windows_discover_sync(ip, port, username, password, domain) -> dict:
    # WMI (not Get-Service): works on every Windows PowerShell version and gives
    # the autostart mode (StartMode) without needing PS 5's StartType.
    res = _run_ps_json(ip, port, username, password, domain,
                       "Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode | ConvertTo-Json -Compress")
    if not res["ok"]:
        return res
    return {"ok": True, "services": [
        {"name": s["Name"], "display_name": s.get("DisplayName"), "raw": s.get("State"),
         "state": normalize_windows(s.get("State")), "startup": s.get("StartMode")}
        for s in res["items"] if isinstance(s, dict) and s.get("Name")
    ]}


# ── Linux (SSH + systemd) ───────────────────────────────────────────────────

def _linux_exec(ip, username, password, cmd: str) -> str:
    from services import linux_manage
    return linux_manage._plain_exec_sync(ip, username, password, cmd, CHECK_TIMEOUT_SEC)["output"]


def parse_systemctl_show(output: str) -> Dict[str, dict]:
    """`systemctl show --property=Id,LoadState,ActiveState,SubState,Description`
    prints one KEY=VALUE block per unit, blank-line separated."""
    units = {}
    for block in re.split(r"\n\s*\n", output.strip()):
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if props.get("Id"):
            units[props["Id"].lower()] = props
    return units


def _linux_check_sync(ip, username, password, names: List[str]) -> dict:
    cmd = ("systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Description "
           + " ".join(shlex.quote(n) for n in names))
    try:
        units = parse_systemctl_show(_linux_exec(ip, username, password, cmd))
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if not units:
        return {"ok": False, "error": "no systemd answer (is this host running systemd?)"}
    out = {}
    for n in names:
        u = units.get(n.lower())
        if not u:
            out[n] = {"state": None, "raw": None, "display": None}      # not in the answer at all: don't guess
            continue
        state = normalize_linux(u.get("ActiveState"), u.get("LoadState"))
        raw = "not-found" if state == "not_found" else f"{u.get('ActiveState')} ({u.get('SubState')})"
        out[n] = {"state": state, "raw": raw, "display": u.get("Description") if state != "not_found" else None}
    return {"ok": True, "services": out}


def parse_linux_discovery(output: str) -> List[dict]:
    """Output of `list-units ...; echo ::UNITFILES::; list-unit-files ...`."""
    units_part, _, files_part = output.partition("::UNITFILES::")
    startup = {}
    for line in files_part.strip().splitlines():
        cols = line.split()
        if len(cols) >= 2:
            startup[cols[0].lower()] = cols[1]
    result = []
    for line in units_part.strip().splitlines():
        cols = line.split(None, 4)
        if len(cols) < 4 or not cols[0].endswith(".service"):
            continue
        unit, load, active, sub = cols[0], cols[1], cols[2], cols[3]
        if load == "not-found":
            continue
        result.append({"name": unit, "display_name": cols[4].strip() if len(cols) > 4 else None,
                       "raw": f"{active} ({sub})", "state": normalize_linux(active, load),
                       "startup": startup.get(unit.lower())})
    return result


def _linux_discover_sync(ip, username, password) -> dict:
    cmd = ("systemctl list-units --type=service --all --no-legend --no-pager --plain; echo ::UNITFILES::; "
           "systemctl list-unit-files --type=service --no-legend --no-pager")
    try:
        services = parse_linux_discovery(_linux_exec(ip, username, password, cmd))
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if not services:
        return {"ok": False, "error": "no systemd answer (is this host running systemd?)"}
    return {"ok": True, "services": services}


# ── Host / credential access ────────────────────────────────────────────────

def _host_ctx(platform: str, host_id: int) -> Optional[dict]:
    """Everything a check needs, or None when the host isn't there / isn't managed."""
    from services import windows_manage, linux_manage
    with SessionLocal() as db:
        host = db.get(_PLATFORMS[platform]["host"], host_id)
        if not host or not host.managed:
            return None
        if platform == "windows":
            cred = windows_manage._credential_for_host(host)
            return {"ip": host.ip, "port": host.winrm_port or 5985, "cred": cred,
                    "name": host.hostname or host.ip}
        cred = linux_manage._shared_credential()
        return {"ip": host.ip, "port": 22, "cred": cred, "name": host.hostname or host.ip}


async def _run_in_executor(fn, *args, timeout=CHECK_TIMEOUT_SEC + 20) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(loop.run_in_executor(vs._EXECUTOR, fn, *args), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _remote_check(platform: str, ctx: dict, names: List[str]) -> dict:
    if platform == "windows":
        user, pw, domain = ctx["cred"]
        return await _run_in_executor(_windows_check_sync, ctx["ip"], ctx["port"], user, pw, domain, names)
    user, pw = ctx["cred"]
    return await _run_in_executor(_linux_check_sync, ctx["ip"], user, pw, names)


# ── Checking ────────────────────────────────────────────────────────────────

def _record_event(db, platform: str, host_id: int, host_name: str, row, ev: dict, now: datetime) -> None:
    db.add(HostServiceEvent(
        platform=platform, host_id=host_id, service_id=row.id, host_name=host_name,
        service_name=row.service_name, display_name=row.display_name, ts=now, kind=ev["kind"],
        state=row.state, expected=row.expected_state, duration_sec=ev["duration_sec"], alert=ev["alert"]))


def _is_due(row, now: datetime) -> bool:
    if not row.enabled:
        return False
    return row.last_checked_at is None or (now - row.last_checked_at) >= timedelta(minutes=max(1, row.interval_min or 5))


async def check_host(platform: str, host_id: int, force: bool = False) -> dict:
    """Checks the due services of one host (all enabled ones when `force`) in a
    single batched call and applies the results. Never raises."""
    Svc = _PLATFORMS[platform]["svc"]
    now = datetime.now()
    ctx = _host_ctx(platform, host_id)
    if ctx is None:
        return {"error": "host not found or not managed"}
    with SessionLocal() as db:
        rows = db.execute(select(Svc).where(Svc.host_id == host_id)).scalars().all()
        names = [r.service_name for r in rows if (force and r.enabled) or _is_due(r, now)]
    if not names:
        return {"ok": True, "checked": 0}
    if not ctx["cred"]:
        msg = "no credential configured (assign one to this host, or set the shared credential)"
        _errors[(platform, host_id)] = {"at": now, "msg": msg}
        return {"error": msg}

    result = await _remote_check(platform, ctx, names)
    now = datetime.now()
    if not result.get("ok"):
        _errors[(platform, host_id)] = {"at": now, "msg": result.get("error", "error")}
        return {"error": result.get("error", "error")}
    _errors.pop((platform, host_id), None)

    with SessionLocal() as db:
        rows = db.execute(select(Svc).where(Svc.host_id == host_id, Svc.service_name.in_(names))).scalars().all()
        for row in rows:
            r = result["services"].get(row.service_name)
            if r is None:
                continue
            if r.get("display") and not row.display_name:
                row.display_name = r["display"]
            ev = apply_result(row, r["state"], r["raw"], now)
            if ev:
                _record_event(db, platform, host_id, ctx["name"], row, ev, now)
        db.commit()
    return {"ok": True, "checked": len(names)}


async def run_due() -> None:
    async with _lock:
        now = datetime.now()
        work = []
        for platform, p in _PLATFORMS.items():
            with SessionLocal() as db:
                rows = db.execute(select(p["svc"])).scalars().all()
            hosts = {r.host_id for r in rows if _is_due(r, now)}
            for hid in hosts:
                err = _errors.get((platform, hid))
                if err and (now - err["at"]).total_seconds() < _ERROR_BACKOFF_SEC:
                    continue                      # host failed recently: don't hammer it every tick
                work.append((platform, hid))
        sem = asyncio.Semaphore(4)

        async def _one(platform, hid):
            async with sem:
                try:
                    await check_host(platform, hid)
                except Exception as e:
                    print(f"[host_services] check error {platform}#{hid}: {e}")
        await asyncio.gather(*[_one(pl, h) for pl, h in work])
        if datetime.now().timestamp() - _state["last_prune"] > 3600:
            _state["last_prune"] = datetime.now().timestamp()
            with SessionLocal() as db:
                db.execute(delete(HostServiceEvent).where(HostServiceEvent.ts < now - timedelta(days=RETENTION_DAYS)))
                db.commit()


async def _loop():
    await asyncio.sleep(25)
    while True:
        try:
            await run_due()
        except Exception as e:
            print(f"[host_services] loop error: {e}")
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


# ── Discovery ───────────────────────────────────────────────────────────────

async def discover(platform: str, host_id: int) -> dict:
    """Live, read-only: every service the host knows, flagged when already monitored."""
    ctx = _host_ctx(platform, host_id)
    if ctx is None:
        return {"error": "host not found or not managed"}
    if not ctx["cred"]:
        return {"error": "no credential configured (assign one to this host, or set the shared credential)"}
    if platform == "windows":
        user, pw, domain = ctx["cred"]
        res = await _run_in_executor(_windows_discover_sync, ctx["ip"], ctx["port"], user, pw, domain, timeout=CHECK_TIMEOUT_SEC + 30)
    else:
        user, pw = ctx["cred"]
        res = await _run_in_executor(_linux_discover_sync, ctx["ip"], user, pw, timeout=CHECK_TIMEOUT_SEC + 30)
    if not res.get("ok"):
        return {"error": res.get("error", "error")}
    Svc = _PLATFORMS[platform]["svc"]
    with SessionLocal() as db:
        mine = {s.service_name.lower() for s in db.execute(select(Svc).where(Svc.host_id == host_id)).scalars().all()}
    services = sorted(res["services"], key=lambda s: (s["display_name"] or s["name"]).lower())
    for s in services:
        s["monitored"] = s["name"].lower() in mine
    return {"ok": True, "services": services}


# ── CRUD ────────────────────────────────────────────────────────────────────

def _to_dict(platform: str, s) -> dict:
    ok = is_compliant(s.expected_state, s.state)
    iso = lambda d: d.isoformat() if d else None
    return {
        "id": s.id, "platform": platform, "host_id": s.host_id, "service_name": s.service_name,
        "display_name": s.display_name, "status": s.status, "state": s.state, "startup": s.startup,
        "expected_state": s.expected_state, "interval_min": s.interval_min,
        "alert_after_fails": s.alert_after_fails, "alert_enabled": s.alert_enabled, "enabled": s.enabled,
        "fail_streak": s.fail_streak, "incident_open": s.alerted, "ok": ok,
        "status_since": iso(s.status_since), "last_checked_at": iso(s.last_checked_at),
    }


def list_services(platform: str, host_id: int) -> dict:
    Svc = _PLATFORMS[platform]["svc"]
    with SessionLocal() as db:
        rows = db.execute(select(Svc).where(Svc.host_id == host_id).order_by(Svc.service_name)).scalars().all()
        err = _errors.get((platform, host_id))
        return {"services": [_to_dict(platform, r) for r in rows],
                "check_error": err["msg"] if err else None,
                "check_error_at": err["at"].isoformat() if err else None}


def _clean_name(platform: str, name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("service name required")
    if platform == "linux":
        if not _LINUX_UNIT_RE.match(name):
            raise ValueError("invalid unit name")
        if "." not in name:
            name += ".service"
    return name


def _validated_params(p: dict) -> dict:
    """Only the given keys, each validated; raises ValueError."""
    out = {}
    if "expected_state" in p:
        if p["expected_state"] not in _VALID_EXPECTED:
            raise ValueError("expected_state must be running or stopped")
        out["expected_state"] = p["expected_state"]
    for key, lo, hi in (("interval_min", 1, 1440), ("alert_after_fails", 1, 20)):
        if key in p:
            try:
                v = int(p[key])
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a number")
            if not lo <= v <= hi:
                raise ValueError(f"{key} must be between {lo} and {hi}")
            out[key] = v
    for key in ("alert_enabled", "enabled"):
        if key in p:
            out[key] = bool(p[key])
    return out


def add_services(platform: str, host_id: int, items: List[dict]) -> dict:
    """items: [{"name", "display_name"?, "startup"?, + optional parameters}] —
    unspecified parameters take the column defaults. Already-watched names are skipped."""
    Svc, Host = _PLATFORMS[platform]["svc"], _PLATFORMS[platform]["host"]
    added, skipped = [], []
    with SessionLocal() as db:
        if not db.get(Host, host_id):
            raise LookupError("host not found")
        existing = {s.service_name.lower() for s in db.execute(select(Svc).where(Svc.host_id == host_id)).scalars().all()}
        for it in items:
            name = _clean_name(platform, it.get("name"))
            if name.lower() in existing:
                skipped.append(name)
                continue
            existing.add(name.lower())
            row = Svc(host_id=host_id, service_name=name, display_name=it.get("display_name") or None,
                      startup=it.get("startup") or None, **_validated_params(it))
            db.add(row)
            db.flush()
            added.append(_to_dict(platform, row))
        db.commit()
    return {"added": added, "skipped": skipped}


def update_service(platform: str, service_id: int, params: dict) -> dict:
    Svc = _PLATFORMS[platform]["svc"]
    clean = _validated_params(params)
    with SessionLocal() as db:
        row = db.get(Svc, service_id)
        if not row:
            raise LookupError("service not found")
        if "expected_state" in clean and clean["expected_state"] != row.expected_state:
            row.fail_streak, row.alerted, row.alert_sent, row.alerted_at = 0, False, False, None   # old expectation's incident is moot
        for k, v in clean.items():
            setattr(row, k, v)
        if clean.get("enabled") is False:
            row.fail_streak = 0                  # paused: no half-counted failures resuming later
        db.commit()
        return _to_dict(platform, row)


def remove_service(platform: str, service_id: int) -> dict:
    Svc = _PLATFORMS[platform]["svc"]
    with SessionLocal() as db:
        row = db.get(Svc, service_id)
        if not row:
            raise LookupError("service not found")
        db.delete(row)
        db.commit()
    return {"ok": True}


def list_events(platform: str, host_id: int, limit: int = 50) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(
            select(HostServiceEvent).where(HostServiceEvent.platform == platform, HostServiceEvent.host_id == host_id)
            .order_by(HostServiceEvent.id.desc()).limit(max(1, min(limit, 200)))
        ).scalars().all()
        return [{"id": e.id, "ts": e.ts.isoformat(), "kind": e.kind, "service_name": e.service_name,
                 "display_name": e.display_name, "state": e.state, "expected": e.expected,
                 "duration_sec": e.duration_sec} for e in rows]


# ── Alerts ──────────────────────────────────────────────────────────────────

async def collect_alert_events() -> List[dict]:
    """One host_service_down / host_service_up alert event per recorded
    transition flagged for alerting, reported exactly once (watermark on the
    event id). The first call only sets the watermark, so enabling this does
    not replay history as new alerts."""
    try:
        with open(_ALERT_STATE_PATH) as f:
            last = int(json.load(f).get("last_event_id", 0))
        first_run = False
    except (OSError, ValueError, TypeError):
        last, first_run = 0, True

    with SessionLocal() as db:
        rows = db.execute(select(HostServiceEvent).where(HostServiceEvent.id > last)
                          .order_by(HostServiceEvent.id)).scalars().all()
    if rows:
        last = rows[-1].id
    if first_run or rows:
        os.makedirs(os.path.dirname(_ALERT_STATE_PATH), exist_ok=True)
        try:
            with open(_ALERT_STATE_PATH, "w") as f:
                json.dump({"last_event_id": last}, f)
        except OSError as e:
            print(f"[host_services] alert state persist error: {e}")
    if first_run:
        return []
    return [{
        "type": "host_service_down" if e.kind == "down" else "host_service_up",
        "device_name": e.host_name, "service": e.display_name or e.service_name, "service_name": e.service_name,
        "state": e.state, "expected": e.expected, "platform": e.platform, "duration_sec": e.duration_sec,
        "count": 1, "detected_at": datetime.utcnow().isoformat(),
    } for e in rows if e.alert]
