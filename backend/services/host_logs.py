"""
Security events of the managed Windows and Linux hosts: the Windows Security log and the Linux authentication log, read over the connections the agent already has.

Wazuh does this with an agent on every host; where there is none, the managed hosts (WinRM / SSH, with the credential the agent already uses for patches and resource
checks) can be asked directly. Every few minutes the events since the last read are fetched - read-only - and turned into SOC alerts of the host:

  Windows (Security log; System log for 7045):  4625 failed logon, 4624 successful RDP logon (after failures), 4740 account locked out, 4720 user created,
                                                4728 / 4732 / 4756 member added to a group (privileged groups only), 1102 the audit log was cleared,
                                                4698 scheduled task created, 7045 a service was installed
  Linux (journald, else /var/log/auth.log or /var/log/secure): failed ssh logins, successful ssh logins (root; after failures), a user created, a user added to
                                                sudo / wheel / admin, repeated sudo failures

Only what is needed to raise the alert is kept (counts, sources, users, names), never the log itself; the first read goes back 15 minutes only, so nothing old is
raised as new. Reading the Windows Security log needs the account to be an administrator or in "Event Log Readers"; a host where it fails shows the error on the page.
"""
import asyncio
import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from sqlalchemy import select

from models.database import SessionLocal, WindowsHost, LinuxHost, HostLogCursor

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "host_logs.json")
DEFAULTS = {"enabled": True, "interval_min": 10}
FIRST_LOOKBACK_MIN = 15
FAIL_THRESHOLD = 10            # failed logons of one host in one read that make an alert
AFTER_FAILURES = 5             # failures from one address, then a success from it
PRIVILEGED = ("administrators", "domain admins", "enterprise admins", "schema admins", "account operators", "backup operators", "server operators", "administratorzy",
              "admins domeny", "administratorzy domeny", "administratorzy przedsiębiorstwa", "administratorzy schematu", "operatorzy kont", "operatorzy kopii zapasowych",
              "operatorzy serwera")
LINUX_ADMIN_GROUPS = ("sudo", "wheel", "admin", "root")

_settings: Dict = dict(DEFAULTS)
_task: Optional[asyncio.Task] = None
_recent_fail: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)       # (host, source) -> times of the failed logons seen lately
_running = {"on": False}


# ── Settings ─────────────────────────────────────────────────────────────────

def load_settings() -> Dict:
    s = dict(DEFAULTS)
    try:
        with open(_PATH, encoding="utf-8") as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except Exception:
        pass
    _settings.clear()
    _settings.update(s)
    return _settings


def settings() -> Dict:
    return dict(_settings)


def update_settings(body: Dict) -> Dict:
    new = dict(_settings)
    if body.get("enabled") is not None:
        new["enabled"] = bool(body["enabled"])
    if body.get("interval_min") is not None:
        m = int(body["interval_min"])
        if not (2 <= m <= 1440):
            raise ValueError("the interval is between 2 minutes and a day")
        new["interval_min"] = m
    _settings.clear()
    _settings.update(new)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f)
    os.replace(tmp, _PATH)
    return settings()


# ── Windows ──────────────────────────────────────────────────────────────────

def windows_script(since: datetime) -> str:
    """PowerShell that returns {"events": [{id, t, d: {field: value}}], "errors": [...]} for the events since `since` (UTC)."""
    iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    return r'''
$ErrorActionPreference = 'Stop'
$since = [datetime]::Parse('__SINCE__', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
$ms = [int64][Math]::Max(1000, ((Get-Date).ToUniversalTime() - $since).TotalMilliseconds)
$errors = @()
$events = @()
function Get-Ev($log, $xp, $max) {
  try {
    Get-WinEvent -LogName $log -FilterXPath $xp -MaxEvents $max -ErrorAction Stop | ForEach-Object {
      $x = [xml]$_.ToXml(); $d = @{}
      foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
      [pscustomobject]@{ id = $_.Id; t = $_.TimeCreated.ToUniversalTime().ToString('o'); d = $d }
    }
  } catch {
    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound|NoMatchingLogsFound') { $script:errors += ($log + ': ' + $_.Exception.Message) }
  }
}
$t = "TimeCreated[timediff(@SystemTime) <= $ms]"
$events += @(Get-Ev 'Security' "*[System[(EventID=4625 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4740 or EventID=1102 or EventID=4698) and $t]]" 3000)
$events += @(Get-Ev 'Security' "*[System[EventID=4624 and $t] and EventData[Data[@Name='LogonType']='10']]" 500)
$events += @(Get-Ev 'System' "*[System[EventID=7045 and $t]]" 200)
ConvertTo-Json -InputObject ([pscustomobject]@{ events = @($events); errors = @($errors) }) -Depth 5 -Compress
'''.replace("__SINCE__", iso)


def parse_windows(payload: dict) -> List[dict]:
    """Normalised events from the script's output."""
    out = []
    for e in payload.get("events") or []:
        d = e.get("d") or {}
        try:
            t = datetime.fromisoformat(str(e["t"]).replace("Z", "+00:00")).replace(tzinfo=None)
        except (KeyError, ValueError):
            continue
        i = int(e.get("id") or 0)
        src = d.get("IpAddress") or ""
        if src in ("-", "::1", "127.0.0.1", ""):
            src = d.get("WorkstationName") or src
        if i == 4625:
            out.append({"t": t, "kind": "logon_failed", "user": d.get("TargetUserName"), "src": src})
        elif i == 4624:
            out.append({"t": t, "kind": "logon_ok", "user": d.get("TargetUserName"), "src": src})
        elif i == 4740:
            out.append({"t": t, "kind": "lockout", "user": d.get("TargetUserName"), "src": d.get("TargetDomainName")})
        elif i == 4720:
            out.append({"t": t, "kind": "user_created", "user": d.get("TargetUserName"), "by": d.get("SubjectUserName")})
        elif i in (4728, 4732, 4756):
            group = (d.get("TargetUserName") or "")
            if group.lower() in PRIVILEGED:
                out.append({"t": t, "kind": "group_added", "user": d.get("MemberName") or d.get("MemberSid"), "group": group, "by": d.get("SubjectUserName")})
        elif i == 1102:
            out.append({"t": t, "kind": "log_cleared", "by": d.get("SubjectUserName")})
        elif i == 4698:
            out.append({"t": t, "kind": "task_created", "name": d.get("TaskName"), "by": d.get("SubjectUserName")})
        elif i == 7045:
            out.append({"t": t, "kind": "service_installed", "name": d.get("ServiceName"), "path": d.get("ImagePath")})
    return out


def _run_windows_sync(ip: str, port: int, username: str, password: str, domain: Optional[str], script: str) -> dict:
    import winrm
    from services import vuln_scan as vs
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(f"{scheme}://{ip}:{port}/wsman", auth=(user, password), transport="ntlm", server_cert_validation="ignore", read_timeout_sec=90, operation_timeout_sec=80)
    try:
        r = vs._run_ps_safe(session, script)
        if r.status_code != 0:
            return {"ok": False, "error": r.std_err.decode("utf-8", errors="ignore")[-500:]}
        raw = r.std_out.decode("utf-8", errors="ignore").strip()
        try:
            return {"ok": True, "payload": json.loads(raw)}
        except Exception as e:
            return {"ok": False, "error": f"unreadable answer: {e}"}
    finally:
        vs._close_winrm(session)


# ── Linux ────────────────────────────────────────────────────────────────────

_MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
_RE_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?([+-]\d\d:?\d\d|Z)?\s+\S+\s+(.*)$")
_RE_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+\S+\s+(.*)$")
_RE_FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+)")
_RE_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
_RE_USERADD = re.compile(r"new user: name=([^,\s]+)")
_RE_GROUP = re.compile(r"add '([^']+)' to (?:shadow )?group '([^']+)'")
_RE_SUDOFAIL = re.compile(r"sudo\S*:\s+(\S+)\s*:\s*(\d+) incorrect password attempt")

LINUX_COMMAND = ("sh -c \"if command -v journalctl >/dev/null 2>&1 && journalctl -q -n 1 --no-pager >/dev/null 2>&1; then "
                 "journalctl -q --since '@SINCE@' -o short-iso --no-pager -t sshd -t sudo -t useradd -t usermod -t groupadd -t adduser 2>/dev/null | tail -n 4000; "
                 "else for f in /var/log/auth.log /var/log/secure; do [ -r $f ] && tail -n 4000 $f; done; fi\"")


def linux_command(since: datetime) -> str:
    return LINUX_COMMAND.replace("@SINCE@", since.strftime("%Y-%m-%d %H:%M:%S"))


def _line_time(line: str, now: datetime) -> Tuple[Optional[datetime], str]:
    m = _RE_ISO.match(line)
    if m:
        t = datetime.fromisoformat(m.group(1))
        tz = m.group(2)
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[-2:])
            t = t - sign * timedelta(hours=hh, minutes=mm)                 # to UTC
        return t, m.group(3)
    m = _RE_SYSLOG.match(line)
    if m:
        mon = _MONTHS.get(m.group(1))
        if not mon:
            return None, line
        local = datetime(now.year, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
        if local > datetime.now() + timedelta(days=1):                      # a December line read in January
            local = local.replace(year=local.year - 1)
        # the log is in the host's local time; the agent's clock offset is the best guess for it
        return local - (datetime.now() - now), m.group(6)
    return None, line


def parse_linux(output: str, since: datetime, now: Optional[datetime] = None) -> List[dict]:
    now = now or datetime.utcnow()
    out, seen = [], set()
    for line in output.splitlines():
        t, msg = _line_time(line.strip(), now)
        if t is None or t < since:
            continue
        key = (t, msg)
        if key in seen:
            continue
        seen.add(key)
        m = _RE_FAILED.search(msg)
        if m:
            out.append({"t": t, "kind": "logon_failed", "user": m.group(1), "src": m.group(2)})
            continue
        m = _RE_OK.search(msg)
        if m:
            out.append({"t": t, "kind": "logon_ok", "user": m.group(2), "src": m.group(3), "method": m.group(1)})
            continue
        m = _RE_USERADD.search(msg)
        if m and ("useradd" in msg or "adduser" in msg):
            out.append({"t": t, "kind": "user_created", "user": m.group(1)})
            continue
        m = _RE_GROUP.search(msg)
        if m and m.group(2) in LINUX_ADMIN_GROUPS:
            out.append({"t": t, "kind": "group_added", "user": m.group(1), "group": m.group(2)})
            continue
        m = _RE_SUDOFAIL.search(msg)
        if m:
            out.append({"t": t, "kind": "sudo_failed", "user": m.group(1), "n": int(m.group(2))})
    return out


# ── Detections ───────────────────────────────────────────────────────────────

def _top(items, n=5) -> List[str]:
    cnt: Dict[str, int] = defaultdict(int)
    for x in items:
        if x:
            cnt[str(x)] += 1
    return [k for k, _ in sorted(cnt.items(), key=lambda kv: -kv[1])[:n]]


def evaluate(host: str, ip: Optional[str], os_kind: str, events: List[dict], now: Optional[float] = None) -> List[str]:
    """Raises the SOC alerts these events justify; returns the rule ids. `os_kind` is "windows" or "linux"."""
    from services import soc
    now = now or time.time()
    raised: List[str] = []
    label = "Windows" if os_kind == "windows" else "Linux"

    def alert(rule: str, title: str, sev: str, cat: str, detail: dict, key: str = "", mitre: Optional[str] = None, count: int = 1):
        soc.raise_alert(rule=f"hostlog.{rule}", device=host, title=title, severity=sev, category=cat, fp_detail=f"{os_kind}|{key}", ip=ip, detail=detail, count=count, mitre=mitre, source="hostlog")
        raised.append(rule)

    fails = [e for e in events if e["kind"] == "logon_failed"]
    for e in fails:
        if e.get("src"):
            _recent_fail[(host, e["src"])].append(now)
    if len(fails) >= FAIL_THRESHOLD:
        worst = max((len([x for x in fails if x.get("src") == s]) for s in {x.get("src") for x in fails}), default=0)
        alert("failed_logons", f"Repeated failed logons ({label})", "high" if worst >= 20 or len(fails) >= 50 else "medium", "auth",
              {"count": len(fails), "sources": _top(e.get("src") for e in fails), "users": _top(e.get("user") for e in fails), "message": f"{len(fails)} failed logons"},
              mitre="T1110", count=len(fails))
    for e in events:
        k = e["kind"]
        if k == "logon_ok":
            src = e.get("src") or ""
            q = _recent_fail.get((host, src))
            while q and now - q[0] > 1800:
                q.popleft()
            if src and q and len(q) >= AFTER_FAILURES:
                alert("login_after_failures", f"Successful logon after failed attempts ({label})", "critical", "auth",
                      {"users": [e.get("user")], "sources": [src], "count": len(q), "message": f"{e.get('user')} from {src} after {len(q)} failures"}, key=src, mitre="T1110")
            elif os_kind == "linux" and (e.get("user") or "") == "root":
                alert("root_login", "Root logged in over ssh", "medium", "auth", {"users": ["root"], "sources": [src], "message": f"root from {src} ({e.get('method')})"}, key=src, mitre="T1078")
        elif k == "lockout":
            alert("lockout", f"Account locked out ({label})", "medium", "auth", {"users": [e.get("user")], "message": f"{e.get('user')} locked out"}, key=str(e.get("user")), mitre="T1110")
        elif k == "user_created":
            alert("user_created", f"User account created ({label})", "medium", "auth", {"users": [e.get("user")], "message": f"{e.get('user')} created" + (f" by {e['by']}" if e.get("by") else "")},
                  key=str(e.get("user")), mitre="T1136")
        elif k == "group_added":
            alert("privileged_group", f"Added to a privileged group ({label})", "high", "auth", {"users": [e.get("user")], "message": f"{e.get('user')} added to {e.get('group')}" + (f" by {e['by']}" if e.get("by") else "")},
                  key=f"{e.get('user')}|{e.get('group')}", mitre="T1098")
        elif k == "log_cleared":
            alert("log_cleared", "The audit log was cleared", "high", "system", {"message": "Security log cleared" + (f" by {e['by']}" if e.get("by") else "")}, mitre="T1070.004")
        elif k == "task_created":
            alert("task_created", "Scheduled task created", "low", "system", {"message": f"{e.get('name')}" + (f" by {e['by']}" if e.get("by") else "")}, key=str(e.get("name")), mitre="T1053.005")
        elif k == "service_installed":
            alert("service_installed", "A service was installed", "medium", "system", {"message": f"{e.get('name')}: {str(e.get('path') or '')[:200]}"}, key=str(e.get("name")), mitre="T1543.003")
        elif k == "sudo_failed":
            alert("sudo_failed", "Failed sudo attempts", "low", "auth", {"users": [e.get("user")], "message": f"{e.get('user')}: {e.get('n')} incorrect password attempts"}, key=str(e.get("user")), mitre="T1548.003")
    return raised


# ── Collecting ───────────────────────────────────────────────────────────────

def _cursor(db, kind: str, host_id: int) -> HostLogCursor:
    c = db.execute(select(HostLogCursor).where(HostLogCursor.kind == kind, HostLogCursor.host_id == host_id)).scalars().first()
    if c is None:
        c = HostLogCursor(kind=kind, host_id=host_id)
        db.add(c)
    return c


def _finish(kind: str, host_id: int, started: datetime, events: int, error: Optional[str], read_ok: bool = True) -> None:
    """`error` with `read_ok` is a warning (one of the logs could not be read, the others were): the cursor moves on and the warning is shown."""
    with SessionLocal() as db:
        c = _cursor(db, kind, host_id)
        c.last_run_at = started
        c.last_error = error[:300] if error else None
        if read_ok:
            c.last_at = started
            c.last_ok_at = started
            c.events_total = (c.events_total or 0) + events
        db.commit()


async def collect_windows(host_id: int) -> dict:
    from services import windows_manage as wm
    with SessionLocal() as db:
        h = db.get(WindowsHost, host_id)
        if h is None:
            return {"error": "host not found"}
        name, ip, port = h.hostname or h.ip, h.ip, h.winrm_port
        cred = wm._credential_for_host(h)
        c = _cursor(db, "windows", host_id)
        since = c.last_at or (datetime.utcnow() - timedelta(minutes=FIRST_LOOKBACK_MIN))
        db.commit()
    if not cred:
        _finish("windows", host_id, datetime.utcnow(), 0, "no credential configured", read_ok=False)
        return {"error": "no credential configured"}
    started = datetime.utcnow()
    from services import vuln_scan as vs
    try:
        r = await asyncio.wait_for(asyncio.get_event_loop().run_in_executor(vs._EXECUTOR, _run_windows_sync, ip, port, cred[0], cred[1], cred[2], windows_script(since)), timeout=120)
    except Exception as e:
        _finish("windows", host_id, started, 0, f"{type(e).__name__}: {e}", read_ok=False)
        return {"error": str(e)}
    if not r["ok"]:
        _finish("windows", host_id, started, 0, r["error"], read_ok=False)
        return {"error": r["error"]}
    errs = r["payload"].get("errors") or []
    events = parse_windows(r["payload"])
    evaluate(name, ip, "windows", events)
    _finish("windows", host_id, started, len(events), "; ".join(errs) if errs else None)
    return {"ok": True, "events": len(events), "errors": errs}


async def collect_linux(host_id: int) -> dict:
    from services import linux_manage as lm, vuln_scan as vs
    with SessionLocal() as db:
        h = db.get(LinuxHost, host_id)
        if h is None:
            return {"error": "host not found"}
        name, ip = h.hostname or h.ip, h.ip
        c = _cursor(db, "linux", host_id)
        since = c.last_at or (datetime.utcnow() - timedelta(minutes=FIRST_LOOKBACK_MIN))
        db.commit()
    cred = lm._shared_credential()
    started = datetime.utcnow()
    if not cred:
        _finish("linux", host_id, started, 0, "no shared credential configured", read_ok=False)
        return {"error": "no shared credential configured"}
    cmd = linux_command(since)
    loop = asyncio.get_event_loop()
    try:
        try:
            r = await asyncio.wait_for(loop.run_in_executor(vs._EXECUTOR, lm._sudo_exec_sync, ip, cred[0], cred[1], cmd, 40), timeout=60)
            out = r.get("output", "") if isinstance(r, dict) else ""
            if not out.strip():
                raise RuntimeError("empty")
        except Exception:
            r = await asyncio.wait_for(loop.run_in_executor(vs._EXECUTOR, lm._plain_exec_sync, ip, cred[0], cred[1], cmd, 40), timeout=60)
            out = r.get("output", "")
    except Exception as e:
        _finish("linux", host_id, started, 0, f"{type(e).__name__}: {e}", read_ok=False)
        return {"error": str(e)}
    events = parse_linux(out, since, started)
    evaluate(name, ip, "linux", events)
    _finish("linux", host_id, started, len(events), None)
    return {"ok": True, "events": len(events)}


async def run_cycle() -> dict:
    with SessionLocal() as db:
        wins = [h.id for h in db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all()]    # noqa: E712
        lins = [h.id for h in db.execute(select(LinuxHost).where(LinuxHost.managed == True)).scalars().all()]        # noqa: E712
    sem = asyncio.Semaphore(3)
    out = {"windows": len(wins), "linux": len(lins), "errors": 0}

    async def one(fn, hid):
        async with sem:
            try:
                r = await fn(hid)
                out["errors"] += "error" in r
            except Exception as e:
                out["errors"] += 1
                print(f"[host_logs] {fn.__name__} {hid}: {e}")
    await asyncio.gather(*[one(collect_windows, i) for i in wins], *[one(collect_linux, i) for i in lins])
    return out


async def _loop():
    load_settings()
    await asyncio.sleep(120)
    while True:
        try:
            if _settings.get("enabled"):
                _running["on"] = True
                await run_cycle()
        except Exception as e:
            print(f"[host_logs] cycle error: {type(e).__name__}: {e}")
        finally:
            _running["on"] = False
        await asyncio.sleep(max(2, int(_settings.get("interval_min") or 10)) * 60)


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
    with SessionLocal() as db:
        cur = {(c.kind, c.host_id): c for c in db.execute(select(HostLogCursor)).scalars().all()}
        rows = []
        for h in db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all():     # noqa: E712
            c = cur.get(("windows", h.id))
            rows.append(_row("windows", h.id, h.hostname or h.ip, h.ip, c))
        for h in db.execute(select(LinuxHost).where(LinuxHost.managed == True)).scalars().all():         # noqa: E712
            c = cur.get(("linux", h.id))
            rows.append(_row("linux", h.id, h.hostname or h.ip, h.ip, c))
    rows.sort(key=lambda r: (r["error"] is None, r["name"].lower()))
    return {"settings": settings(), "running": _running["on"], "hosts": rows}


def _row(kind: str, hid: int, name: str, ip: str, c: Optional[HostLogCursor]) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None
    return {"kind": kind, "id": hid, "name": name, "ip": ip, "last_run": iso(c.last_run_at) if c else None, "last_ok": iso(c.last_ok_at) if c else None,
            "error": c.last_error if c else None, "events": (c.events_total or 0) if c else 0}
