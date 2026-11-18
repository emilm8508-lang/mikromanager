"""
Processes of a managed host, and actions on its services and processes: "find what eats the server and stop it".

The monitoring already says "CPU of FS1 at 98% for 20 minutes" or "service Spooler is stopped"; the next question is which process it is
and the next step is to restart the service or end the process. Both are here, for the Windows (WinRM) and Linux (SSH) hosts the agent
already manages (same credentials, same per-host "managed" opt-in):

  processes()   read on demand (nothing is polled in the background): the processes using the most CPU and memory now -
                Windows from the performance counters (CPU % over the moment of the read, divided by the logical processors) with the
                services each process hosts; Linux from two `top` samples a second apart (the second one is the CPU of that second).
                No command lines and no user names are read (they can carry passwords and personal data).
  service_action()   start / stop / restart a service (Windows) or a systemd unit (Linux, through sudo).
  kill_process()     end a process by its id, only when the process with that id still has the name shown (an id can be reused).

Write actions are gated like the rest of the host management (Windows: "Zarządzanie Windows", Linux: MIKROTIK_LINUX_MANAGE_ENABLED),
need a reason, run one at a time per host, and are logged (HostActionLog: who, what, why, the outcome; and the activity feed for
Central). Nothing typed is spliced into a script as code: service / unit names are checked against a pattern and quoted, process
ids are integers. Refused: ending the processes the system cannot live without, and stopping the service the agent reaches the host
through (WinRM, sshd) - that would lock the agent out; restarting them is allowed.
"""
import asyncio
import json
import re
import shlex
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, WindowsHost, LinuxHost, HostActionLog
from services import vuln_scan as vs

READ_TIMEOUT_SEC = 45
ACTION_TIMEOUT_SEC = 90
TOP_N = 40
MAX_REASON = 500
SERVICE_ACTIONS = ("start", "stop", "restart")

_WIN_SVC_RE = re.compile(r"^[A-Za-z0-9_.\-$@# ]{1,200}$")
_LINUX_UNIT_RE = re.compile(r"^[A-Za-z0-9@:_.\\-]{1,200}$")
_PROC_NAME_RE = re.compile(r"^[^\x00-\x1f'\"`$;|&<>]{1,100}$")
# ending these takes the system down (Windows) or is pointless and dangerous (Linux)
_WIN_CRITICAL = {"system", "idle", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso", "svchost", "registry", "memory compression",
                 "fontdrvhost", "dwm"}
_LINUX_CRITICAL = {"systemd", "init", "kthreadd", "sshd", "systemd-journald", "systemd-logind", "dbus-daemon", "dbus-broker"}
# stopping these cuts the agent off the host; restart is fine
_NO_STOP = {"windows": {"winrm", "rpcss", "eventlog"}, "linux": {"sshd", "ssh", "sshd.service", "ssh.service", "systemd-logind", "dbus"}}

_locks: Dict[tuple, asyncio.Lock] = {}


# ── Hosts ────────────────────────────────────────────────────────────────────

def _manage_enabled(platform: str) -> bool:
    if platform == "windows":
        from services import windows_manage
        return windows_manage._manage_enabled()
    from services import linux_manage
    return linux_manage.MANAGE_ENABLED


def _host_ctx(platform: str, host_id: int) -> dict:
    from services import windows_manage, linux_manage
    if platform not in ("windows", "linux"):
        raise ValueError("platform: windows or linux")
    with SessionLocal() as db:
        host = db.get(WindowsHost if platform == "windows" else LinuxHost, host_id)
        if not host or not host.managed:
            raise ValueError("host not found or not managed")
        cred = windows_manage._credential_for_host(host) if platform == "windows" else linux_manage._shared_credential()
        if not cred:
            raise ValueError("no credential configured for this host")
        return {"ip": host.ip, "port": (host.winrm_port or 5985) if platform == "windows" else 22, "cred": cred, "name": host.hostname or host.ip}


async def _in_executor(fn, *args, timeout: float):
    loop = asyncio.get_event_loop()
    return await asyncio.wait_for(loop.run_in_executor(vs._EXECUTOR, fn, *args), timeout=timeout)


# ── Reading the processes ────────────────────────────────────────────────────

WINDOWS_PROCS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
if (-not $cores) { $cores = 1 }
$svc = @{}
Get-CimInstance Win32_Service -Filter "ProcessId > 0" | ForEach-Object { $svc[[int]$_.ProcessId] += @($_.Name) }
$p = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' }
$p | ForEach-Object {
  [pscustomobject]@{ pid = [int]$_.IDProcess; name = ($_.Name -replace '#\d+$', ''); cpu = [math]::Round($_.PercentProcessorTime / $cores, 1);
                     mem = [math]::Round($_.WorkingSetPrivate / 1MB, 1); services = @($svc[[int]$_.IDProcess]) }
} | ConvertTo-Json -Compress
"""

LINUX_PROCS = "top -b -n 2 -d 1 -w 512 2>/dev/null | tail -n +1; echo '@@UNITS@@'; ps -eo pid=,unit= 2>/dev/null | head -n 2000"


def parse_windows(raw: str) -> List[dict]:
    raw = (raw or "").strip()
    if not raw:
        return []
    data = json.loads(raw)
    rows = [data] if isinstance(data, dict) else data
    out = []
    for r in rows:
        try:
            svcs = [str(s) for s in (r.get("services") or []) if s][:10]
            out.append({"pid": int(r["pid"]), "name": str(r.get("name") or "")[:100], "cpu": float(r.get("cpu") or 0), "mem_mb": float(r.get("mem") or 0),
                        "services": svcs})
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _mem_mb(v: str) -> Optional[float]:
    """top's RES: KiB by default, or with a unit suffix (m, g, t)."""
    m = re.fullmatch(r"([\d.,]+)([kmgt]?)", v.strip().lower())
    if not m:
        return None
    n = float(m.group(1).replace(",", "."))
    return round(n * {"": 1 / 1024, "k": 1 / 1024, "m": 1, "g": 1024, "t": 1024 * 1024}[m.group(2)], 1)


def parse_linux(output: str) -> List[dict]:
    """The second `top` sample (the CPU of one second), with the systemd unit of each process from `ps`."""
    text, _, units_txt = (output or "").partition("@@UNITS@@")
    units = {}
    for line in units_txt.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and p[0].isdigit() and p[1].strip() not in ("-", ""):
            units[int(p[0])] = p[1].strip()
    lines = text.splitlines()
    heads = [i for i, l in enumerate(lines) if re.search(r"\bPID\b", l) and "%CPU" in l and "COMMAND" in l]
    if not heads:
        return []
    h = heads[-1]
    cols = lines[h].split()
    try:
        ip, ic, ir, icmd = cols.index("PID"), cols.index("%CPU"), cols.index("RES"), cols.index("COMMAND")
    except ValueError:
        return []
    out = []
    for line in lines[h + 1:]:
        p = line.split()
        if len(p) <= icmd or not p[ip].isdigit():
            continue
        try:
            cpu = float(p[ic].replace(",", "."))
        except ValueError:
            continue
        pid = int(p[ip])
        out.append({"pid": pid, "name": " ".join(p[icmd:])[:100], "cpu": cpu, "mem_mb": _mem_mb(p[ir]) or 0.0,
                    "services": [units[pid]] if pid in units else []})
    return out


def _top(rows: List[dict]) -> List[dict]:
    """The TOP_N by CPU and the TOP_N by memory, together, CPU first."""
    by_cpu = sorted(rows, key=lambda r: (-r["cpu"], -r["mem_mb"]))[:TOP_N]
    by_mem = sorted(rows, key=lambda r: -r["mem_mb"])[:TOP_N]
    seen, out = set(), []
    for r in by_cpu + by_mem:
        if r["pid"] not in seen:
            seen.add(r["pid"])
            out.append(r)
    return sorted(out, key=lambda r: (-r["cpu"], -r["mem_mb"]))


def _win_read_sync(ip, port, user, pw, domain) -> dict:
    from services import host_services
    session = host_services._winrm_session(ip, port, user, pw, domain)
    try:
        r = vs._run_ps_safe(session, WINDOWS_PROCS)
        if r.status_code != 0:
            return {"error": r.std_err.decode("utf-8", errors="ignore")[-500:] or "PowerShell error"}
        return {"rows": parse_windows(r.std_out.decode("utf-8", errors="ignore"))}
    finally:
        vs._close_winrm(session)


def _linux_read_sync(ip, user, pw) -> dict:
    from services import linux_manage
    out = linux_manage._plain_exec_sync(ip, user, pw, LINUX_PROCS, READ_TIMEOUT_SEC)["output"]
    rows = parse_linux(out)
    if not rows:
        return {"error": "could not read the processes (is `top` there?)"}
    return {"rows": rows}


async def processes(platform: str, host_id: int) -> dict:
    ctx = _host_ctx(platform, host_id)
    try:
        if platform == "windows":
            u, p, d = ctx["cred"]
            r = await _in_executor(_win_read_sync, ctx["ip"], ctx["port"], u, p, d, timeout=READ_TIMEOUT_SEC + 20)
        else:
            u, p = ctx["cred"]
            r = await _in_executor(_linux_read_sync, ctx["ip"], u, p, timeout=READ_TIMEOUT_SEC + 20)
    except (asyncio.TimeoutError, TimeoutError):
        r = {"error": "timeout"}
    except Exception as e:
        r = {"error": f"{type(e).__name__}: {e}"[:500]}
    if r.get("error"):
        return {"host": ctx["name"], "error": r["error"], "processes": [], "at": datetime.utcnow().isoformat() + "Z"}
    rows = r["rows"]
    return {"host": ctx["name"], "error": None, "processes": _top(rows), "total": len(rows), "at": datetime.utcnow().isoformat() + "Z",
            "can_act": _manage_enabled(platform)}


# ── Actions ──────────────────────────────────────────────────────────────────

def _check_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    if len(reason) > MAX_REASON:
        raise ValueError(f"reason is too long (max {MAX_REASON} characters)")
    return reason


def service_script(platform: str, name: str, action: str) -> str:
    """The command for one service action. Raises ValueError for a name or an action that is not allowed."""
    if action not in SERVICE_ACTIONS:
        raise ValueError(f"action: one of {', '.join(SERVICE_ACTIONS)}")
    name = (name or "").strip()
    if platform == "windows":
        if not _WIN_SVC_RE.match(name):
            raise ValueError("not a valid service name")
        if action == "stop" and name.lower() in _NO_STOP["windows"]:
            raise ValueError(f"stopping {name} would cut the agent off this host - restart it instead")
        q = "'" + name.replace("'", "''") + "'"
        verb = {"start": "Start-Service", "stop": "Stop-Service -Force", "restart": "Restart-Service -Force"}[action]
        return (f"$ErrorActionPreference = 'Stop'; $s = Get-Service -Name {q}; {verb} -InputObject $s; Start-Sleep -Seconds 2; "
                f"$s.Refresh(); 'STATE=' + [string]$s.Status")
    if not _LINUX_UNIT_RE.match(name):
        raise ValueError("not a valid unit name")
    if action == "stop" and name.lower() in _NO_STOP["linux"]:
        raise ValueError(f"stopping {name} would cut the agent off this host - restart it instead")
    return f"sh -c {shlex.quote(f'systemctl {action} -- {shlex.quote(name)} && sleep 1; echo STATE=$(systemctl is-active -- {shlex.quote(name)})')}"


def kill_script(platform: str, pid: int, name: str, force: bool = False) -> str:
    """Ends the process only when the id still belongs to a process of that name. Raises ValueError for a protected one."""
    pid = int(pid)
    name = (name or "").strip()
    if pid <= 4 or (platform == "linux" and pid == 1):
        raise ValueError("system process - not ended")
    if not _PROC_NAME_RE.match(name):
        raise ValueError("not a valid process name")
    base = name.lower().removesuffix(".exe")
    if base in (_WIN_CRITICAL if platform == "windows" else _LINUX_CRITICAL):
        raise ValueError(f"{name} is a system process - ending it would bring the host down or lock the agent out")
    if platform == "windows":
        q = "'" + base.replace("'", "''") + "'"
        return (f"$ErrorActionPreference = 'Stop'; $p = Get-Process -Id {pid}; if ($p.ProcessName -ne {q}) {{ throw 'the process id now belongs to ' + $p.ProcessName }}; "
                f"Stop-Process -Id {pid} -Force; Start-Sleep -Seconds 1; if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ 'STATE=running' }} else {{ 'STATE=ended' }}")
    sig = "KILL" if force else "TERM"
    inner = (f'[ "$(cat /proc/{pid}/comm 2>/dev/null)" = {shlex.quote(name[:15])} ] || {{ echo "the process id now belongs to $(cat /proc/{pid}/comm 2>/dev/null)"; exit 3; }}; '
             f"kill -{sig} {pid} && sleep 1; if [ -d /proc/{pid} ]; then echo STATE=running; else echo STATE=ended; fi")
    return f"sh -c {shlex.quote(inner)}"


def _win_run_sync(ip, port, user, pw, domain, script: str) -> dict:
    from services import hyperv_manage
    r = hyperv_manage._run_ps_sync(ip, port, user, pw, domain, script, ACTION_TIMEOUT_SEC)
    out = r.std_out.decode("utf-8", errors="ignore").strip()
    err = r.std_err.decode("utf-8", errors="ignore").strip()
    return {"exit_code": r.status_code, "output": (out + ("\n" + err if err else ""))[-2000:]}


def _linux_run_sync(ip, user, pw, cmd: str) -> dict:
    from services import linux_manage
    r = linux_manage._sudo_exec_sync(ip, user, pw, cmd, ACTION_TIMEOUT_SEC)
    return {"exit_code": r["exit_code"], "output": (r["output"] or "")[-2000:]}


def _state_of(output: str) -> Optional[str]:
    m = re.findall(r"STATE=(\S+)", output or "")
    return m[-1].lower() if m else None


async def _act(platform: str, host_id: int, kind: str, target: str, script: str, reason: str, user: str, expect: Optional[str]) -> dict:
    ctx = _host_ctx(platform, host_id)
    with SessionLocal() as db:
        log = HostActionLog(platform=platform, host_id=host_id, host_name=ctx["name"], kind=kind, target=target[:200], reason=reason,
                            created_by=user, status="running")
        db.add(log)
        db.commit()
        log_id = log.id
    status, output, state = "error", "", None
    lock = _locks.setdefault((platform, host_id), asyncio.Lock())
    async with lock:
        try:
            if platform == "windows":
                u, p, d = ctx["cred"]
                r = await _in_executor(_win_run_sync, ctx["ip"], ctx["port"], u, p, d, script, timeout=ACTION_TIMEOUT_SEC + 20)
            else:
                u, p = ctx["cred"]
                r = await _in_executor(_linux_run_sync, ctx["ip"], u, p, script, timeout=ACTION_TIMEOUT_SEC + 20)
            output = r["output"]
            state = _state_of(output)
            if r["exit_code"] == 0 and (expect is None or state == expect):
                status = "ok"
        except (asyncio.TimeoutError, TimeoutError):
            output = "timeout"
        except Exception as e:
            output = f"{type(e).__name__}: {e}"[-2000:]
    with SessionLocal() as db:
        r = db.get(HostActionLog, log_id)
        if r:
            r.status, r.output, r.result_state, r.finished_at = status, output[-2000:], state, datetime.utcnow()
            db.commit()
    try:
        from services import activity
        activity.record("host_action", platform=platform, hostname=ctx["name"], kind=kind, target=target[:100], reason=reason[:200], by=user, status=status)
    except Exception as e:
        print(f"[host_processes] activity record error: {e}")
    return {"id": log_id, "status": status, "state": state, "output": output[-1000:]}


async def service_action(platform: str, host_id: int, name: str, action: str, reason: str, user: str) -> dict:
    if not _manage_enabled(platform):
        raise PermissionError(f"{platform.capitalize()} management is switched off on this agent")
    reason = _check_reason(reason)
    script = service_script(platform, name, action)
    expect = {"windows": {"start": "running", "restart": "running", "stop": "stopped"},
              "linux": {"start": "active", "restart": "active", "stop": "inactive"}}[platform][action]
    return await _act(platform, host_id, f"service_{action}", name.strip(), script, reason, user, expect)


async def kill_process(platform: str, host_id: int, pid: int, name: str, reason: str, user: str, force: bool = False) -> dict:
    if not _manage_enabled(platform):
        raise PermissionError(f"{platform.capitalize()} management is switched off on this agent")
    reason = _check_reason(reason)
    script = kill_script(platform, pid, name, force)
    return await _act(platform, host_id, "process_kill" + ("_force" if force and platform == "linux" else ""), f"{name} (PID {int(pid)})", script, reason, user, "ended")


def history(platform: str, host_id: int, limit: int = 30) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(HostActionLog).where(HostActionLog.platform == platform, HostActionLog.host_id == host_id)
                          .order_by(HostActionLog.id.desc()).limit(max(1, min(limit, 200)))).scalars().all()
    return [{"id": r.id, "at": r.created_at.isoformat() + "Z" if r.created_at else None, "kind": r.kind, "target": r.target, "reason": r.reason,
             "by": r.created_by, "status": r.status, "state": r.result_state, "output": (r.output or "")[-500:]} for r in rows]
