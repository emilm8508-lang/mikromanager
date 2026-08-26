"""
Windows server patch management — WinRM into hosts discovered by services/
vuln_scan.py's network scan (open port 5985/5986) and check/install Windows
Update with ONE shared credential (Credential model, same one used
everywhere else), never per-host credential guessing. Direct analog of
services/linux_manage.py — same "one credential for all", same opt-in
managed=False-until-reviewed gate, same in-memory _jobs status pattern.

Discovery reuses vuln_scan.py's existing weekly network pass (any host
with an open WinRM port, read from VulnHost/VulnService) rather than
scanning the network a second time.

Checking for updates is a pure read (Windows Update Agent COM API's
Search()) — safe, no gate needed beyond the login this whole UI already
sits behind. INSTALLING updates is a different story: calling
UpdateInstaller.Install() directly inside a plain WinRM (NTLM) session
fails with "Access is denied" (0x80070005) — the well-documented
double-hop problem (a remote WinRM session doesn't carry the fully
impersonated token the installer requires). The same workaround
PSWindowsUpdate's remote mode uses (Invoke-WUJob): write a script to the
target, register + immediately run a Scheduled Task as SYSTEM (a LOCAL
execution context on that host, so double-hop doesn't apply), poll for
its result file, then clean the task and script up. This is the least
verified part of this module — see _manage_enabled() below.

MIKROTIK_WINDOWS_MANAGE_ENABLED defaults to "0" (OFF), unlike Linux's
default-on MIKROTIK_LINUX_MANAGE_ENABLED — the scheduled-task-as-SYSTEM
mechanism above is a materially bigger step than toggling apt behind
sudo, and hasn't been validated against a real Windows Server + WinRM
target yet. Checked here (blocks the local tab's check/upgrade/restart
actions too, not discovery/read-only Search) AND separately in
services/uplink.py's command handler. The per-host managed=True opt-in
is still the gate that matters day to day, exactly as documented in
linux_manage.py.

The toggle itself is no longer JUST that env var: WindowsManageSettings.
manage_enabled (DB) overrides it when set, so the operator can flip this
from the agent's own UI — or remotely from Central — instead of having
to SSH/RDP into each agent's OS to edit its environment and restart the
service. See _manage_enabled() below.
"""
import asyncio
import json
import os
import re
import time
import uuid
from datetime import datetime
from typing import Callable, Optional
from sqlalchemy import select

from models.database import SessionLocal, Credential, VulnHost, VulnService, WindowsHost, WindowsManageSettings
from services.crypto import decrypt
from services import vuln_scan as vs
from services import activity

_MANAGE_ENABLED_ENV_DEFAULT = os.environ.get("MIKROTIK_WINDOWS_MANAGE_ENABLED", "0").strip().lower() not in ("0", "false", "no")


def _manage_enabled() -> bool:
    """Effective enabled/disabled state: WindowsManageSettings.manage_enabled
    (DB, settable from this agent's UI or via Central) if explicitly set,
    else the MIKROTIK_WINDOWS_MANAGE_ENABLED env var it replaces day to day
    (kept as the fallback so an untouched deployment behaves exactly as
    before this setting existed)."""
    with SessionLocal() as db:
        row = db.get(WindowsManageSettings, 1)
        if row is not None and row.manage_enabled is not None:
            return row.manage_enabled
    return _MANAGE_ENABLED_ENV_DEFAULT

CHECK_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_WINDOWS_CHECK_TIMEOUT_SEC", "120"))
UPGRADE_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_WINDOWS_UPGRADE_TIMEOUT_SEC", "3600"))
MAX_TITLES = 200
MAX_SCRIPT_BYTES = 64_000

_jobs: dict = {}   # host_id -> job status dict
_upgrade_semaphore = asyncio.Semaphore(int(os.environ.get("MIKROTIK_WINDOWS_UPGRADE_CONCURRENCY", "2")))

_ACTIVE_STATUSES = ("starting", "checking", "updating", "upgrading", "restarting", "running_script")

_HOSTNAME_RE = re.compile(r"^Host Name:\s*(.+)$", re.MULTILINE)
_OS_NAME_RE = re.compile(r"^OS Name:\s*(.+)$", re.MULTILINE)
_OS_VERSION_RE = re.compile(r"^OS Version:\s*(.+)$", re.MULTILINE)


def get_job_status(host_id: int) -> dict:
    return _jobs.get(host_id, {"status": "no_job"})


# ── Settings (the one shared credential) ────────────────────────────────

def get_settings() -> dict:
    enabled = _manage_enabled()
    with SessionLocal() as db:
        row = db.get(WindowsManageSettings, 1)
        if not row or not row.credential_id:
            return {"credential_id": None, "credential_name": None, "enabled": enabled}
        cred = db.get(Credential, row.credential_id)
        return {"credential_id": row.credential_id, "credential_name": cred.name if cred else None,
                "enabled": enabled}


def set_settings(credential_id: Optional[int], manage_enabled: Optional[bool] = None) -> dict:
    """manage_enabled: None means "leave the toggle as it is" (distinct
    from False, which explicitly turns it off) — the settings form only
    ever sends a credential change most of the time, and that shouldn't
    silently reset the enabled toggle back to the env var fallback."""
    with SessionLocal() as db:
        row = db.get(WindowsManageSettings, 1)
        if not row:
            row = WindowsManageSettings(id=1)
            db.add(row)
        row.credential_id = credential_id
        if manage_enabled is not None:
            row.manage_enabled = manage_enabled
        row.updated_at = datetime.utcnow()
        db.commit()
    return get_settings()


def _shared_credential() -> Optional[tuple]:
    """Returns (username, password, domain) for the configured shared credential, or None."""
    with SessionLocal() as db:
        row = db.get(WindowsManageSettings, 1)
        if not row or not row.credential_id:
            return None
        cred = db.get(Credential, row.credential_id)
        if not cred:
            return None
        try:
            password = decrypt(cred.password_enc)
        except Exception:
            return None
        return cred.username, password, cred.domain


# ── Discovery ────────────────────────────────────────────────────────────

def _identify_host_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Read-only WinRM probe:
    hostname + OS identity via `systeminfo`. Deliberately separate from
    vuln_scan.py's _winrm_identity_sync (which only parses OS Name/OS
    Version, discards Host Name) — same reasoning as linux_manage.py's
    own _identify_host_sync being separate from vuln_scan's SSH identity
    check. Always returns a dict with an "error" key (None on success)."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(user, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=10, operation_timeout_sec=8,
        )
        result = session.run_cmd("systeminfo")
        if result.status_code != 0:
            return {"output": "", "error": f"systeminfo exited {result.status_code}"}
        return {"output": result.std_out.decode("utf-8", errors="ignore"), "error": None}
    except Exception as e:
        return {"output": "", "error": f"{type(e).__name__}: {e}"}


async def _identify_host(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(vs._EXECUTOR, _identify_host_sync, ip, port, username, password, domain)
    if result["error"]:
        return {"hostname": None, "os_name": None, "os_version": None, "error": result["error"]}
    output = result["output"]
    host_m = _HOSTNAME_RE.search(output)
    name_m = _OS_NAME_RE.search(output)
    ver_m = _OS_VERSION_RE.search(output)
    if not name_m:
        return {"hostname": None, "os_name": None, "os_version": None,
                "error": "WinRM login succeeded but systeminfo output didn't look like Windows "
                         "(unexpected locale/format, or not actually Windows)"}
    return {
        "hostname": host_m.group(1).strip() if host_m else None,
        "os_name": name_m.group(1).strip(),
        "os_version": ver_m.group(1).strip() if ver_m else None,
        "error": None,
    }


async def discover_windows_hosts(on_event: Optional[Callable] = None) -> dict:
    """Read hosts with an open WinRM port from the vuln scanner's own
    tables (no independent port scan — reuses services/vuln_scan.py's
    weekly pass, vs.WINRM_PORTS = {5985, 5986}), identify any not yet
    known using ONLY the shared credential. New hosts are inserted with
    managed=False (pending) — never auto-enabled. Direct mirror of
    linux_manage.discover_linux_hosts()."""
    if not _manage_enabled():
        return {"skipped": "MIKROTIK_WINDOWS_MANAGE_ENABLED not set"}

    cred = _shared_credential()
    if not cred:
        return {"skipped": "no shared credential configured"}
    username, password, domain = cred

    with SessionLocal() as db:
        rows = list(db.execute(
            select(VulnHost.ip, VulnService.port)
            .join(VulnService, VulnService.host_id == VulnHost.id)
            .where(VulnService.port.in_((5985, 5986)))
        ).all())
        # Prefer 5986 (TLS) over 5985 when a host has both.
        port_by_ip: dict = {}
        for ip, port in rows:
            if ip not in port_by_ip or port == 5986:
                port_by_ip[ip] = port
        known_ips = {ip for ip in db.execute(select(WindowsHost.ip)).scalars().all()}

    now = datetime.utcnow()

    if port_by_ip:
        with SessionLocal() as db:
            existing = db.execute(
                select(WindowsHost).where(WindowsHost.ip.in_(list(port_by_ip.keys())))
            ).scalars().all()
            for h in existing:
                h.last_seen_at = now
            db.commit()

    new_ips = [ip for ip in port_by_ip if ip not in known_ips]
    vs._emit(on_event, {"type": "phase", "phase": "windows_identify", "total": len(new_ips)})
    discovered = 0
    for idx, ip in enumerate(new_ips, 1):
        port = port_by_ip[ip]
        info = await _identify_host(ip, port, username, password, domain)
        vs._emit(on_event, {"type": "progress", "phase": "windows_identify",
                            "completed": idx, "total": len(new_ips), "ip": ip,
                            "detail": info.get("error")})
        if info.get("error"):
            print(f"[windows_manage] identify skipped {ip}: {info['error']}")
            continue
        with SessionLocal() as db:
            if db.execute(select(WindowsHost).where(WindowsHost.ip == ip)).scalar_one_or_none():
                continue  # discovered concurrently, skip
            db.add(WindowsHost(
                ip=ip, hostname=info["hostname"], os_name=info["os_name"],
                os_version=info["os_version"], winrm_port=port, managed=False, source="auto",
                first_seen_at=now, last_seen_at=now,
            ))
            db.commit()
        discovered += 1

    # Refresh pending-update counts for already-managed hosts — best-effort
    # per host, one host's WinRM failure never aborts the rest of the pass.
    with SessionLocal() as db:
        managed_hosts = db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all()  # noqa: E712
        managed_snapshot = [(h.id, h.ip, h.winrm_port, h.last_compliance_check_at) for h in managed_hosts]

    checked = 0
    vs._emit(on_event, {"type": "phase", "phase": "windows_refresh", "total": len(managed_snapshot)})
    for idx, (host_id, ip, port, last_compliance_at) in enumerate(managed_snapshot, 1):
        vs._emit(on_event, {"type": "progress", "phase": "windows_refresh",
                            "completed": idx, "total": len(managed_snapshot), "ip": ip})
        if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
            continue
        try:
            result = await _run_check(ip, port, username, password, domain)
            if result["ok"]:
                _persist_check_result(host_id, ok=True, count=result["count"], titles=result["titles"])
                checked += 1
            else:
                _persist_check_result(host_id, ok=False, error=result["error"])
        except Exception as e:
            print(f"[windows_manage] discovery refresh error for {ip}: {e}")

        # Compliance hardening checks — same weekly cadence, own TTL (see
        # linux_manage.discover_linux_hosts()'s identical block).
        from services import compliance
        if not last_compliance_at or (datetime.utcnow() - last_compliance_at).days >= compliance.COMPLIANCE_CHECK_DAYS:
            try:
                await compliance.run_windows_checks(host_id)
            except Exception as e:
                print(f"[windows_manage] compliance check error for {ip}: {e}")

    return {"candidates": len(port_by_ip), "discovered": discovered, "refreshed": checked}


async def full_network_scan_and_discover(on_event: Optional[Callable] = None) -> dict:
    """Manual "Skanuj sieć teraz" entry point — mirrors
    linux_manage.full_network_scan_and_discover(): runs a real
    vuln_scan.run_scan() pass first (safe anytime, no-ops if a scan is
    already running) so a host that only just started listening on WinRM
    is found immediately, then discovers/refreshes from freshly updated
    port data."""
    try:
        await vs.run_scan(on_event=on_event)
    except Exception as e:
        print(f"[windows_manage] full network scan error: {e}")
    return await discover_windows_hosts(on_event=on_event)


# ── WinRM check / install / restart ─────────────────────────────────────

_CHECK_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$updates = @()
foreach ($u in $result.Updates) {
    $updates += [PSCustomObject]@{ Title = $u.Title; KB = ($u.KBArticleIDs -join ',') }
}
$updates | ConvertTo-Json -Compress
"""


def _check_updates_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Pure read: Search() only,
    never Download()/Install() — no double-hop issue, works over a plain
    WinRM session same as _identify_host_sync above."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=CHECK_TIMEOUT_SEC + 5, operation_timeout_sec=CHECK_TIMEOUT_SEC,
    )
    result = session.run_ps(_CHECK_SCRIPT)
    if result.status_code != 0:
        return {"ok": False, "error": result.std_err.decode("utf-8", errors="ignore")[-2000:]}
    raw = result.std_out.decode("utf-8", errors="ignore").strip()
    if not raw:
        return {"ok": True, "count": 0, "titles": []}
    try:
        parsed = json.loads(raw)
    except Exception as e:
        return {"ok": False, "error": f"couldn't parse update list: {e}"}
    if isinstance(parsed, dict):
        parsed = [parsed]
    titles = [f"{u.get('Title', '?')}" + (f" (KB{u['KB']})" if u.get("KB") else "") for u in parsed]
    return {"ok": True, "count": len(titles), "titles": titles[:MAX_TITLES]}


async def _run_check(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _check_updates_sync, ip, port, username, password, domain),
            timeout=CHECK_TIMEOUT_SEC + 15,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _persist_check_result(host_id: int, ok: bool, count: Optional[int] = None,
                           titles: Optional[list] = None, error: Optional[str] = None) -> None:
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host:
            return
        host.last_check_at = datetime.utcnow()
        host.last_status = "ok" if ok else "error"
        host.last_error = error
        if ok:
            host.upgradable_count = count
            host.upgradable_titles = json.dumps(titles or [])
        db.commit()


# Scheduled-task-as-SYSTEM install script — see module docstring for why
# this indirection exists (double-hop). {job_id} is substituted per run so
# concurrent jobs on the same host (shouldn't normally happen, but the
# semaphore caps at 2 across ALL hosts, not per host) never collide.
_INSTALL_TASK_SCRIPT = r"""
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {{ if (!$u.EulaAccepted) {{ $u.AcceptEula() }}; $toDownload.Add($u) | Out-Null }}
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $toDownload
$downloader.Download() | Out-Null
$toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {{ if ($u.IsDownloaded) {{ $toInstall.Add($u) | Out-Null }} }}
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$installResult = $installer.Install()
[PSCustomObject]@{{ ResultCode = $installResult.ResultCode; RebootRequired = $installResult.RebootRequired; Count = $toInstall.Count }} |
    ConvertTo-Json -Compress | Set-Content -Path "$env:TEMP\mm_winupdate_{job_id}_result.json"
"""


def _install_updates_sync(ip: str, port: int, username: str, password: str, domain: Optional[str],
                          job_id: str, timeout_sec: int) -> dict:
    """Blocking — run via loop.run_in_executor. Writes the install script
    to the target, registers + runs it as a Scheduled Task running as
    SYSTEM (sidesteps the WinRM double-hop restriction on
    UpdateInstaller.Install() — see module docstring), polls until the
    task finishes, reads the JSON result file, then cleans up the task
    and both temp files regardless of outcome."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=30, operation_timeout_sec=25,
    )
    task_name = f"MikroManagerUpdate_{job_id}"
    # PowerShell-side path expressions (expanded by the REMOTE shell, not
    # here) — quoted wherever used in a script so a %TEMP% containing a
    # space (a Windows username with a space in it is common) doesn't
    # split the argument.
    script_path = f"$env:TEMP\\mm_winupdate_{job_id}.ps1"
    result_path = f"$env:TEMP\\mm_winupdate_{job_id}_result.json"
    script_body = _INSTALL_TASK_SCRIPT.format(job_id=job_id)

    try:
        write_cmd = (
            f"$s = @'\n{script_body}\n'@; "
            f'Set-Content -Path "{script_path}" -Value $s'
        )
        r = session.run_ps(write_cmd)
        if r.status_code != 0:
            return {"ok": False, "error": f"couldn't write install script: {r.std_err.decode('utf-8', errors='ignore')[-1000:]}"}

        # run_cmd(exe, args) — args is a real argument LIST (each item is
        # one argv entry), not a shell command line, so schtasks.exe gets
        # exactly the tokens below with no re-parsing/splitting in between.
        # The /TR value is itself the one place we build a sub-command
        # line by hand (schtasks stores it as a single string) — its own
        # embedded file path is double-quoted for the same %TEMP%-with-a-
        # space reason as above.
        tr_value = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
        r = session.run_cmd("schtasks", [
            "/Create", "/TN", task_name, "/TR", tr_value,
            "/SC", "ONCE", "/ST", "00:00", "/RL", "HIGHEST", "/RU", "SYSTEM", "/F",
        ])
        if r.status_code != 0:
            return {"ok": False, "error": f"schtasks /Create failed: {r.std_err.decode('utf-8', errors='ignore')[-1000:]}"}

        r = session.run_cmd("schtasks", ["/Run", "/TN", task_name])
        if r.status_code != 0:
            return {"ok": False, "error": f"schtasks /Run failed: {r.std_err.decode('utf-8', errors='ignore')[-1000:]}"}

        deadline = time.time() + timeout_sec
        state = "Running"
        while time.time() < deadline:
            time.sleep(5)
            q = session.run_cmd("schtasks", ["/Query", "/TN", task_name, "/FO", "LIST"])
            out = q.std_out.decode("utf-8", errors="ignore")
            m = re.search(r"Status:\s*(.+)", out)
            state = m.group(1).strip() if m else state
            if state.lower() != "running":
                break
        else:
            return {"ok": False, "error": f"install timed out after {timeout_sec}s (task still running)"}

        r = session.run_ps(f'Get-Content -Path "{result_path}" -Raw -ErrorAction SilentlyContinue')
        raw = r.std_out.decode("utf-8", errors="ignore").strip()
        if not raw:
            return {"ok": False, "error": "install task finished but produced no result file "
                                          "(scheduled task may have been blocked by policy/AV — check the target's Task Scheduler history)"}
        try:
            parsed = json.loads(raw)
        except Exception as e:
            return {"ok": False, "error": f"couldn't parse install result: {e}"}
        # ResultCode: 2 = succeeded, 3 = succeeded with errors, 4 = failed, 5 = cancelled
        code = parsed.get("ResultCode")
        ok = code in (2, 3)
        return {"ok": ok, "result_code": code, "reboot_required": bool(parsed.get("RebootRequired")),
                "count": parsed.get("Count"), "error": None if ok else f"install ResultCode={code}"}
    finally:
        try:
            session.run_cmd("schtasks", ["/Delete", "/TN", task_name, "/F"])
        except Exception:
            pass
        try:
            session.run_ps(f'Remove-Item -Path "{script_path}","{result_path}" -ErrorAction SilentlyContinue')
        except Exception:
            pass


def _restart_sync(ip: str, port: int, username: str, password: str, domain: Optional[str], reason: str) -> dict:
    """Blocking — run via loop.run_in_executor. Plain `shutdown.exe` — no
    double-hop issue (unlike Windows Update's COM installer), works over a
    normal WinRM session. /t 60 gives WinRM time to get a response back
    before the host starts going down. /d p:4:1 is a standard Microsoft
    reason code ("Planned, Application: Installation") shown alongside our
    own /c comment in Event Viewer (EventID 1074)."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=15, operation_timeout_sec=10,
    )
    r = session.run_cmd("shutdown", ["/r", "/t", "60", "/c", reason, "/d", "p:4:1"])
    if r.status_code != 0:
        return {"ok": False, "error": r.std_err.decode("utf-8", errors="ignore")[-1000:]}
    return {"ok": True}


def _fail_job(host_id: int, ip: str, error: str) -> dict:
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if host:
            host.last_status = "error"
            host.last_error = error
            db.commit()
    activity.record("windows_update_failed", host_id=host_id, ip=ip, error=error)
    _jobs[host_id] = {"status": "error", "error": error, "ip": ip}
    return {"error": error}


# ── Actions ──────────────────────────────────────────────────────────────

async def check_updates(host_id: int) -> dict:
    """Read-only Search() — never gated on MANAGE_ENABLED (unlike
    upgrade_host/restart_host), same split as linux_manage.check_updates()
    vs upgrade_host()."""
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        ip, port = host.ip, host.winrm_port

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password, domain = cred

    _jobs[host_id] = {"status": "checking", "started_at": datetime.utcnow().isoformat(),
                       "ip": ip, "log": ["Checking for updates..."]}
    result = await _run_check(ip, port, username, password, domain)

    if not result["ok"]:
        err = result["error"]
        status = "timeout" if err == "timeout" else "error"
        _jobs[host_id] = {"status": status, "error": err, "ip": ip}
        _persist_check_result(host_id, ok=False, error=err)
        return {"error": err}

    _jobs[host_id] = {"status": "done", "finished_at": datetime.utcnow().isoformat(), "ip": ip,
                       "upgradable_count": result["count"], "log": result["titles"][:50]}
    _persist_check_result(host_id, ok=True, count=result["count"], titles=result["titles"])
    return {"ok": True, "upgradable_count": result["count"]}


async def upgrade_host(host_id: int, reason: str) -> dict:
    """Scheduled-task-as-SYSTEM install (see module docstring). Gated on
    MANAGE_ENABLED — this is the mechanism whose real-world behavior is
    unverified against a live Windows Server, per the plan this shipped
    from. reason is required (non-empty) — recorded in activity + the job
    status, matching restart_host's audit trail."""
    if not _manage_enabled():
        return {"error": "Windows management is disabled (MIKROTIK_WINDOWS_MANAGE_ENABLED)"}
    if not reason or not reason.strip():
        return {"error": "reason required"}
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        ip, port = host.ip, host.winrm_port
        identity = host.hostname or host.ip

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password, domain = cred

    async with _upgrade_semaphore:
        job_id = uuid.uuid4().hex[:12]
        _jobs[host_id] = {"status": "upgrading", "started_at": datetime.utcnow().isoformat(),
                           "ip": ip, "identity": identity, "reason": reason,
                           "log": ["Registering install task as SYSTEM (this can take a while)..."]}
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(vs._EXECUTOR, _install_updates_sync, ip, port, username, password,
                                     domain, job_id, UPGRADE_TIMEOUT_SEC),
                timeout=UPGRADE_TIMEOUT_SEC + 30,
            )
        except (asyncio.TimeoutError, TimeoutError):
            return _fail_job(host_id, ip, "install timed out")
        except Exception as e:
            return _fail_job(host_id, ip, f"install failed: {e}")

        if not result["ok"]:
            return _fail_job(host_id, ip, result["error"])

        now = datetime.utcnow()
        with SessionLocal() as db:
            host = db.get(WindowsHost, host_id)
            if host:
                host.last_upgrade_at = now
                host.last_status = "ok"
                host.last_error = None
                host.reboot_required = result["reboot_required"]
                host.upgradable_count = 0
                host.upgradable_titles = json.dumps([])
                db.commit()

        activity.record("windows_update_installed", host_id=host_id, ip=ip, identity=identity,
                         reason=reason, reboot_required=result["reboot_required"])

        _jobs[host_id] = {
            "status": "done", "finished_at": now.isoformat(), "ip": ip, "identity": identity,
            "reboot_required": result["reboot_required"], "reason": reason,
            "log": [f"Installed {result.get('count', '?')} update(s), ResultCode={result['result_code']}"],
        }
        return {"ok": True, "reboot_required": result["reboot_required"]}


async def restart_host(host_id: int, reason: str) -> dict:
    if not _manage_enabled():
        return {"error": "Windows management is disabled (MIKROTIK_WINDOWS_MANAGE_ENABLED)"}
    if not reason or not reason.strip():
        return {"error": "reason required"}
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        ip, port = host.ip, host.winrm_port
        identity = host.hostname or host.ip

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password, domain = cred

    _jobs[host_id] = {"status": "restarting", "started_at": datetime.utcnow().isoformat(),
                       "ip": ip, "identity": identity, "reason": reason,
                       "log": ["Sending shutdown /r..."]}
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _restart_sync, ip, port, username, password, domain, reason),
            timeout=30,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return _fail_job(host_id, ip, "restart command timed out")
    except Exception as e:
        return _fail_job(host_id, ip, f"restart failed: {e}")

    if not result["ok"]:
        return _fail_job(host_id, ip, result["error"])

    now = datetime.utcnow()
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if host:
            host.last_restart_at = now
            host.last_restart_reason = reason
            host.last_status = "ok"
            host.last_error = None
            db.commit()

    activity.record("windows_restarted", host_id=host_id, ip=ip, identity=identity, reason=reason)
    _jobs[host_id] = {"status": "done", "finished_at": now.isoformat(), "ip": ip, "identity": identity,
                       "reason": reason, "log": ["Restart command sent (host going down in ~60s)"]}
    return {"ok": True}


async def upgrade_bulk(host_ids: list, reason: str) -> dict:
    """Sequential, never parallel — mirrors linux_manage.upgrade_bulk. The
    per-upgrade _upgrade_semaphore still applies on top for any
    individually-triggered upgrade happening at the same time."""
    if not reason or not reason.strip():
        return {"error": "reason required"}
    results = {}
    for host_id in host_ids:
        results[host_id] = await upgrade_host(host_id, reason)
    return {"results": results}


# ── Run an arbitrary script (opt-in feature, mirrors linux_manage.py's
# run_script() — see its docstring for why this is gated more heavily
# than everything else in this module)


def _run_script_sync(ip: str, port: int, username: str, password: str, domain: Optional[str],
                     script: str, timeout_sec: int) -> dict:
    """Blocking — run via loop.run_in_executor. Unlike Windows Update
    installation, an arbitrary PowerShell script has no double-hop problem
    (it isn't touching UpdateInstaller's impersonation-sensitive COM API) —
    a plain `session.run_ps(script)` over the normal WinRM session works
    directly, no scheduled-task workaround needed."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=timeout_sec + 10, operation_timeout_sec=timeout_sec,
    )
    result = session.run_ps(script)
    output = (result.std_out.decode("utf-8", errors="ignore")
              + result.std_err.decode("utf-8", errors="ignore"))
    if len(output) > 200_000:
        output = output[:200_000] + "\n... [truncated]"
    return {"exit_code": result.status_code, "output": output}


async def run_script(host_id: int, script: str, reason: str) -> dict:
    """Run an arbitrary PowerShell script on a managed host — the single
    most powerful action in this module, gated more heavily than the rest:
    a non-empty reason and a script under MAX_SCRIPT_BYTES are both
    required in addition to MANAGE_ENABLED. Never exposed through the
    Central command queue (see uplink.py) — only reachable from this
    agent's own, already login+MFA-gated UI."""
    if not _manage_enabled():
        return {"error": "Windows management is disabled (MIKROTIK_WINDOWS_MANAGE_ENABLED)"}
    if not reason or not reason.strip():
        return {"error": "reason required"}
    if not script or not script.strip():
        return {"error": "script required"}
    if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
        return {"error": f"script exceeds {MAX_SCRIPT_BYTES} byte limit"}
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        ip, port = host.ip, host.winrm_port
        identity = host.hostname or host.ip

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password, domain = cred

    _jobs[host_id] = {"status": "running_script", "started_at": datetime.utcnow().isoformat(),
                       "ip": ip, "identity": identity, "reason": reason,
                       "log": ["Running script..."]}
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _run_script_sync, ip, port, username, password,
                                 domain, script, UPGRADE_TIMEOUT_SEC),
            timeout=UPGRADE_TIMEOUT_SEC + 15,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return _fail_job(host_id, ip, "script timed out")
    except Exception as e:
        return _fail_job(host_id, ip, f"script failed: {e}")

    # Full (truncated) script text in the audit trail, not just the fact a
    # script ran — mirrors linux_manage.run_script()'s reasoning.
    activity.record("windows_script_run", host_id=host_id, ip=ip, identity=identity,
                     reason=reason, script=script[:2000], exit_code=result["exit_code"])

    now = datetime.utcnow()
    job = {
        "status": "done" if result["exit_code"] == 0 else "error",
        "finished_at": now.isoformat(), "ip": ip, "identity": identity, "reason": reason,
        "log": [result["output"][-4000:]],
    }
    if result["exit_code"] != 0:
        job["error"] = f"script exited with code {result['exit_code']}"
    _jobs[host_id] = job
    return {"ok": result["exit_code"] == 0, "exit_code": result["exit_code"]}


async def run_script_bulk(host_ids: list, script: str, reason: str) -> dict:
    """Sequential, never parallel — same reasoning as upgrade_bulk."""
    results = {}
    for host_id in host_ids:
        results[host_id] = await run_script(host_id, script, reason)
    return {"results": results}


# ── Listing / admin ──────────────────────────────────────────────────────

def _host_to_dict(h: WindowsHost) -> dict:
    return {
        "id": h.id, "ip": h.ip, "hostname": h.hostname,
        "os_name": h.os_name, "os_version": h.os_version, "winrm_port": h.winrm_port,
        "managed": h.managed, "source": h.source,
        "first_seen_at": h.first_seen_at.isoformat() if h.first_seen_at else None,
        "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "last_check_at": h.last_check_at.isoformat() if h.last_check_at else None,
        "last_upgrade_at": h.last_upgrade_at.isoformat() if h.last_upgrade_at else None,
        "upgradable_count": h.upgradable_count,
        "reboot_required": h.reboot_required,
        "last_status": h.last_status, "last_error": h.last_error,
        "last_restart_at": h.last_restart_at.isoformat() if h.last_restart_at else None,
        "last_restart_reason": h.last_restart_reason,
    }


def list_hosts() -> list:
    with SessionLocal() as db:
        hosts = db.execute(select(WindowsHost).order_by(WindowsHost.ip)).scalars().all()
        return [_host_to_dict(h) for h in hosts]


def set_managed(host_id: int, managed: bool) -> dict:
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host:
            return {"error": "not found"}
        host.managed = managed
        db.commit()
        return _host_to_dict(host)


def public_summary() -> list:
    """Redacted summary for the snapshot's plaintext envelope — ONLY
    managed=True hosts, never raw log/reason from past actions beyond the
    latest status. Mirrors linux_manage.public_summary()."""
    with SessionLocal() as db:
        hosts = db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all()  # noqa: E712
        return [{
            "id": h.id, "ip": h.ip, "hostname": h.hostname, "os_name": h.os_name,
            "upgradable_count": h.upgradable_count, "reboot_required": h.reboot_required,
            "last_upgrade_at": h.last_upgrade_at.isoformat() if h.last_upgrade_at else None,
            "last_status": h.last_status,
        } for h in hosts]
