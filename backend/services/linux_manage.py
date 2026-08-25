"""
Linux host patch management — SSH into hosts discovered by services/
vuln_scan.py's network scan and run apt update/upgrade with ONE shared
credential (Credential model, same one used everywhere else), never
per-host credential guessing. vuln_scan.py's _auth_augment() deliberately
tries every saved credential against every host — the opposite of "one
credential for all of them" as requested — so it is NOT reused here; this
module only ever authenticates with the single credential chosen in
LinuxManageSettings.

Discovery reuses vuln_scan.py's existing weekly network pass (any host
with an open port 22, read from VulnHost/VulnService) rather than
scanning the network a second time. Discovered hosts start managed=False
(opt-in gate, mirrors ovh/schema.sql's edge_devices.enabled default) —
apt upgrade must never run on a host nobody reviewed. Existing managed
hosts are never auto-disabled or deleted just because one scan didn't see
them (unlike VulnHost's own pruning) — silently dropping a host from a
curated, opted-in list would be a bigger problem than a stale row.

Job state is held in _jobs (in-memory) so the UI can poll status — same
pattern as services/firmware.py's _jobs[device_id].

v1 scope: apt (Debian/Ubuntu) and dnf (RHEL family, incl. Oracle Linux).
A host on an unrecognized distro is discovered and labeled
(package_manager) but check/upgrade actions are rejected rather than
attempting an unsupported command path.

MIKROTIK_LINUX_MANAGE_ENABLED defaults to "1" (matches this codebase's
usual default-on convention, e.g. MIKROTIK_AUTO_UPDATE_ENABLED) — the
local agent UI already requires password+MFA to reach this tab at all,
and the sudo commands run here are fixed strings (apt/dnf update+upgrade
only, see _check_command/_upgrade_command) with no arbitrary-command
path anywhere in the API, so a separate env-var barrier on top of that
login would just be friction without a matching new risk. Can still be
set to "0" to opt back out (e.g. while still reviewing a fresh
deployment) — checked here (blocks the local tab too) AND separately in
services/uplink.py's command handler, so a correctly signed remote
command from Central also respects it. The per-host managed=True opt-in
(see discover_linux_hosts()'s docstring) is the gate that actually
matters day to day: it's what stops apt upgrade from ever running on a
host nobody specifically reviewed, regardless of this flag.
"""
import asyncio
import json
import os
import re
import time
from datetime import datetime
from typing import Callable, Optional
from sqlalchemy import select

from models.database import SessionLocal, Credential, VulnHost, VulnService, LinuxHost, LinuxManageSettings
from services.crypto import decrypt
from services import vuln_scan as vs
from services import activity

MANAGE_ENABLED = os.environ.get("MIKROTIK_LINUX_MANAGE_ENABLED", "1").strip().lower() not in ("0", "false", "no")

CHECK_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_LINUX_CHECK_TIMEOUT_SEC", "120"))
UPGRADE_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_LINUX_UPGRADE_TIMEOUT_SEC", "1800"))
MAX_OUTPUT_BYTES = 200_000

_jobs: dict = {}   # host_id -> job status dict
_upgrade_semaphore = asyncio.Semaphore(int(os.environ.get("MIKROTIK_LINUX_UPGRADE_CONCURRENCY", "2")))

_OS_RELEASE_ID_RE = re.compile(r'^ID=(?:"([^"]+)"|(\S+))', re.MULTILINE)
_OS_RELEASE_VERSION_RE = re.compile(r'^VERSION_ID=(?:"([^"]+)"|(\S+))', re.MULTILINE)
_OS_RELEASE_PRETTY_RE = re.compile(r'^PRETTY_NAME=(?:"([^"]+)"|(\S+))', re.MULTILINE)


def get_job_status(host_id: int) -> dict:
    return _jobs.get(host_id, {"status": "no_job"})


# ── Settings (the one shared credential) ────────────────────────────────

def get_settings() -> dict:
    with SessionLocal() as db:
        row = db.get(LinuxManageSettings, 1)
        if not row or not row.credential_id:
            return {"credential_id": None, "credential_name": None, "enabled": MANAGE_ENABLED}
        cred = db.get(Credential, row.credential_id)
        return {"credential_id": row.credential_id, "credential_name": cred.name if cred else None,
                "enabled": MANAGE_ENABLED}


def set_settings(credential_id: Optional[int]) -> dict:
    with SessionLocal() as db:
        row = db.get(LinuxManageSettings, 1)
        if not row:
            row = LinuxManageSettings(id=1)
            db.add(row)
        row.credential_id = credential_id
        row.updated_at = datetime.utcnow()
        db.commit()
    return get_settings()


def _shared_credential() -> Optional[tuple]:
    """Returns (username, password) for the configured shared credential, or None."""
    with SessionLocal() as db:
        row = db.get(LinuxManageSettings, 1)
        if not row or not row.credential_id:
            return None
        cred = db.get(Credential, row.credential_id)
        if not cred:
            return None
        try:
            password = decrypt(cred.password_enc)
        except Exception:
            return None
        return cred.username, password


# ── Discovery ────────────────────────────────────────────────────────────

def _identify_host_sync(ip: str, username: str, password: str) -> Optional[dict]:
    """Blocking — run via loop.run_in_executor. Read-only SSH probe: distro
    identity + hostname. Deliberately separate from vuln_scan.py's
    _ssh_identity_sync (which only parses ID/VERSION_ID, discards
    hostname/PRETTY_NAME) so this feature never needs to touch that
    already-relied-upon shared function."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=username, password=password,
                        timeout=8, banner_timeout=8, auth_timeout=8,
                        look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command(
            "cat /etc/os-release 2>/dev/null; echo ---HOST---; hostname 2>/dev/null", timeout=8)
        output = stdout.read().decode("utf-8", errors="ignore")
        return {"output": output}
    except Exception:
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


async def _identify_host(ip: str, username: str, password: str) -> Optional[dict]:
    loop = asyncio.get_event_loop()
    # Shares vuln_scan.py's dedicated thread pool rather than the process's
    # default executor — same reasoning as there: a blocking SSH call here
    # must never compete with (and starve) unrelated work elsewhere in the
    # app (e.g. serving a static page) for a thread from a shared pool.
    result = await loop.run_in_executor(vs._EXECUTOR, _identify_host_sync, ip, username, password)
    if not result:
        return None
    os_part, _, host_part = result["output"].partition("---HOST---")
    id_m = _OS_RELEASE_ID_RE.search(os_part)
    if not id_m:
        return None
    ver_m = _OS_RELEASE_VERSION_RE.search(os_part)
    pretty_m = _OS_RELEASE_PRETTY_RE.search(os_part)
    distro_id = (id_m.group(1) or id_m.group(2) or "").lower()
    distro_version = (ver_m.group(1) or ver_m.group(2)) if ver_m else None
    distro_pretty = (pretty_m.group(1) or pretty_m.group(2)) if pretty_m else None
    hostname = host_part.strip().splitlines()[0].strip() if host_part.strip() else None
    pkg_mgr_raw = vs._PACKAGE_MANAGER_BY_DISTRO.get(distro_id)
    # vuln_scan.py's dict labels the underlying package-LISTING tool it uses
    # for its own inventory audit (dpkg-query / rpm -qa) — this module wants
    # the actionable MANAGEMENT tool instead: apt for Debian-family, dnf for
    # every RPM-family distro it knows about (RHEL/Fedora/Rocky/Alma/Oracle
    # Linux all ship dnf today; yum is just an alias to it on modern releases).
    package_manager = {"dpkg": "apt", "rpm": "dnf"}.get(pkg_mgr_raw)
    return {
        "distro_id": distro_id, "distro_version": distro_version,
        "distro_pretty": distro_pretty, "hostname": hostname,
        "package_manager": package_manager,
    }


async def discover_linux_hosts(on_event: Optional[Callable] = None) -> dict:
    """Read hosts with an open SSH port from the vuln scanner's own tables
    (no independent port scan — reuses services/vuln_scan.py's weekly
    pass), identify any not yet known using ONLY the shared credential.
    New hosts are inserted with managed=False (pending) — never
    auto-enabled.

    on_event, if given, reports progress the same way as vuln_scan.run_scan()
    (reuses its _emit helper) — this function's two sequential per-host
    loops (identifying new hosts, refreshing pending-update counts for
    already-managed ones) are exactly the kind of silent, potentially-slow
    work that button click had zero feedback for."""
    if not MANAGE_ENABLED:
        return {"skipped": "MIKROTIK_LINUX_MANAGE_ENABLED not set"}

    cred = _shared_credential()
    if not cred:
        return {"skipped": "no shared credential configured"}
    username, password = cred

    with SessionLocal() as db:
        candidate_ips = list(db.execute(
            select(VulnHost.ip)
            .join(VulnService, VulnService.host_id == VulnHost.id)
            .where(VulnService.port == 22)
        ).scalars().all())
        known_ips = {ip for ip in db.execute(select(LinuxHost.ip)).scalars().all()}

    now = datetime.utcnow()

    # Refresh last_seen_at for already-known hosts still present in this pass.
    if candidate_ips:
        with SessionLocal() as db:
            existing = db.execute(
                select(LinuxHost).where(LinuxHost.ip.in_(candidate_ips))
            ).scalars().all()
            for h in existing:
                h.last_seen_at = now
            db.commit()

    new_ips = [ip for ip in candidate_ips if ip not in known_ips]
    vs._emit(on_event, {"type": "phase", "phase": "linux_identify", "total": len(new_ips)})
    discovered = 0
    for idx, ip in enumerate(new_ips, 1):
        info = await _identify_host(ip, username, password)
        vs._emit(on_event, {"type": "progress", "phase": "linux_identify",
                            "completed": idx, "total": len(new_ips), "ip": ip})
        if not info or not info["distro_id"]:
            continue
        with SessionLocal() as db:
            if db.execute(select(LinuxHost).where(LinuxHost.ip == ip)).scalar_one_or_none():
                continue  # discovered concurrently, skip
            db.add(LinuxHost(
                ip=ip, hostname=info["hostname"], distro_id=info["distro_id"],
                distro_pretty=info["distro_pretty"], distro_version=info["distro_version"],
                package_manager=info["package_manager"], managed=False, source="auto",
                first_seen_at=now, last_seen_at=now,
            ))
            db.commit()
        discovered += 1

    # Refresh pending-update counts for already-managed, actionable hosts —
    # keeps "N updates pending" visible (locally and via the Central
    # summary) without requiring a manual per-host "Check" click after
    # every scan. Best-effort per host: one host's SSH failure (offline,
    # credential rotated, network blip) never aborts the rest of the pass.
    checked = 0
    with SessionLocal() as db:
        managed_hosts = db.execute(
            select(LinuxHost).where(LinuxHost.managed == True,  # noqa: E712
                                     LinuxHost.package_manager.in_(SUPPORTED_PACKAGE_MANAGERS))
        ).scalars().all()
        managed_snapshot = [(h.id, h.ip, h.package_manager) for h in managed_hosts]

    vs._emit(on_event, {"type": "phase", "phase": "linux_refresh", "total": len(managed_snapshot)})
    for idx, (host_id, ip, pkg_mgr) in enumerate(managed_snapshot, 1):
        vs._emit(on_event, {"type": "progress", "phase": "linux_refresh",
                            "completed": idx, "total": len(managed_snapshot), "ip": ip})
        if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
            continue  # a user-triggered check/upgrade is already running for this host
        try:
            result = await _run_check(ip, username, password, pkg_mgr)
            if result["ok"]:
                _persist_check_result(host_id, ok=True, count=result["count"], packages=result["packages"])
                checked += 1
            else:
                _persist_check_result(host_id, ok=False, error=result["error"])
        except Exception as e:
            print(f"[linux_manage] discovery refresh error for {ip}: {e}")

    return {"candidates": len(candidate_ips), "discovered": discovered, "refreshed": checked}


async def full_network_scan_and_discover(on_event: Optional[Callable] = None) -> dict:
    """Manual "Skanuj sieć teraz" entry point (POST /api/linux/discover).
    discover_linux_hosts() alone only reads whatever the vulnerability
    scanner's own weekly pass already found (VulnHost/VulnService rows) —
    it never probes the network itself. That's the right call for the
    automatic hook at the end of vuln_scan.run_scan() (no point re-probing
    what that same run just did), but it means a host that only just
    started listening on port 22 wouldn't be found until the NEXT weekly
    scan, up to a week later — surprising for a button literally labeled
    "scan the network now". This triggers a real vuln_scan.run_scan() pass
    first (safe to call anytime — it no-ops via its own _in_progress guard
    if a scan is already running), then discovers/refreshes from the
    freshly updated port data.

    on_event, if given, is passed straight through to run_scan() (which
    itself already calls discover_linux_hosts(on_event=on_event) at its
    end) and to this function's own explicit discover_linux_hosts() call
    below, so a caller streaming progress sees phases from both stages."""
    try:
        await vs.run_scan(on_event=on_event)
    except Exception as e:
        print(f"[linux_manage] full network scan error: {e}")
    return await discover_linux_hosts(on_event=on_event)


# ── SSH command execution (first place in this codebase capturing real
# stdout+stderr+exit code — vuln_scan.py's exec_command calls are fixed,
# read-only, and discard both) ───────────────────────────────────────────

def _plain_exec_sync(ip: str, username: str, password: str, cmd: str, timeout_sec: int) -> dict:
    """Blocking, no sudo — for read-only checks that don't need root."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=username, password=password,
                        timeout=timeout_sec, banner_timeout=timeout_sec, auth_timeout=timeout_sec,
                        look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command(cmd, timeout=timeout_sec)
        return {"output": stdout.read().decode("utf-8", errors="ignore")}
    finally:
        try:
            client.close()
        except Exception:
            pass


def _sudo_exec_sync(ip: str, username: str, password: str, cmd: str, timeout_sec: int) -> dict:
    """Blocking — run via loop.run_in_executor. Runs `cmd` under
    `sudo -S -p ''`, feeding the password over the SSH channel's stdin
    stream — NEVER interpolated into the command line (no `echo pw | sudo`)
    so it can't show up in `ps aux` on a multi-user box. Works whether or
    not NOPASSWD sudo is configured on the target: if it is, sudo skips
    the prompt and just ignores the piped stdin.

    Reads stdout+stderr incrementally rather than one blocking read-to-EOF
    (so a caller can show progress on a multi-minute upgrade), capped at
    MAX_OUTPUT_BYTES total. Returns {"exit_code", "output"} with the real
    exit status from the channel — never inferred from the text alone."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=22, username=username, password=password,
                        timeout=10, banner_timeout=10, auth_timeout=10,
                        look_for_keys=False, allow_agent=False)
        stdin, stdout, stderr = client.exec_command(f"sudo -S -p '' {cmd}", timeout=timeout_sec)
        stdin.write(password + "\n")
        stdin.flush()

        channel = stdout.channel
        chunks: list = []
        total = 0
        start = time.time()
        while True:
            got_data = False
            if channel.recv_ready():
                chunk = channel.recv(4096)
                if chunk:
                    got_data = True
                    total += len(chunk)
                    if total <= MAX_OUTPUT_BYTES:
                        chunks.append(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096)
                if chunk:
                    got_data = True
                    total += len(chunk)
                    if total <= MAX_OUTPUT_BYTES:
                        chunks.append(chunk)
            if not got_data:
                if channel.exit_status_ready():
                    break
                if time.time() - start > timeout_sec:
                    raise TimeoutError(f"command timed out after {timeout_sec}s")
                time.sleep(0.2)

        exit_code = channel.recv_exit_status()
        output = b"".join(chunks).decode("utf-8", errors="ignore")
        if total > MAX_OUTPUT_BYTES:
            output += "\n... [truncated]"
        return {"exit_code": exit_code, "output": output}
    finally:
        try:
            client.close()
        except Exception:
            pass


SUPPORTED_PACKAGE_MANAGERS = ("apt", "dnf")


def _check_command(pkg_mgr: str) -> str:
    if pkg_mgr == "apt":
        return "apt-get update -qq && apt list --upgradable 2>/dev/null"
    if pkg_mgr == "dnf":
        # Exit code 100 means "updates available" (NOT an error) — handled
        # specially by the caller, see check_updates()/_run_check().
        return "dnf check-update -q"
    raise ValueError(f"unsupported package manager: {pkg_mgr}")


def _upgrade_command(pkg_mgr: str) -> str:
    if pkg_mgr == "apt":
        return ('DEBIAN_FRONTEND=noninteractive apt-get -y '
                '-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade')
    if pkg_mgr == "dnf":
        return "dnf -y upgrade"
    raise ValueError(f"unsupported package manager: {pkg_mgr}")


def _reboot_check_command(pkg_mgr: str) -> str:
    if pkg_mgr == "apt":
        return "test -f /var/run/reboot-required && echo REBOOT_REQUIRED || true"
    # needs-restarting -r (yum-utils/dnf-utils) exits 1 if a reboot is
    # needed, 0 if not. If the tool isn't installed the command exits 127 —
    # treated as "unknown", never surfaced as a false positive.
    return "needs-restarting -r >/dev/null 2>&1; test $? -eq 1 && echo REBOOT_REQUIRED || true"


def _lock_message(output: str, pkg_mgr: str) -> Optional[str]:
    """Explicit recognition of the most common transient failure — another
    package-manager process (Ubuntu's unattended-upgrades timer, or a
    concurrent dnf run) holding the lock — so a job fails fast with a clear
    reason instead of running to the full timeout."""
    if pkg_mgr == "apt":
        if "Could not get lock" in output or "Unable to acquire the dpkg frontend lock" in output:
            return "apt/dpkg is locked by another process (e.g. unattended-upgrades) — try again later"
    elif pkg_mgr == "dnf":
        if "already locked" in output.lower():
            return "dnf is locked by another process — try again later"
    return None


def _parse_upgradable(output: str, pkg_mgr: str) -> list:
    """Parses the check command's output into a list of package names,
    capped at 200 entries for storage. Formats differ per tool:
      apt:  'firefox/jammy-updates 115.0 amd64 [upgradable from: 114.0]'
      dnf:  'firefox.x86_64          115.0-1.el9        updates'
    """
    packages = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if pkg_mgr == "apt":
            if line.startswith("Listing"):
                continue
            name = line.split("/")[0].strip()
        else:
            if line.startswith("Last metadata") or line.startswith("Obsoleting"):
                continue
            parts = line.split()
            name = parts[0] if len(parts) >= 2 else None
        if name:
            packages.append(name)
    return packages[:200]


async def _run_check(ip: str, username: str, password: str, pkg_mgr: str) -> dict:
    """Runs the check command for `pkg_mgr` and returns a normalized
    {"ok": bool, "count": int, "packages": list, "output": str, "error": str}
    — shared by check_updates() (job-tracked, user-triggered) and
    discover_linux_hosts()'s silent refresh of already-managed hosts, so
    the dnf exit-code-100-means-updates-available quirk (see
    _check_command's docstring) is handled in exactly one place."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _sudo_exec_sync, ip, username, password,
                                  _check_command(pkg_mgr), CHECK_TIMEOUT_SEC),
            timeout=CHECK_TIMEOUT_SEC + 15,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return {"ok": False, "error": "timeout", "output": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": ""}

    output = result["output"]
    lock_msg = _lock_message(output, pkg_mgr)
    if lock_msg:
        return {"ok": False, "error": lock_msg, "output": output}

    if pkg_mgr == "dnf":
        # 0 = no updates, 100 = updates available, anything else = real error.
        if result["exit_code"] not in (0, 100):
            return {"ok": False, "error": f"dnf check-update failed (exit {result['exit_code']})", "output": output}
        packages = _parse_upgradable(output, pkg_mgr) if result["exit_code"] == 100 else []
    else:
        if result["exit_code"] != 0:
            return {"ok": False, "error": f"apt-get update failed (exit {result['exit_code']})", "output": output}
        packages = _parse_upgradable(output, pkg_mgr)

    return {"ok": True, "count": len(packages), "packages": packages, "output": output}


def _persist_check_result(host_id: int, ok: bool, count: Optional[int] = None,
                           packages: Optional[list] = None, error: Optional[str] = None) -> None:
    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if not host:
            return
        host.last_check_at = datetime.utcnow()
        host.last_status = "ok" if ok else "error"
        host.last_error = error
        if ok:
            host.upgradable_count = count
            host.upgradable_packages = json.dumps(packages or [])
        db.commit()


def _fail_job(host_id: int, ip: str, error: str, output: Optional[str] = None) -> dict:
    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if host:
            host.last_status = "error"
            host.last_error = error
            db.commit()
    activity.record("linux_apt_upgrade_failed", host_id=host_id, ip=ip, error=error)
    _jobs[host_id] = {"status": "error", "error": error, "ip": ip,
                       "log": [output[-2000:]] if output else []}
    return {"error": error}


# ── Actions ──────────────────────────────────────────────────────────────

_ACTIVE_STATUSES = ("starting", "checking", "updating", "upgrading")


async def check_updates(host_id: int) -> dict:
    """Runs the check command for the host's package manager (apt: update
    index + list upgradable; dnf: check-update) — read-only aside from
    refreshing apt's package index, never installs anything. Separate from
    upgrade_host(), same UX split as services/firmware.py's
    check_updates() vs upgrade_device()."""
    if not MANAGE_ENABLED:
        return {"error": "Linux management is disabled (MIKROTIK_LINUX_MANAGE_ENABLED)"}
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        if host.package_manager not in SUPPORTED_PACKAGE_MANAGERS:
            return {"error": f"unsupported package manager: {host.package_manager}"}
        ip, pkg_mgr = host.ip, host.package_manager

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password = cred

    _jobs[host_id] = {"status": "checking", "started_at": datetime.utcnow().isoformat(),
                       "ip": ip, "log": ["Checking for updates..."]}
    result = await _run_check(ip, username, password, pkg_mgr)

    if not result["ok"]:
        err = result["error"]
        status = "timeout" if err == "timeout" else "error"
        _jobs[host_id] = {"status": status, "error": err, "ip": ip,
                           "log": [result["output"][-2000:]] if result.get("output") else []}
        _persist_check_result(host_id, ok=False, error=err)
        return {"error": err}

    _jobs[host_id] = {"status": "done", "finished_at": datetime.utcnow().isoformat(), "ip": ip,
                       "upgradable_count": result["count"], "log": [result["output"][-4000:]]}
    _persist_check_result(host_id, ok=True, count=result["count"], packages=result["packages"])
    return {"ok": True, "upgradable_count": result["count"]}


async def upgrade_host(host_id: int) -> dict:
    """apt: `apt-get update` then `apt-get upgrade -y` (DEBIAN_FRONTEND=
    noninteractive + --force-confdef/--force-confold, the standard safe
    default for unattended upgrades — keeps the currently-installed config
    file rather than hanging on a conffile prompt). dnf: `dnf -y upgrade`
    (refreshes its own metadata as part of the same command). Then checks
    for a pending reboot. Never reboots automatically."""
    if not MANAGE_ENABLED:
        return {"error": "Linux management is disabled (MIKROTIK_LINUX_MANAGE_ENABLED)"}
    if _jobs.get(host_id, {}).get("status") in _ACTIVE_STATUSES:
        return {"error": f"job already in state '{_jobs[host_id]['status']}'"}

    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if not host or not host.managed:
            return {"error": "host not found or not managed"}
        if host.package_manager not in SUPPORTED_PACKAGE_MANAGERS:
            return {"error": f"unsupported package manager: {host.package_manager}"}
        ip, pkg_mgr = host.ip, host.package_manager
        identity = host.hostname or host.ip

    cred = _shared_credential()
    if not cred:
        return {"error": "no shared credential configured"}
    username, password = cred

    async with _upgrade_semaphore:
        _jobs[host_id] = {"status": "starting", "started_at": datetime.utcnow().isoformat(),
                           "log": [f"Starting {pkg_mgr} upgrade"], "ip": ip, "identity": identity}
        loop = asyncio.get_event_loop()

        if pkg_mgr == "apt":
            _jobs[host_id]["status"] = "updating"
            _jobs[host_id]["log"].append("Running apt-get update...")
            try:
                upd = await asyncio.wait_for(
                    loop.run_in_executor(vs._EXECUTOR, _sudo_exec_sync, ip, username, password,
                                          "DEBIAN_FRONTEND=noninteractive apt-get update -qq",
                                          UPGRADE_TIMEOUT_SEC),
                    timeout=UPGRADE_TIMEOUT_SEC + 15,
                )
            except (asyncio.TimeoutError, TimeoutError):
                return _fail_job(host_id, ip, "apt-get update timed out")
            except Exception as e:
                return _fail_job(host_id, ip, f"apt-get update failed: {e}")

            lock_msg = _lock_message(upd["output"], pkg_mgr)
            if lock_msg or upd["exit_code"] != 0:
                return _fail_job(host_id, ip, lock_msg or f"apt-get update failed (exit {upd['exit_code']})", upd["output"])
            update_log = upd["output"]
        else:
            update_log = ""  # dnf upgrade refreshes metadata itself, no separate step

        _jobs[host_id]["status"] = "upgrading"
        _jobs[host_id]["log"].append(f"Running {_upgrade_command(pkg_mgr)}...")
        try:
            up = await asyncio.wait_for(
                loop.run_in_executor(vs._EXECUTOR, _sudo_exec_sync, ip, username, password,
                                      _upgrade_command(pkg_mgr), UPGRADE_TIMEOUT_SEC),
                timeout=UPGRADE_TIMEOUT_SEC + 15,
            )
        except (asyncio.TimeoutError, TimeoutError):
            return _fail_job(host_id, ip, f"{pkg_mgr} upgrade timed out")
        except Exception as e:
            return _fail_job(host_id, ip, f"{pkg_mgr} upgrade failed: {e}")

        lock_msg = _lock_message(up["output"], pkg_mgr)
        if lock_msg or up["exit_code"] != 0:
            return _fail_job(host_id, ip, lock_msg or f"{pkg_mgr} upgrade failed (exit {up['exit_code']})", up["output"])

        reboot_required = False
        try:
            rr = await loop.run_in_executor(
                vs._EXECUTOR, _plain_exec_sync, ip, username, password, _reboot_check_command(pkg_mgr), 15)
            reboot_required = "REBOOT_REQUIRED" in rr.get("output", "")
        except Exception:
            pass

        now = datetime.utcnow()
        with SessionLocal() as db:
            host = db.get(LinuxHost, host_id)
            if host:
                host.last_upgrade_at = now
                host.last_status = "ok"
                host.last_error = None
                host.reboot_required = reboot_required
                host.upgradable_count = 0
                host.upgradable_packages = json.dumps([])
                db.commit()

        activity.record("linux_apt_upgraded", host_id=host_id, ip=ip, identity=identity,
                         reboot_required=reboot_required)

        _jobs[host_id] = {
            "status": "done", "finished_at": now.isoformat(), "ip": ip, "identity": identity,
            "reboot_required": reboot_required,
            "log": [update_log[-2000:], up["output"][-4000:]],
        }
        return {"ok": True, "reboot_required": reboot_required}


async def upgrade_bulk(host_ids: list) -> dict:
    """Sequential, never parallel — one host's upgrade completes before the
    next starts, same as services/firmware.py's upgrade_bulk. The
    per-upgrade _upgrade_semaphore still applies on top of this for any
    individually-triggered upgrades happening at the same time."""
    results = {}
    for host_id in host_ids:
        results[host_id] = await upgrade_host(host_id)
    return {"results": results}


# ── Listing / admin ──────────────────────────────────────────────────────

def _host_to_dict(h: LinuxHost) -> dict:
    return {
        "id": h.id, "ip": h.ip, "hostname": h.hostname,
        "distro_id": h.distro_id, "distro_pretty": h.distro_pretty, "distro_version": h.distro_version,
        "package_manager": h.package_manager, "managed": h.managed, "source": h.source,
        "first_seen_at": h.first_seen_at.isoformat() if h.first_seen_at else None,
        "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "last_check_at": h.last_check_at.isoformat() if h.last_check_at else None,
        "last_upgrade_at": h.last_upgrade_at.isoformat() if h.last_upgrade_at else None,
        "upgradable_count": h.upgradable_count,
        "reboot_required": h.reboot_required,
        "last_status": h.last_status, "last_error": h.last_error,
    }


def list_hosts() -> list:
    with SessionLocal() as db:
        hosts = db.execute(select(LinuxHost).order_by(LinuxHost.ip)).scalars().all()
        return [_host_to_dict(h) for h in hosts]


def set_managed(host_id: int, managed: bool) -> dict:
    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if not host:
            return {"error": "not found"}
        host.managed = managed
        db.commit()
        return _host_to_dict(host)


def public_summary() -> list:
    """Redacted summary for the snapshot's plaintext envelope — ONLY
    managed=True hosts (an auto-discovered-but-not-opted-in host's
    existence must never leave the agent, even as metadata), and never
    raw command output/log (mirrors services/supply_chain.py's
    public_summary(): counts/status only, not full findings)."""
    with SessionLocal() as db:
        hosts = db.execute(select(LinuxHost).where(LinuxHost.managed == True)).scalars().all()  # noqa: E712
        return [{
            "id": h.id, "ip": h.ip, "hostname": h.hostname, "distro_pretty": h.distro_pretty,
            "upgradable_count": h.upgradable_count, "reboot_required": h.reboot_required,
            "last_upgrade_at": h.last_upgrade_at.isoformat() if h.last_upgrade_at else None,
            "last_status": h.last_status,
        } for h in hosts]
