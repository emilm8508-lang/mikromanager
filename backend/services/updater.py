"""
Self-updater — runs git pull + npm build + exits cleanly so the supervisor
(systemd on Linux, NSSM on Windows) auto-restarts the process with new code.

Three ways this runs:
  - Manual: a button click (backend/api/system.py) or CLI (python -m services.updater).
  - Remote-requested: a scheduled command from central ("please update"),
    still a deliberate human action (someone clicked "update this tenant").
  - Fully autonomous (start_auto_update()): checks origin/master once a day
    and self-updates + restarts with NO human confirmation, if behind.
    This is a real change in risk profile from the other two paths — a bad
    push reaches every live agent with auto-update enabled, unattended, no
    review gate. Explicitly opted into (MIKROTIK_AUTO_UPDATE_ENABLED,
    defaults to enabled — set to "0" to keep updates manual-only again).
"""
import asyncio
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from typing import Optional


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

AUTO_UPDATE_ENABLED = os.environ.get("MIKROTIK_AUTO_UPDATE_ENABLED", "1").strip().lower() not in ("0", "false", "no")
AUTO_UPDATE_HOUR = int(os.environ.get("MIKROTIK_AUTO_UPDATE_HOUR", "3"))  # UTC, offset from the :00 weekly jobs


# ── State (read by /api/system/updater/status) ────────────────────────────────
_state = {
    "in_progress": False,
    "last_run": None,
    "last_ok": None,
    "last_error": None,
    "last_log": [],
}


def status() -> dict:
    return {
        "in_progress": _state["in_progress"],
        "last_run": _state["last_run"],
        "last_ok": _state["last_ok"],
        "last_error": _state["last_error"],
        "last_log_tail": _state["last_log"][-20:] if _state["last_log"] else [],
    }


def read_git_info() -> dict:
    """Read local git commit info. Best-effort."""
    info = {"commit": None, "commit_time": None, "branch": None}
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, cwd=REPO_ROOT,
        )
        if r.returncode == 0:
            info["commit"] = r.stdout.strip()
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, cwd=REPO_ROOT,
        )
        if r.returncode == 0 and r.stdout.strip().isdigit():
            info["commit_time"] = int(r.stdout.strip())
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, cwd=REPO_ROOT,
        )
        if r.returncode == 0:
            info["branch"] = r.stdout.strip()
    except Exception:
        pass
    return info


def _npm_cmd() -> str:
    """Return the right npm executable name for this platform."""
    if sys.platform == "win32":
        # Prefer npm.cmd (shim from Node installer)
        return shutil.which("npm.cmd") or shutil.which("npm") or "npm.cmd"
    return shutil.which("npm") or "npm"


def _child_env() -> dict:
    """Prepared environment for subprocesses spawned by the updater.

    Systemd services usually run under a hardened user (mikromanager) that:
      - has no home directory (or one it can't write to)
      - PrivateTmp=true blocks /tmp visibility
    Both pip and npm need a writable tmp + cache. Point HOME/TMPDIR/npm cache
    to writable locations inside the app dir so the update works regardless.
    """
    env = os.environ.copy()
    # Writable app-owned scratch dirs — created if missing
    tmp = os.path.join(REPO_ROOT, ".tmp")
    cache = os.path.join(REPO_ROOT, ".cache")
    os.makedirs(tmp, exist_ok=True)
    os.makedirs(cache, exist_ok=True)
    env.setdefault("HOME", REPO_ROOT)
    env["TMPDIR"] = tmp
    env["TMP"] = tmp
    env["TEMP"] = tmp
    env["npm_config_cache"] = cache
    env["PIP_CACHE_DIR"] = cache
    return env


async def _run(cmd, log, cwd, timeout=300) -> int:
    """Run a subprocess capturing stdout/stderr into log list. Returns exit code.
    Runs the blocking subprocess.run() in a worker thread so it doesn't freeze
    the whole backend event loop during the multi-minute update."""
    label = " ".join(cmd)
    log.append(f"$ {label}")

    def _blocking_run():
        # encoding="utf-8" explicitly — without it, text=True decodes using
        # the OS's default codepage (e.g. CP1250 on a Windows agent), which
        # crashes on legitimate UTF-8 output (a commit message, a package
        # name) even though git/pip/npm all emit UTF-8 regardless of locale.
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, cwd=cwd, env=_child_env(),
        )

    try:
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(None, _blocking_run)
        if r.stdout:
            log.append(r.stdout.strip())
        if r.stderr:
            log.append(r.stderr.strip())
        log.append(f"[exit {r.returncode}]")
        return r.returncode
    except subprocess.TimeoutExpired:
        log.append(f"[TIMEOUT after {timeout}s]")
        return -1
    except Exception as e:
        log.append(f"[ERROR: {type(e).__name__}: {e}]")
        return -2


async def perform_update(restart_supervisor: bool = True) -> tuple:
    """Run full self-update. Returns (success: bool, logs: list[str])."""
    global _state
    if _state["in_progress"]:
        return False, ["update already in progress"]

    _state["in_progress"] = True
    _state["last_run"] = datetime.utcnow().isoformat()
    log: list = []

    try:
        # 1. git fetch
        if await _run(["git", "fetch", "origin"], log, cwd=REPO_ROOT) != 0:
            _state["last_error"] = "git fetch failed"
            return False, log

        # 2. git reset to origin/master (blows away local drift)
        if await _run(["git", "reset", "--hard", "origin/master"], log, cwd=REPO_ROOT) != 0:
            _state["last_error"] = "git reset failed"
            return False, log

        # 3. Install python deps if requirements.txt changed. Use current
        # interpreter (works with venv too). Exit code MUST be checked —
        # previously wasn't, so a failed pip install (network hiccup,
        # permission issue) silently left the agent on old dependencies
        # while git+npm still "succeeded", with no visible error anywhere.
        req_path = os.path.join(REPO_ROOT, "backend", "requirements.txt")
        if os.path.exists(req_path):
            if await _run([sys.executable, "-m", "pip", "install",
                           "-r", req_path, "--quiet"], log, cwd=REPO_ROOT, timeout=600) != 0:
                _state["last_error"] = "pip install failed"
                return False, log

        # 4. npm install + build
        frontend = os.path.join(REPO_ROOT, "frontend")
        npm = _npm_cmd()
        if await _run([npm, "install", "--no-audit", "--no-fund"], log, cwd=frontend, timeout=600) != 0:
            _state["last_error"] = "npm install failed"
            return False, log

        # Build into a staging directory rather than straight into "dist" —
        # the live backend keeps serving dist/'s files (StaticFiles/
        # FileResponse) the WHOLE time this update runs (nothing here stops
        # traffic), and Vite overwrites files in place rather than replacing
        # them atomically. A request landing mid-write reads a file whose
        # size changed between the response's Content-Length being computed
        # and the body finishing streaming — confirmed on a real agent as
        # the browser's own page load failing with net::ERR_CONTENT_LENGTH_
        # MISMATCH, right as an update was building. Swapping the whole
        # directory in with a rename (near-instant, not proportional to
        # content size) instead closes that window down to microseconds.
        dist = os.path.join(frontend, "dist")
        dist_new = os.path.join(frontend, "dist_new")
        dist_old = os.path.join(frontend, "dist_old")
        if os.path.isdir(dist_new):
            shutil.rmtree(dist_new, ignore_errors=True)
        if await _run([npm, "run", "build", "--", "--outDir", "dist_new"],
                      log, cwd=frontend, timeout=600) != 0:
            _state["last_error"] = "npm build failed"
            return False, log

        if not os.path.isdir(dist_new):
            _state["last_error"] = "npm build produced no dist_new output"
            return False, log
        try:
            # Leftover from a previous cycle that couldn't be removed then
            # (e.g. a file still open from an in-flight response on Windows,
            # which blocks deletion) — best-effort cleanup, never fatal.
            if os.path.isdir(dist_old):
                shutil.rmtree(dist_old, ignore_errors=True)
            if os.path.isdir(dist):
                os.rename(dist, dist_old)
            os.rename(dist_new, dist)
        except OSError as e:
            _state["last_error"] = f"dist swap failed: {e}"
            log.append(f"[dist swap error] {e}")
            return False, log

        _state["last_ok"] = datetime.utcnow().isoformat()
        _state["last_error"] = None
        log.append("[UPDATE OK]")

        if restart_supervisor:
            log.append("[scheduling process exit for supervisor auto-restart]")
            # Give the HTTP response time to flush before killing ourselves
            asyncio.get_event_loop().call_later(3.0, lambda: os._exit(0))

        return True, log
    finally:
        _state["last_log"] = log
        _state["in_progress"] = False


# ── Fully autonomous daily update check ─────────────────────────────────────
# See module docstring for the risk tradeoff. Deliberately checks (git fetch
# + compare HEAD to origin/master) BEFORE calling perform_update() — never
# calls it unconditionally, so a day with no new commits does nothing at all
# (no needless npm/pip reinstall, no restart).

_auto_update_task: Optional[asyncio.Task] = None


def _next_daily_run(now: datetime, hour: int) -> datetime:
    # :15 past the hour, offset from the other services' :00 weekly slots
    # (vuln_scan 02:00, agent_backup 03:00, supply_chain 04:00 — all Sunday
    # only, so an exact hour clash is rare, but the offset keeps it that way).
    candidate = now.replace(hour=hour, minute=15, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


async def _check_and_update() -> None:
    """Fetches origin, compares local HEAD to origin/master, and only calls
    perform_update() if they actually differ. Never raises — a failed check
    must not crash the loop; it just tries again at the next scheduled run."""
    try:
        loop = asyncio.get_event_loop()

        def _git(args, timeout=60):
            return subprocess.run(
                ["git"] + args, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=timeout,
                cwd=REPO_ROOT, env=_child_env(),
            )

        fetch = await loop.run_in_executor(None, lambda: _git(["fetch", "origin"]))
        if fetch.returncode != 0:
            print(f"[updater] auto-update check: git fetch failed: {(fetch.stderr or '').strip()[:200]}")
            return

        local = await loop.run_in_executor(None, lambda: _git(["rev-parse", "HEAD"], timeout=10))
        remote = await loop.run_in_executor(None, lambda: _git(["rev-parse", "origin/master"], timeout=10))
        local_hash = local.stdout.strip()
        remote_hash = remote.stdout.strip()
        if not local_hash or not remote_hash:
            print("[updater] auto-update check: couldn't determine local/remote HEAD, skipping")
            return
        if local_hash == remote_hash and not _state.get("last_error"):
            return  # already up to date AND last attempt was clean — most days, this is the only line that runs

        if local_hash == remote_hash:
            # git is already at the latest commit (it advances before pip/npm
            # run, so a failed dependency install can't be undone by a retry
            # of THIS step) — but the previous attempt left last_error set,
            # so retry the install steps anyway instead of silently giving up
            # forever just because there's no new commit to react to.
            print(f"[updater] auto-update: retrying after previous failure ({_state['last_error']})")
        else:
            print(f"[updater] auto-update: {local_hash[:12]} -> {remote_hash[:12]}, updating now")
        await perform_update(restart_supervisor=True)
    except Exception as e:
        print(f"[updater] auto-update check error: {type(e).__name__}: {e}")


async def _auto_update_loop():
    while True:
        try:
            now = datetime.utcnow()
            sleep_sec = max(1.0, (_next_daily_run(now, AUTO_UPDATE_HOUR) - now).total_seconds())
            await asyncio.sleep(sleep_sec)
            await _check_and_update()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[updater] auto-update loop error: {e}")


def start_auto_update():
    global _auto_update_task
    if not AUTO_UPDATE_ENABLED:
        return
    if _auto_update_task is None or _auto_update_task.done():
        loop = asyncio.get_event_loop()
        _auto_update_task = loop.create_task(_auto_update_loop())


def stop_auto_update():
    global _auto_update_task
    if _auto_update_task and not _auto_update_task.done():
        _auto_update_task.cancel()
        _auto_update_task = None


if __name__ == "__main__":
    # Manual CLI: python -m services.updater
    async def main():
        ok, logs = await perform_update(restart_supervisor=False)
        print("\n".join(logs))
        sys.exit(0 if ok else 1)
    asyncio.run(main())
