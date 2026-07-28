"""
Self-updater — runs git pull + npm build + exits cleanly so the supervisor
(systemd on Linux, NSSM on Windows) auto-restarts the process with new code.

Used both by scheduled command from central ("please update") and by manual
CLI: python -m services.updater.
"""
import asyncio
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


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
            capture_output=True, text=True, timeout=5, cwd=REPO_ROOT,
        )
        if r.returncode == 0:
            info["commit"] = r.stdout.strip()
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            capture_output=True, text=True, timeout=5, cwd=REPO_ROOT,
        )
        if r.returncode == 0 and r.stdout.strip().isdigit():
            info["commit_time"] = int(r.stdout.strip())
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5, cwd=REPO_ROOT,
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


def _run(cmd, log, cwd, timeout=300) -> int:
    """Run a subprocess capturing stdout/stderr into log list. Returns exit code."""
    label = " ".join(cmd)
    log.append(f"$ {label}")
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
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
        if _run(["git", "fetch", "origin"], log, cwd=REPO_ROOT) != 0:
            _state["last_error"] = "git fetch failed"
            return False, log

        # 2. git reset to origin/master (blows away local drift)
        if _run(["git", "reset", "--hard", "origin/master"], log, cwd=REPO_ROOT) != 0:
            _state["last_error"] = "git reset failed"
            return False, log

        # 3. Optional: install python deps if requirements.txt changed
        # Use current interpreter (works with venv too)
        req_path = os.path.join(REPO_ROOT, "backend", "requirements.txt")
        if os.path.exists(req_path):
            _run([sys.executable, "-m", "pip", "install",
                  "-r", req_path, "--quiet"], log, cwd=REPO_ROOT, timeout=600)

        # 4. npm install + build
        frontend = os.path.join(REPO_ROOT, "frontend")
        npm = _npm_cmd()
        if _run([npm, "install", "--no-audit", "--no-fund"], log, cwd=frontend, timeout=600) != 0:
            _state["last_error"] = "npm install failed"
            return False, log
        if _run([npm, "run", "build"], log, cwd=frontend, timeout=600) != 0:
            _state["last_error"] = "npm build failed"
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


if __name__ == "__main__":
    # Manual CLI: python -m services.updater
    async def main():
        ok, logs = await perform_update(restart_supervisor=False)
        print("\n".join(logs))
        sys.exit(0 if ok else 1)
    asyncio.run(main())
