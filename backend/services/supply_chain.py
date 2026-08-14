"""
Supply-chain vulnerability scan — weekly `pip-audit` (backend/requirements.txt)
and `npm audit` (frontend/package.json) run, cached in memory.

Deliberately NOT a DB table: this is a point-in-time snapshot of exactly two
ecosystems (our own dependency manifests), not a growing per-host inventory
like services/vuln_scan.py — the last run's result is all that's ever needed,
so an in-memory cache plus a timestamp is enough.

Findings from the two tools are NOT the same shape (pip-audit gives an
advisory id + CVE aliases + fix versions but no severity; npm audit gives a
severity, a title, and a GitHub advisory URL but no CVE id directly) — kept
as two separate lists rather than forced into one lossy common shape, same
"don't paper over provider-shaped differences" approach as vuln_scan.py's
NVD/vulners merge.
"""
import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from typing import Optional

from services import updater as updater_svc

SCAN_DAY = int(os.environ.get("MIKROTIK_SUPPLYCHAIN_DAY", "6"))    # 0=Mon..6=Sun, default Sunday
SCAN_HOUR = int(os.environ.get("MIKROTIK_SUPPLYCHAIN_HOUR", "4"))  # after vuln_scan (2:00) + agent_backup (3:00)

REQUIREMENTS_PATH = os.path.join(updater_svc.REPO_ROOT, "backend", "requirements.txt")
FRONTEND_DIR = os.path.join(updater_svc.REPO_ROOT, "frontend")

_state = {
    "last_run": None,
    "last_error": None,
    "in_progress": False,
    "pip": {"ok": None, "error": None, "findings": [], "skipped": []},
    "npm": {"ok": None, "error": None, "findings": [], "summary": None},
}
_task: Optional[asyncio.Task] = None


def status() -> dict:
    now = datetime.utcnow()
    return {
        **_state,
        "scan_day": SCAN_DAY,
        "scan_hour": SCAN_HOUR,
        "next_run_estimated": _next_run_datetime(now).timestamp(),
    }


def _next_run_datetime(now: datetime) -> datetime:
    days_ahead = (SCAN_DAY - now.weekday()) % 7
    candidate = (now + timedelta(days=days_ahead)).replace(
        hour=SCAN_HOUR, minute=0, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


def _run_pip_audit_sync() -> dict:
    """Blocking — call via run_in_executor. Returns {"ok", "error", "findings", "skipped"}."""
    if not os.path.isfile(REQUIREMENTS_PATH):
        return {"ok": False, "error": "requirements.txt not found", "findings": [], "skipped": []}
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json",
           "-r", REQUIREMENTS_PATH, "--aliases"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                            cwd=updater_svc.REPO_ROOT, env=updater_svc._child_env())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "pip-audit timed out after 300s", "findings": [], "skipped": []}
    except FileNotFoundError:
        return {"ok": False, "error": "pip-audit not installed (pip install pip-audit)", "findings": [], "skipped": []}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "findings": [], "skipped": []}

    # pip-audit exits non-zero when it finds vulnerabilities OR on a hard
    # error — the only reliable way to tell them apart is whether stdout
    # actually parses as its JSON report shape (dependencies/fixes keys).
    try:
        report = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        err = (r.stderr or r.stdout or "unknown pip-audit failure").strip()
        return {"ok": False, "error": err[-500:], "findings": [], "skipped": []}

    findings = []
    skipped = []
    for dep in report.get("dependencies", []):
        if "skip_reason" in dep:
            skipped.append({"name": dep.get("name"), "reason": dep.get("skip_reason")})
            continue
        for vuln in dep.get("vulns", []):
            findings.append({
                "package": dep.get("name"),
                "version": dep.get("version"),
                "id": vuln.get("id"),
                "aliases": vuln.get("aliases", []),
                "fix_versions": vuln.get("fix_versions", []),
            })
    return {"ok": True, "error": None, "findings": findings, "skipped": skipped}


def _run_npm_audit_sync() -> dict:
    """Blocking — call via run_in_executor. Returns {"ok", "error", "findings", "summary"}."""
    if not os.path.isfile(os.path.join(FRONTEND_DIR, "package.json")):
        return {"ok": False, "error": "frontend/package.json not found", "findings": [], "summary": None}
    npm = updater_svc._npm_cmd()
    cmd = [npm, "audit", "--json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                            cwd=FRONTEND_DIR, env=updater_svc._child_env())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "npm audit timed out after 120s", "findings": [], "summary": None}
    except FileNotFoundError:
        return {"ok": False, "error": "npm not found on PATH", "findings": [], "summary": None}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "findings": [], "summary": None}

    # npm audit exits non-zero whenever vulnerabilities are found (not just on
    # a real error) — same "parse first, trust exit code second" approach as
    # pip-audit above.
    try:
        report = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        err = (r.stderr or r.stdout or "unknown npm audit failure").strip()
        return {"ok": False, "error": err[-500:], "findings": [], "summary": None}

    findings = []
    for name, v in report.get("vulnerabilities", {}).items():
        # `via` entries are "provider-shaped": either a full advisory dict, or
        # just a bare dependency-name string when the vuln is inherited
        # transitively — defensive per-entry handling, same style as the
        # vulners.audit parsing in vuln_scan.py.
        title = None
        url = None
        for via in v.get("via", []):
            if isinstance(via, dict):
                title = via.get("title")
                url = via.get("url")
                break
        findings.append({
            "package": name,
            "severity": v.get("severity"),
            "title": title,
            "url": url,
            "range": v.get("range"),
            "is_direct": v.get("isDirect"),
            "fix_available": bool(v.get("fixAvailable")),
        })
    summary = report.get("metadata", {}).get("vulnerabilities")
    return {"ok": True, "error": None, "findings": findings, "summary": summary}


async def run_scan() -> dict:
    """Runs both audits. One tool failing never blocks the other — same
    fail-isolated philosophy as vuln_scan.py's NVD/vulners merge."""
    if _state["in_progress"]:
        return {"ok": False, "error": "a scan is already in progress"}

    _state["in_progress"] = True
    try:
        loop = asyncio.get_event_loop()
        pip_result, npm_result = await asyncio.gather(
            loop.run_in_executor(None, _run_pip_audit_sync),
            loop.run_in_executor(None, _run_npm_audit_sync),
        )
        _state["pip"] = pip_result
        _state["npm"] = npm_result
        _state["last_run"] = datetime.utcnow().isoformat()
        _state["last_error"] = None
        if not pip_result["ok"] and not npm_result["ok"]:
            _state["last_error"] = f"pip: {pip_result['error']} | npm: {npm_result['error']}"
        return {"ok": True, "pip": pip_result, "npm": npm_result}
    finally:
        _state["in_progress"] = False


async def _loop():
    while True:
        try:
            now = datetime.utcnow()
            sleep_sec = max(1.0, (_next_run_datetime(now) - now).total_seconds())
            await asyncio.sleep(sleep_sec)
            await run_scan()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[supply_chain] loop error: {e}")


def start():
    global _task
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None
