"""
Bulk actions over several Mikrotik devices at once: run a script, reboot, or
upgrade RouterOS — the "Akcje zbiorcze" tab.

  - script  : RouterOS CLI lines, run over SSH on every selected device in
              parallel (a few at a time). One line = one complete command
              (RouterOS prints failures into the output, so success is judged
              from the text).
  - reboot  : REST POST /system/reboot, falling back to SSH.
  - upgrade : the existing firmware.upgrade_device() (optional backup first,
              wait for the device to come back), strictly one device at a time.

Each run is stored locally (FleetActionRun) with per-device results that the
UI polls while it progresses. Safeguards: a reason is mandatory, the target
list is capped, the script is size-limited, factory-reset commands are
refused, and nothing here is reachable from Central — only action, device
count and reason are reported there (the script itself can hold secrets).

A run that was in flight when the agent restarted can't be resumed; it is
shown as "interrupted" instead of "running" forever.
"""
import asyncio
import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, Credential, FleetActionRun
from services.device_client import build_client
from services.mikrotik_client import MikrotikClient
from services import activity, firmware

ENABLED = os.environ.get("MIKROTIK_FLEET_ACTIONS_ENABLED", "1").strip().lower() not in ("0", "false", "no")
MAX_DEVICES = 50
MAX_SCRIPT_BYTES = 16_000
MAX_OUTPUT_CHARS = 20_000
CLI_TIMEOUT_SEC = 30
CONCURRENCY = 5
ACTIONS = ("script", "reboot", "upgrade")

# Wiping the configuration on a whole selection by a typo is not something a
# bulk tool should allow — do that one device at a time, in Winbox.
_FORBIDDEN = re.compile(r"reset-configuration|/system\s+reset|/system\s+default-configuration", re.I)
_ERROR_MARKERS = re.compile(
    r"^(failure:|syntax error|expected |bad command name|no such item|invalid value|not enough permissions|input does not match)",
    re.I | re.M)

_active: set = set()
_write_lock = asyncio.Lock()


# ── Validation ───────────────────────────────────────────────────────────────

def script_lines(script: str) -> List[str]:
    """One command per line; blank lines and #-comments dropped; a trailing
    backslash joins the next line (RouterOS line continuation)."""
    lines, buf = [], ""
    for raw in (script or "").splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        lines.append((buf + line).strip())
        buf = ""
    if buf.strip():
        lines.append(buf.strip())
    return lines


def validate(action: str, device_ids: List[int], reason: str, script: Optional[str]) -> None:
    if not ENABLED:
        raise PermissionError("bulk actions are disabled (MIKROTIK_FLEET_ACTIONS_ENABLED=0)")
    if action not in ACTIONS:
        raise ValueError("unknown action")
    if not device_ids:
        raise ValueError("no devices selected")
    if len(set(device_ids)) > MAX_DEVICES:
        raise ValueError(f"at most {MAX_DEVICES} devices per run")
    if len((reason or "").strip()) < 3:
        raise ValueError("reason required")
    if action == "script":
        if not (script or "").strip():
            raise ValueError("script is empty")
        if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
            raise ValueError("script too large")
        if not script_lines(script):
            raise ValueError("script contains only comments")
        if _FORBIDDEN.search(script):
            raise ValueError("factory-reset commands are not allowed in bulk runs")


# ── Per-device execution ─────────────────────────────────────────────────────

def _load(device_id: int):
    with SessionLocal() as db:
        row = db.execute(select(Device, Credential).join(Credential, Device.credential_id == Credential.id)
                         .where(Device.id == device_id)).one_or_none()
    if not row:
        return None, None
    device, cred = row
    if (device.vendor or "mikrotik").lower() != "mikrotik":
        return device, None
    try:
        client = build_client(device, cred)
    except Exception:
        return device, None
    return device, client if isinstance(client, MikrotikClient) else None


def judge_output(output: str) -> Optional[str]:
    """RouterOS reports failures in the text — returns the first offending
    line, or None when nothing looks like an error."""
    m = _ERROR_MARKERS.search(output or "")
    if not m:
        return None
    line_start = output.rfind("\n", 0, m.start()) + 1
    line_end = output.find("\n", m.start())
    return output[line_start: line_end if line_end != -1 else len(output)].strip()[:300]


async def _run_script(device, client, lines: List[str]) -> dict:
    try:
        out = await asyncio.wait_for(client.run_cli(lines, ssh_port=device.ssh_port or 22, timeout_sec=CLI_TIMEOUT_SEC),
                                     timeout=CLI_TIMEOUT_SEC * (len(lines) + 1))
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}
    bad = judge_output(out)
    return {"status": "error" if bad else "ok", "output": out[:MAX_OUTPUT_CHARS], "error": bad}


async def _went_offline(client) -> bool:
    """After an ambiguous failure of the reboot request: did the device really
    stop answering (= it is rebooting) or is it still up (= nothing happened)?"""
    await asyncio.sleep(5)
    try:
        await asyncio.wait_for(client.get_resource(), timeout=4)
        return False
    except Exception:
        return True


async def _reboot(device, client) -> dict:
    import aiohttp
    try:
        await client.rest_post("system/reboot")
        return {"status": "ok", "output": "REST /system/reboot sent"}
    except Exception as e:
        # The device may drop the connection as it goes down — but "cannot
        # connect" and timeouts also look like that, so an ambiguous failure
        # only counts as success if the device then really stops answering.
        ambiguous = (isinstance(e, (aiohttp.ServerDisconnectedError, asyncio.TimeoutError))
                     or (isinstance(e, aiohttp.ClientOSError) and not isinstance(e, aiohttp.ClientConnectorError)))
        if ambiguous and await _went_offline(client):
            return {"status": "ok", "output": "REST /system/reboot sent (device went offline)"}
    try:
        out = await asyncio.wait_for(client.run_cli(["/system reboot"], ssh_port=device.ssh_port or 22, timeout_sec=15), timeout=30)
        if await _went_offline(client):
            return {"status": "ok", "output": ("SSH: " + out)[:MAX_OUTPUT_CHARS] or "SSH /system reboot sent"}
        return {"status": "error", "error": "reboot command sent but the device is still answering", "output": out[:MAX_OUTPUT_CHARS]}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}

UPDATE_CHANNELS = ("stable", "long-term", "testing", "development")


async def _upgrade(device, client, backup: bool, channel: Optional[str]) -> dict:
    device_id = device.id
    if channel:
        try:
            await client.set_update_channel(channel)
        except Exception as e:
            return {"status": "error", "error": f"could not set update channel to {channel}: {type(e).__name__}: {e}"}
    # Ask the device (it knows its own architecture and channel): nothing to do
    # means no download and, above all, no pointless reboot. If the check
    # itself fails we fall through to the upgrade, as before.
    st = await client.get_package_update_status()
    if st and (st.get("status") or "").lower().startswith("system is already up to date"):
        return {"status": "ok", "output": f"already up to date ({st.get('installed')}, channel {st.get('channel')}) - nothing to do"}
    res = await firmware.upgrade_device(device_id, do_backup=backup)
    log = "\n".join(firmware.get_job_status(device_id).get("log", []))
    if res.get("ok"):
        return {"status": "ok", "output": f"{res.get('old')} -> {res.get('new')}\n{log}"[:MAX_OUTPUT_CHARS]}
    return {"status": "error", "error": res.get("error") or "upgrade failed", "output": log[:MAX_OUTPUT_CHARS]}


# ── Runs ─────────────────────────────────────────────────────────────────────

async def _set_result(run_id: int, device_id: int, **fields) -> None:
    async with _write_lock:
        with SessionLocal() as db:
            run = db.get(FleetActionRun, run_id)
            results = json.loads(run.results or "{}")
            cur = results.setdefault(str(device_id), {})
            cur.update(fields)
            run.results = json.dumps(results)
            db.commit()


async def _execute(run_id: int, action: str, device_ids: List[int], lines: List[str], backup: bool,
                   channel: Optional[str] = None, stop_on_failure: bool = False) -> None:
    sem = asyncio.Semaphore(CONCURRENCY)

    async def _one(did: int):
        async with sem if action != "upgrade" else _NullCtx():
            await _set_result(run_id, did, status="running", started_at=datetime.now().isoformat())
            try:
                device, client = _load(did)
                if client is None:
                    res = {"status": "skipped", "error": "not a Mikrotik device with a stored credential"}
                elif action == "script":
                    res = await _run_script(device, client, lines)
                elif action == "reboot":
                    res = await _reboot(device, client)
                else:
                    res = await _upgrade(device, client, backup, channel)
            except Exception as e:
                res = {"status": "error", "error": f"{type(e).__name__}: {e}"}
            await _set_result(run_id, did, finished_at=datetime.now().isoformat(), **res)
            return res

    try:
        if action == "upgrade":
            for i, did in enumerate(device_ids):   # strictly one at a time, in the given order
                res = await _one(did)
                if stop_on_failure and res.get("status") == "error":
                    for later in device_ids[i + 1:]:
                        await _set_result(run_id, later, status="skipped", error="stopped after an earlier device failed")
                    break
        else:
            await asyncio.gather(*[_one(d) for d in device_ids])
    finally:
        _active.discard(run_id)
        with SessionLocal() as db:
            run = db.get(FleetActionRun, run_id)
            if run:
                run.status, run.finished_at = "done", datetime.now()
                db.commit()


class _NullCtx:
    async def __aenter__(self): return None
    async def __aexit__(self, *a): return False


def start_run(action: str, device_ids: List[int], reason: str, script: Optional[str], backup: bool, created_by: str,
              channel: Optional[str] = None, stop_on_failure: bool = False, group_id: Optional[int] = None,
              trigger: str = "manual") -> int:
    validate(action, device_ids, reason, script)
    if channel is not None and channel not in UPDATE_CHANNELS:
        raise ValueError("unknown update channel")
    ids = list(dict.fromkeys(int(i) for i in device_ids))
    names: Dict[int, dict] = {}
    with SessionLocal() as db:
        for d in db.execute(select(Device).where(Device.id.in_(ids))).scalars().all():
            names[d.id] = {"name": d.identity or d.name or d.ip, "ip": d.ip}
        missing = [i for i in ids if i not in names]
        if missing:
            raise ValueError(f"unknown device ids: {missing}")
        run = FleetActionRun(
            action=action, reason=reason.strip(), script=script if action == "script" else None,
            options=json.dumps({"backup": bool(backup), "channel": channel, "stop_on_failure": bool(stop_on_failure),
                                "group_id": group_id, "trigger": trigger}) if action == "upgrade" else None,
            created_by=created_by, status="running",
            results=json.dumps({str(i): {**names[i], "status": "queued"} for i in ids}))
        db.add(run)
        db.commit()
        run_id = run.id
    try:
        # Central's activity log gets the fact, the size and the reason — never the script.
        activity.record("fleet_action", action=action, devices=len(ids), reason=reason.strip()[:200], by=created_by)
    except Exception as e:
        print(f"[fleet_actions] activity record error: {e}")
    _active.add(run_id)
    asyncio.get_event_loop().create_task(_execute(
        run_id, action, ids, script_lines(script) if action == "script" else [], backup, channel, stop_on_failure))
    return run_id


def _to_dict(run: FleetActionRun, with_results: bool) -> dict:
    status = run.status
    if status == "running" and run.id not in _active:
        status = "interrupted"             # in flight when the agent restarted; cannot be resumed
    results = json.loads(run.results or "{}")
    counts: Dict[str, int] = {}
    for r in results.values():
        counts[r.get("status", "queued")] = counts.get(r.get("status", "queued"), 0) + 1
    out = {
        "id": run.id, "action": run.action, "reason": run.reason, "created_by": run.created_by, "status": status,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "devices": len(results), "counts": counts,
    }
    if with_results:
        out["script"] = run.script
        out["options"] = json.loads(run.options) if run.options else None
        out["results"] = results
    return out


def list_runs(limit: int = 30) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(FleetActionRun).order_by(FleetActionRun.id.desc()).limit(max(1, min(limit, 100)))).scalars().all()
        return [_to_dict(r, False) for r in rows]


def get_run(run_id: int) -> dict:
    with SessionLocal() as db:
        run = db.get(FleetActionRun, run_id)
        if not run:
            raise LookupError("run not found")
        return _to_dict(run, True)
