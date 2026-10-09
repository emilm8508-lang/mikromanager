"""
Power / checkpoint actions on a Hyper-V VM — the only part of the Hyper-V
feature that WRITES to a host. Local only: unlike the Windows Update commands
there is deliberately no Central -> agent path for these, so nothing here
can be triggered from outside the agent's own (login + MFA) UI.

Gated by the same switch as the rest of Windows management (the agent's
"Zarządzanie Windows włączone" setting / MIKROTIK_WINDOWS_MANAGE_ENABLED), a
mandatory reason, and strict validation: the VM is addressed by its GUID, taken
from the database and checked against a pattern before it ever reaches a
script, and a checkpoint name is cut down to harmless characters — nothing the
operator types is spliced into PowerShell as code. Every action is logged
(HypervActionLog: who, which VM, why, outcome) and the host is re-polled
afterwards so the board shows the new state.

Actions: start · shutdown (graceful, through the guest's integration services) ·
poweroff (hard, like pulling the plug) · restart · checkpoint. Deleting VMs,
disks or checkpoints is not offered — that belongs in Hyper-V Manager.
"""
import asyncio
import re
from datetime import datetime
from typing import Optional

from sqlalchemy import select, update

from models.database import SessionLocal, WindowsHost, HypervHost, HypervVM, HypervActionLog
from services import windows_manage as wm
from services import vuln_scan as vs
from services import activity
from services import hyperv_manage

ACTION_TIMEOUT_SEC = 180
MAX_REASON = 500
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SNAP_BAD = re.compile(r"[^A-Za-z0-9 _.\-]")

# action -> (PowerShell body using $vm, which states the VM may be in for it to make sense)
_ACTIONS = {
    "start": "Start-VM -VM $vm -Confirm:$false",
    "shutdown": "Stop-VM -VM $vm -Confirm:$false",
    "poweroff": "Stop-VM -VM $vm -TurnOff -Force -Confirm:$false",
    "restart": "Restart-VM -VM $vm -Force -Confirm:$false",
    "checkpoint": "Checkpoint-VM -VM $vm -SnapshotName '{snap}' -Confirm:$false",
}
ACTION_NAMES = tuple(_ACTIONS)

_locks: dict = {}          # windows_host_id -> asyncio.Lock — one action at a time per host
_tasks: set = set()


def enabled() -> bool:
    return wm._manage_enabled()


def _snapshot_name(requested: Optional[str], vm_name: str) -> str:
    name = _SNAP_BAD.sub("", (requested or "").strip())[:64].strip()
    return name or f"MikroManager {datetime.now():%Y-%m-%d %H:%M}"


def build_script(action: str, guid: str, snapshot_name: Optional[str] = None) -> str:
    """The exact PowerShell that will run — pure, so it can be inspected and tested."""
    if action not in _ACTIONS:
        raise ValueError(f"unknown action: {action}")
    if not _GUID_RE.match(guid or ""):
        raise ValueError("invalid VM id")
    body = _ACTIONS[action]
    if action == "checkpoint":
        body = body.format(snap=_snapshot_name(snapshot_name, "").replace("'", "''"))
    return f"$ErrorActionPreference = 'Stop'\n$vm = Get-VM -Id '{guid}'\n{body}\n'OK'"


def _to_dict(r: HypervActionLog) -> dict:
    return {
        "id": r.id, "windows_host_id": r.windows_host_id, "host_name": r.host_name, "vm_name": r.vm_name, "action": r.action,
        "reason": r.reason, "created_by": r.created_by, "status": r.status, "output": r.output,
        "created_at": hyperv_manage._iso(r.created_at), "finished_at": hyperv_manage._iso(r.finished_at),
    }


def list_actions(limit: int = 50, vm_name: Optional[str] = None) -> list:
    with SessionLocal() as db:
        q = select(HypervActionLog).order_by(HypervActionLog.id.desc()).limit(max(1, min(limit, 200)))
        if vm_name:
            q = q.where(HypervActionLog.vm_name == vm_name)
        return [_to_dict(r) for r in db.execute(q).scalars().all()]


def get_action(action_id: int) -> dict:
    with SessionLocal() as db:
        r = db.get(HypervActionLog, action_id)
        if not r:
            raise LookupError("action not found")
        return _to_dict(r)


def mark_interrupted() -> None:
    """Called at startup: an action that was in flight when the agent stopped is not 'running' any more."""
    try:
        with SessionLocal() as db:
            db.execute(update(HypervActionLog).where(HypervActionLog.status == "running")
                       .values(status="error", output="interrupted (the agent was restarted)", finished_at=datetime.utcnow()))
            db.commit()
    except Exception as e:
        print(f"[hyperv_actions] mark_interrupted error: {e}")


def start_action(vm_id: int, action: str, reason: str, created_by: str, snapshot_name: Optional[str] = None) -> int:
    """Validates and queues one action; returns the log id (the work runs in the background). Raises
    PermissionError (switch off) or ValueError (bad input / unknown VM)."""
    if not enabled():
        raise PermissionError("Windows management is switched off on this agent (Zarządzanie Windows)")
    if action not in _ACTIONS:
        raise ValueError(f"unknown action: {action}")
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    if len(reason) > MAX_REASON:
        raise ValueError(f"reason is too long (max {MAX_REASON} characters)")
    with SessionLocal() as db:
        vm = db.get(HypervVM, vm_id)
        if not vm:
            raise ValueError("VM not found")
        if not vm.vm_guid or not _GUID_RE.match(vm.vm_guid):
            raise ValueError("this VM has no id yet - wait for the next poll")
        hv = db.get(HypervHost, vm.hyperv_host_id)
        host = db.get(WindowsHost, hv.windows_host_id) if hv else None
        if not host or not host.managed:
            raise ValueError("host not found or not managed")
        guid, vm_name, host_id, host_name = vm.vm_guid, vm.name, host.id, host.hostname or host.ip
        script = build_script(action, guid, snapshot_name)   # also validates the checkpoint name
        log = HypervActionLog(windows_host_id=host_id, host_name=host_name, vm_name=vm_name, vm_guid=guid, action=action,
                              reason=reason, created_by=created_by, status="running")
        db.add(log)
        db.commit()
        log_id = log.id

    task = asyncio.get_event_loop().create_task(_run(log_id, host_id, host_name, vm_name, action, reason, created_by, script))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return log_id


async def _run(log_id: int, host_id: int, host_name: str, vm_name: str, action: str, reason: str, created_by: str, script: str) -> None:
    lock = _locks.setdefault(host_id, asyncio.Lock())
    status, output = "error", ""
    async with lock:
        try:
            with SessionLocal() as db:
                host = db.get(WindowsHost, host_id)
            cred = wm._credential_for_host(host) if host else None
            if not cred:
                output = "no credential configured"
            else:
                username, password, domain = cred
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(vs._EXECUTOR, hyperv_manage._run_ps_sync, host.ip, host.winrm_port, username, password,
                                         domain, script, ACTION_TIMEOUT_SEC),
                    timeout=ACTION_TIMEOUT_SEC + 20)
                out = result.std_out.decode("utf-8", errors="ignore").strip()
                err = result.std_err.decode("utf-8", errors="ignore").strip()
                if result.status_code == 0 and out.endswith("OK"):
                    status, output = "ok", "OK"
                else:
                    output = (err or out or f"exit code {result.status_code}")[-2000:]
        except (asyncio.TimeoutError, TimeoutError):
            output = "timeout"
        except Exception as e:
            output = str(e)[-2000:]
        with SessionLocal() as db:
            r = db.get(HypervActionLog, log_id)
            if r:
                r.status, r.output, r.finished_at = status, output, datetime.utcnow()
                db.commit()
        try:
            activity.record("hyperv_vm_action", host_id=host_id, hostname=host_name, vm_name=vm_name, action=action,
                            reason=reason, by=created_by, status=status)
        except Exception as e:
            print(f"[hyperv_actions] activity record error: {e}")
        # show the new state on the board without waiting for the next scheduled poll
        try:
            await hyperv_manage.check_hyperv_host(host_id)
        except Exception as e:
            print(f"[hyperv_actions] re-poll error: {e}")
