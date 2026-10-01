"""
Hyper-V host/VM inventory + basic alerting — WinRM into hosts already known
via services/windows_manage.py (managed=True WindowsHost rows), reusing its
exact session/credential helpers. Not a new discovery path: any managed
Windows host might or might not actually run Hyper-V, found out the same
way the data is collected (one WinRM+PowerShell round trip does double
duty — Get-VM simply errors out on a host without the Hyper-V PowerShell
module, which this module tells apart from a real failure).

Host-level CPU/memory utilization is deliberately NOT duplicated here —
windows_manage.py's own resource check already collects it from the OS
view (Win32_Processor/Win32_OperatingSystem), which already accounts for
VM resource consumption on the root partition. This module adds only what
that one doesn't have: Hyper-V host capacity (logical processors, total
memory) and the per-VM inventory (state/CPU/memory/heartbeat).

Split into a slow write path and a fast read path, mirroring resource_
monitor.py's own Linux/Windows disk+memory design exactly (see that
module's docstring for the full reasoning): refresh_managed_hyperv_hosts()
does the actual WinRM polling on resource_monitor.py's existing slow loop
(MIKROTIK_RESOURCE_CHECK_MIN, default 30 min — alongside windows_manage's
own resource refresh, same WinRM session cost already being paid that
cycle) and persists raw state; collect_hyperv_events() is the cheap,
DB-only diff called every ~2 min from uplink.py's _build_snapshot(), using
the exact state-file pattern copied from tunnel_monitor.py/edge_discovery.py
(self-dedup, never pruned on a transient miss) to detect a VM's
Running<->not-Running transition without a second WinRM round trip.
"""
import asyncio
import json
import os
from datetime import datetime
from typing import Optional

from sqlalchemy import select

from models.database import SessionLocal, WindowsHost, HypervHost, HypervVM
from services import windows_manage as wm
from services import vuln_scan as vs
from services import activity

CHECK_TIMEOUT_SEC = wm.CHECK_TIMEOUT_SEC

_HYPERV_SCRIPT = r"""
$vms = @(Get-VM | Select-Object Name, State, Status, CPUUsage, MemoryAssigned, MemoryDemand, MemoryStartup, Heartbeat, @{N='UptimeSeconds';E={[int64]$_.Uptime.TotalSeconds}})
$vmHost = Get-VMHost | Select-Object LogicalProcessorCount, MemoryCapacity
[PSCustomObject]@{ Vms = $vms; Host = $vmHost } | ConvertTo-Json -Compress -Depth 4
"""

# Signature of "this host has no Hyper-V PowerShell module at all" (no
# Hyper-V role, or role present but the RSAT-style management cmdlets
# aren't installed) — distinguished from a real/transient failure so the
# expected majority of managed Windows hosts that simply aren't
# hypervisors never logs a scary error every refresh cycle.
_NOT_HYPERV_MARKERS = ("is not recognized as the name of a cmdlet", "CommandNotFoundException")


def _is_not_hyperv(error_text: str) -> bool:
    return any(m in error_text for m in _NOT_HYPERV_MARKERS)


def _check_hyperv_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Read-only Hyper-V cmdlets —
    needs the WinRM account to be in the target's local Hyper-V
    Administrators group (or Administrators), same requirement as any
    other Get-VM usage; no write/admin action beyond that is ever taken."""
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
    try:
        result = vs._run_ps_safe(session, _HYPERV_SCRIPT)
        stderr = result.std_err.decode("utf-8", errors="ignore")
        if _is_not_hyperv(stderr):
            return {"ok": False, "not_hyperv": True}
        if result.status_code != 0:
            return {"ok": False, "error": stderr[-2000:]}
        raw = result.std_out.decode("utf-8", errors="ignore").strip()
        if not raw:
            return {"ok": False, "error": "empty response"}
        try:
            parsed = json.loads(raw)
        except Exception as e:
            return {"ok": False, "error": f"couldn't parse Hyper-V JSON: {e}"}
        return {"ok": True, "parsed": parsed}
    finally:
        vs._close_winrm(session)


def _int_or_none(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _parse_hyperv(parsed: dict) -> dict:
    """Same defensive single-result quirk handling as windows_manage.
    _parse_resources: ConvertTo-Json renders a lone result as a bare
    object, not a 1-element array, when a host has exactly one VM."""
    vms_raw = parsed.get("Vms")
    if isinstance(vms_raw, dict):
        vms_raw = [vms_raw]
    vms = []
    for v in vms_raw or []:
        if not isinstance(v, dict) or not v.get("Name"):
            continue
        vms.append({
            "name": v["Name"],
            "state": v.get("State"),
            "status": v.get("Status"),
            "cpu_usage_pct": _int_or_none(v.get("CPUUsage")),
            "memory_assigned_bytes": _int_or_none(v.get("MemoryAssigned")),
            "memory_demand_bytes": _int_or_none(v.get("MemoryDemand")),
            "memory_startup_bytes": _int_or_none(v.get("MemoryStartup")),
            "uptime_sec": _int_or_none(v.get("UptimeSeconds")),
            "heartbeat": v.get("Heartbeat"),
        })

    host_raw = parsed.get("Host") or {}
    if isinstance(host_raw, list):  # defensive — Get-VMHost is always singular, but never trust it blindly
        host_raw = host_raw[0] if host_raw else {}

    return {
        "vms": vms,
        "logical_processor_count": _int_or_none(host_raw.get("LogicalProcessorCount")),
        "memory_capacity_bytes": _int_or_none(host_raw.get("MemoryCapacity")),
    }


async def check_hyperv_host(host_id: int) -> dict:
    """Polls one managed Windows host for Hyper-V data and persists it.
    Read-only aside from the agent's own DB. Never raises — always returns
    a dict with "ok" (or "error")."""
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host:
            return {"error": "host not found"}
        ip, port, hostname = host.ip, host.winrm_port, (host.hostname or host.ip)

    cred = wm._credential_for_host(host)
    if not cred:
        return {"error": "no credential configured"}
    username, password, domain = cred

    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _check_hyperv_sync, ip, port, username, password, domain),
            timeout=CHECK_TIMEOUT_SEC + 15,
        )
    except (asyncio.TimeoutError, TimeoutError):
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}

    now = datetime.utcnow()
    with SessionLocal() as db:
        hv_host = db.execute(
            select(HypervHost).where(HypervHost.windows_host_id == host_id)
        ).scalar_one_or_none()
        if not hv_host:
            hv_host = HypervHost(windows_host_id=host_id)
            db.add(hv_host)
            db.flush()

        if result.get("not_hyperv"):
            hv_host.last_status = "not_hyperv"
            hv_host.last_check_at = now
            db.commit()
            return {"ok": True, "not_hyperv": True}

        if not result.get("ok"):
            hv_host.last_status = "error"
            hv_host.last_error = result.get("error")
            hv_host.last_check_at = now
            db.commit()
            return {"error": result.get("error")}

        parsed = _parse_hyperv(result["parsed"])
        hv_host.last_status = "ok"
        hv_host.last_error = None
        hv_host.logical_processor_count = parsed["logical_processor_count"]
        hv_host.memory_capacity_bytes = parsed["memory_capacity_bytes"]
        hv_host.vm_count_total = len(parsed["vms"])
        hv_host.vm_count_running = sum(1 for v in parsed["vms"] if v["state"] == "Running")
        hv_host.last_check_at = now

        for v in parsed["vms"]:
            row = db.execute(
                select(HypervVM).where(HypervVM.hyperv_host_id == hv_host.id, HypervVM.name == v["name"])
            ).scalar_one_or_none()
            if not row:
                row = HypervVM(hyperv_host_id=hv_host.id, name=v["name"])
                db.add(row)
            row.state = v["state"]
            row.status = v["status"]
            row.cpu_usage_pct = v["cpu_usage_pct"]
            row.memory_assigned_bytes = v["memory_assigned_bytes"]
            row.memory_demand_bytes = v["memory_demand_bytes"]
            row.memory_startup_bytes = v["memory_startup_bytes"]
            row.uptime_sec = v["uptime_sec"]
            row.heartbeat = v["heartbeat"]
            row.last_seen_at = now
        db.commit()

    try:
        activity.record("hyperv_check", host_id=host_id, hostname=hostname, vm_count=len(parsed["vms"]))
    except Exception as e:
        print(f"[hyperv_manage] activity record error: {e}")
    return {"ok": True, "vm_count": len(parsed["vms"])}


async def refresh_managed_hyperv_hosts() -> dict:
    """Called from resource_monitor.py's own slow loop, alongside
    windows_manage.refresh_managed_hosts_resources() — same managed=True
    WindowsHost set, one extra WinRM round trip per host (cheap relative
    to the session already being opened that cycle)."""
    with SessionLocal() as db:
        ids = [h.id for h in db.execute(
            select(WindowsHost).where(WindowsHost.managed == True)  # noqa: E712
        ).scalars().all()]
    checked = 0
    for host_id in ids:
        try:
            result = await check_hyperv_host(host_id)
            if result.get("ok"):
                checked += 1
        except Exception as e:
            print(f"[hyperv_manage] refresh error for host {host_id}: {e}")
    return {"checked": checked, "total": len(ids)}


# ── Fast path: event detection from already-persisted state ──────────────
# Exact state-file pattern copied from tunnel_monitor.py/edge_discovery.py —
# self-dedup (new status saved immediately after comparison), never pruned
# on a transient miss (a host that failed THIS particular 2-min read keeps
# its last-known VM states rather than losing history).

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "hyperv_state.json")


def _load_state() -> dict:
    if not os.path.exists(_STATE_PATH):
        return {}
    try:
        with open(_STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        tmp = _STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, _STATE_PATH)
    except Exception as e:
        print(f"[hyperv_manage] state save error: {e}")


async def collect_hyperv_events() -> list:
    """Cheap, DB-only diff against the state file — no WinRM call here,
    just reads whatever refresh_managed_hyperv_hosts() last persisted (up
    to RESOURCE_CHECK_MIN stale, same tradeoff as every other resource
    metric in this codebase). Only a Running<->not-Running transition is
    reported — distinguishing a graceful operator-initiated shutdown from
    a crash isn't attempted (same simplicity as device_rebooted elsewhere
    in this codebase not distinguishing planned vs unplanned reboots)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervVM, HypervHost, WindowsHost)
            .join(HypervHost, HypervVM.hyperv_host_id == HypervHost.id)
            .join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
        ).all()

    state = _load_state()
    events = []
    now_iso = datetime.utcnow().isoformat()

    for vm, hv_host, host in rows:
        key = f"{hv_host.id}:{vm.name}"
        prev_state = state.get(key)
        new_state = vm.state
        host_name = host.hostname or host.ip

        if prev_state is not None and prev_state != new_state:
            was_running = prev_state == "Running"
            now_running = new_state == "Running"
            if was_running and not now_running:
                event_type = "hyperv_vm_down"
            elif not was_running and now_running:
                event_type = "hyperv_vm_up"
            else:
                event_type = None  # e.g. Off -> Saved: neither edge we alert on
            if event_type:
                events.append({
                    "type": event_type, "device_name": f"{host_name}: {vm.name}",
                    "host_id": host.id, "vm_name": vm.name,
                    "from_state": prev_state, "to_state": new_state,
                    "count": 1, "detected_at": now_iso,
                })
                try:
                    activity.record(event_type, device_name=f"{host_name}: {vm.name}",
                                     from_state=prev_state, to_state=new_state)
                except Exception as e:
                    print(f"[hyperv_manage] activity record error: {e}")

        state[key] = new_state

    _save_state(state)
    return events


# ── Listing / admin (local agent UI) ──────────────────────────────────────

def list_hosts() -> list:
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .order_by(WindowsHost.ip)
        ).all()
        return [{
            "id": hv.id, "windows_host_id": host.id, "ip": host.ip, "hostname": host.hostname,
            "logical_processor_count": hv.logical_processor_count,
            "memory_capacity_bytes": hv.memory_capacity_bytes,
            "vm_count_total": hv.vm_count_total, "vm_count_running": hv.vm_count_running,
            "last_check_at": hv.last_check_at.isoformat() if hv.last_check_at else None,
            "last_status": hv.last_status, "last_error": hv.last_error,
        } for hv, host in rows if hv.last_status != "not_hyperv"]


def list_vms(hyperv_host_id: int) -> list:
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervVM).where(HypervVM.hyperv_host_id == hyperv_host_id).order_by(HypervVM.name)
        ).scalars().all()
        return [{
            "id": v.id, "name": v.name, "state": v.state, "status": v.status,
            "cpu_usage_pct": v.cpu_usage_pct,
            "memory_assigned_bytes": v.memory_assigned_bytes,
            "memory_demand_bytes": v.memory_demand_bytes,
            "memory_startup_bytes": v.memory_startup_bytes,
            "uptime_sec": v.uptime_sec, "heartbeat": v.heartbeat,
            "last_seen_at": v.last_seen_at.isoformat() if v.last_seen_at else None,
        } for v in rows]


def public_summary() -> list:
    """Redacted summary for the snapshot's plaintext envelope, mirroring
    linux_manage.py/windows_manage.py's own public_summary() exactly —
    host capacity + VM counts + the list of VMs NOT currently running
    (the one thing worth a glance from Central; a healthy VM list adds
    nothing an operator needs to see remotely)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .where(HypervHost.last_status == "ok")
        ).all()
        result = []
        for hv, host in rows:
            vms = db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv.id)).scalars().all()
            not_running = [v.name for v in vms if v.state != "Running"]
            result.append({
                "id": hv.id, "ip": host.ip, "hostname": host.hostname,
                "logical_processor_count": hv.logical_processor_count,
                "memory_capacity_bytes": hv.memory_capacity_bytes,
                "vm_count_total": hv.vm_count_total, "vm_count_running": hv.vm_count_running,
                "vms_not_running": not_running,
                "last_check_at": hv.last_check_at.isoformat() if hv.last_check_at else None,
            })
        return result
