"""
"What needs attention" for Hyper-V — computed from what services/hyperv_manage.py
already persisted (HypervHost / HypervVM / HypervSample), no host contact. The
same list feeds the Problems card of the dashboard, the VM flags in the tiles,
Central's copy and (for the kinds in hyperv_manage.INSIGHT_EVENTS) the alert
events, so there is one definition of "a problem" and one place to tune it.

Each insight: key (unique, stable: kind + host id + VM name), kind, severity
("high" | "medium" | "low"), the host and (for VM-level kinds) the VM, a short
English text (used in alert details), and params — the figures the UI puts into
its own translated sentence for that kind.

A host that has stopped answering gets one "host_unreachable" and nothing else:
the figures of its VMs are stale and would only add noise.
"""
import os
from datetime import datetime, timedelta
from typing import List

from sqlalchemy import select, func

from models.database import HypervHost, HypervVM, HypervSample, WindowsHost

HOST_DOWN_AFTER_FAILS = 2
MEM_HIGH_PCT = float(os.environ.get("MIKROTIK_HYPERV_HOST_MEM_PCT", "90"))
CPU_HIGH_PCT = float(os.environ.get("MIKROTIK_HYPERV_HOST_CPU_PCT", "90"))
STORAGE_LOW_PCT = float(os.environ.get("MIKROTIK_HYPERV_STORAGE_FREE_PCT", "15"))
VCPU_RATIO = float(os.environ.get("MIKROTIK_HYPERV_VCPU_RATIO", "4"))
SNAPSHOT_DAYS = float(os.environ.get("MIKROTIK_HYPERV_SNAPSHOT_DAYS", "7"))
OFF_DAYS = float(os.environ.get("MIKROTIK_HYPERV_OFF_DAYS", "30"))
IDLE_CPU_PCT = float(os.environ.get("MIKROTIK_HYPERV_IDLE_CPU_PCT", "3"))
IDLE_MIN_HOURS = 48
VM_CPU_HIGH_PCT = float(os.environ.get("MIKROTIK_HYPERV_VM_CPU_PCT", "90"))
VM_MEM_PRESSURE = 0.95            # demand / assigned
BOOT_GRACE_SEC = 300              # a VM that just started has no heartbeat yet

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_BAD_HEARTBEAT = ("NoContact", "LostCommunication")


def vm_tile(state, severities) -> str:
    """Colour class of a VM tile: crit (red) / warn (amber) / ok (green) / off (grey). `severities` are
    those of the insights that concern this VM."""
    if (state or "").endswith("Critical") or "high" in severities:
        return "crit"
    if state == "Running":
        return "warn" if "medium" in severities else "ok"
    return "off" if state == "Off" else "warn"


def _gb(b) -> float:
    return round((b or 0) / 1024 ** 3, 1)


def compute(db) -> List[dict]:
    now = datetime.utcnow()
    out: List[dict] = []

    hosts = db.execute(
        select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
        .where(HypervHost.last_status != "not_hyperv")
    ).all()
    if not hosts:
        return out

    # one grouped query each, not one per VM
    recent = {r[0]: (r[1], r[2]) for r in db.execute(
        select(HypervSample.ref_id, func.avg(HypervSample.cpu_pct), func.count(HypervSample.cpu_pct))
        .where(HypervSample.kind == "vm", HypervSample.ts >= now - timedelta(minutes=16), HypervSample.cpu_pct.is_not(None))
        .group_by(HypervSample.ref_id)).all()}
    longterm = {r[0]: (r[1], r[2], r[3]) for r in db.execute(
        select(HypervSample.ref_id, func.avg(HypervSample.cpu_pct), func.min(HypervSample.ts), func.count(HypervSample.cpu_pct))
        .where(HypervSample.kind == "vm", HypervSample.ts >= now - timedelta(days=7), HypervSample.cpu_pct.is_not(None))
        .group_by(HypervSample.ref_id)).all()}

    for hv, host in hosts:
        hname = host.hostname or host.ip

        def add(kind, severity, text, vm=None, **params):
            out.append({
                "key": f"{kind}:{hv.id}:{vm or ''}", "kind": kind, "severity": severity,
                "hyperv_host_id": hv.id, "windows_host_id": host.id, "host": hname, "vm": vm,
                "text": text, "params": params,
            })

        if hv.last_status == "error" and (hv.fail_streak or 0) >= HOST_DOWN_AFTER_FAILS:
            add("host_unreachable", "high", f"{hname}: Hyper-V host not answering ({hv.fail_streak} polls in a row)",
                polls=hv.fail_streak or 0, error=(hv.last_error or "")[:200])
            continue

        if hv.mem_used_pct is not None and hv.mem_used_pct >= MEM_HIGH_PCT:
            add("host_memory_high", "high", f"{hname}: host memory {hv.mem_used_pct:.0f}% used", pct=round(hv.mem_used_pct))
        if hv.cpu_used_pct is not None and hv.cpu_used_pct >= CPU_HIGH_PCT:
            add("host_cpu_high", "medium", f"{hname}: host CPU {hv.cpu_used_pct:.0f}% busy", pct=round(hv.cpu_used_pct))
        if hv.storage_total_bytes and hv.storage_free_bytes is not None:
            free_pct = hv.storage_free_bytes / hv.storage_total_bytes * 100
            if free_pct <= STORAGE_LOW_PCT:
                add("host_storage_low", "high" if free_pct <= STORAGE_LOW_PCT / 2 else "medium",
                    f"{hname}: only {free_pct:.0f}% free on the VM storage volume ({_gb(hv.storage_free_bytes)} GB)",
                    free_pct=round(free_pct), free_gb=_gb(hv.storage_free_bytes))

        vms = db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv.id)).scalars().all()
        running = [v for v in vms if v.state == "Running"]
        vcpu = sum(v.vcpu_count or 0 for v in running)
        if hv.logical_processor_count and vcpu / hv.logical_processor_count > VCPU_RATIO:
            ratio = vcpu / hv.logical_processor_count
            add("host_cpu_overcommit", "medium", f"{hname}: {vcpu} vCPUs on {hv.logical_processor_count} logical CPUs ({ratio:.1f}:1)",
                vcpu=vcpu, lp=hv.logical_processor_count, ratio=round(ratio, 1))

        for v in vms:
            state = v.state or ""
            if state.endswith("Critical"):
                add("vm_critical_state", "high", f"{hname}: VM {v.name} is in a critical state ({state})", vm=v.name, state=state)
            if state == "Running":
                if (v.heartbeat or "") in _BAD_HEARTBEAT and (v.uptime_sec or 0) > BOOT_GRACE_SEC:
                    add("vm_no_heartbeat", "high", f"{hname}: VM {v.name} is running but the guest does not answer ({v.heartbeat})",
                        vm=v.name, heartbeat=v.heartbeat)
                if v.dynamic_memory is not False and v.memory_assigned_bytes and v.memory_demand_bytes is not None \
                        and v.memory_demand_bytes / v.memory_assigned_bytes >= VM_MEM_PRESSURE:
                    add("vm_memory_pressure", "medium", f"{hname}: VM {v.name} wants nearly all the memory it has",
                        vm=v.name, demand_gb=_gb(v.memory_demand_bytes), assigned_gb=_gb(v.memory_assigned_bytes))
                r = recent.get(v.id)
                if r and r[1] >= 2 and r[0] is not None and r[0] >= VM_CPU_HIGH_PCT:
                    add("vm_cpu_high", "medium", f"{hname}: VM {v.name} CPU {r[0]:.0f}% for the last 15 minutes", vm=v.name, pct=round(r[0]))
                lt = longterm.get(v.id)
                if lt and lt[1] and (now - lt[1]).total_seconds() >= IDLE_MIN_HOURS * 3600 and lt[0] is not None and lt[0] < IDLE_CPU_PCT:
                    add("vm_idle", "low", f"{hname}: VM {v.name} averaged {lt[0]:.1f}% CPU over the last days", vm=v.name, avg=round(lt[0], 1))
            elif state in ("Off", "Saved", "Paused") and v.state_since and (now - v.state_since).total_seconds() >= OFF_DAYS * 86400:
                days = int((now - v.state_since).total_seconds() // 86400)
                add("vm_off_long", "low", f"{hname}: VM {v.name} has been {state.lower()} for {days} days", vm=v.name, state=state, days=days)

            if v.oldest_snapshot_at and (v.snapshot_count or 0) > 0:
                age = (now - v.oldest_snapshot_at).total_seconds() / 86400
                if age >= SNAPSHOT_DAYS:
                    add("vm_snapshot_old", "high" if age >= 30 else "medium",
                        f"{hname}: VM {v.name} has a checkpoint {int(age)} days old ({v.snapshot_count} in total)",
                        vm=v.name, days=int(age), count=v.snapshot_count)
            health = v.replication_health or ""
            if health in ("Critical", "Warning") or (v.replication_state or "") in ("Error", "Suspended", "ResynchronizeSuspended"):
                add("vm_replication", "high" if health == "Critical" or v.replication_state == "Error" else "medium",
                    f"{hname}: VM {v.name} replication {health or v.replication_state}", vm=v.name,
                    health=health, state=v.replication_state)

    out.sort(key=lambda i: (_SEVERITY_ORDER[i["severity"]], i["host"], i["vm"] or "", i["kind"]))
    return out
