"""
Hyper-V host/VM monitoring — WinRM into hosts already known via
services/windows_manage.py (managed=True WindowsHost rows), reusing its exact
session/credential helpers. Not a new discovery path: any managed Windows host
might or might not run Hyper-V, found out the same way the data is collected
(one WinRM+PowerShell round trip does double duty — Get-VM simply errors out on
a host without the Hyper-V PowerShell module, which this module tells apart
from a real failure and then re-checks only once a day).

One read-only poll per Hyper-V host (MIKROTIK_HYPERV_POLL_SEC, default 5 min —
its own loop, no longer tied to the 30-min generic resource refresh, which is
far too slow for a status board) collects, in a single round trip:
  host  — capacity (logical CPUs, memory), live CPU / memory load, free space of
          the VM storage volume, virtual switches, failover-cluster name;
  VMs   — state, vCPU, CPU, memory (assigned / demand / dynamic range), heartbeat,
          replication, checkpoints (count + oldest), disks (real vs. nominal
          size), IPs, switches.
It is persisted (HypervHost / HypervVM), a history sample per host and VM is
appended (HypervSample, trend charts + idle-VM detection), and VMs that no
longer exist on the host are removed.

Everything derived from that state lives elsewhere and reads the database only:
hyperv_insights.py (the "what needs attention" list), the alert events below
(collect_hyperv_events, a cheap diff called every ~2 min from uplink.py using
the state-file pattern of tunnel_monitor.py / edge_discovery.py — self-dedup,
never pruned on a transient miss) and public_summary() (the redacted copy
for Central). Writing to a VM (start / stop / checkpoint ...) is
hyperv_actions.py — nothing in this file changes anything on a host.
"""
import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, delete, func

from models.database import SessionLocal, WindowsHost, HypervHost, HypervVM, HypervSample
from services import windows_manage as wm
from services import vuln_scan as vs
from services import activity

POLL_SEC = max(60, int(os.environ.get("MIKROTIK_HYPERV_POLL_SEC", "300")))
CHECK_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_HYPERV_TIMEOUT_SEC", "180"))
HISTORY_DAYS = int(os.environ.get("MIKROTIK_HYPERV_HISTORY_DAYS", "14"))
NOT_HYPERV_RECHECK_HOURS = 24
MAX_SNAPSHOTS_KEPT = 30       # per VM in the detail view; the count itself is exact
MAX_VMS_IN_SUMMARY = 200      # per host in Central's redacted copy
HOST_DOWN_AFTER_FAILS = 2     # consecutive failed polls before a host counts as unreachable

# ISO timestamps are produced on the host, the rest is plain data. Every optional piece is wrapped in
# its own try/catch: a missing cmdlet (no Get-Cluster, no replication role) must never sink the whole
# poll. Enums are cast to text on purpose — Windows PowerShell 5.1's ConvertTo-Json writes them as
# numbers otherwise. Get-VM failing (no module) is NOT caught, so it surfaces as the "not a Hyper-V
# host" marker below.
_HYPERV_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Iso($d) { if ($d) { try { return ([datetime]$d).ToUniversalTime().ToString('o') } catch { return $null } } return $null }
$allVms = @(Get-VM)
$vms = foreach ($v in $allVms) {
  $snaps = @(); try { $snaps = @(Get-VMSnapshot -VM $v -ErrorAction Stop | Sort-Object CreationTime) } catch {}
  $snapList = @($snaps | Select-Object -First 30 | ForEach-Object { [PSCustomObject]@{ Name = [string]$_.Name; Created = (Iso $_.CreationTime) } })
  $disks = @()
  try {
    foreach ($d in @(Get-VMHardDiskDrive -VM $v -ErrorAction Stop)) {
      $fs = $null; $mx = $null; $ty = $null
      try { $h = Get-VHD -Path $d.Path -ErrorAction Stop; $fs = [int64]$h.FileSize; $mx = [int64]$h.Size; $ty = [string]$h.VhdType } catch {}
      $disks += [PSCustomObject]@{ File = [System.IO.Path]::GetFileName([string]$d.Path); FileBytes = $fs; MaxBytes = $mx; Type = $ty }
    }
  } catch {}
  $nics = @(); try { $nics = @(Get-VMNetworkAdapter -VM $v -ErrorAction Stop) } catch {}
  $ips = @(); foreach ($n in $nics) { foreach ($ip in @($n.IPAddresses)) { if ($ip -and ([string]$ip) -notmatch ':') { $ips += [string]$ip } } }
  $sw = @($nics | ForEach-Object { [string]$_.SwitchName } | Where-Object { $_ } | Select-Object -Unique)
  [PSCustomObject]@{
    Id = [string]$v.Id; Name = [string]$v.Name; State = [string]$v.State; Status = [string]$v.Status
    CPUUsage = $v.CPUUsage; MemoryAssigned = $v.MemoryAssigned; MemoryDemand = $v.MemoryDemand; MemoryStartup = $v.MemoryStartup
    MemoryMinimum = $v.MemoryMinimum; MemoryMaximum = $v.MemoryMaximum; DynamicMemory = [bool]$v.DynamicMemoryEnabled
    Heartbeat = [string]$v.Heartbeat; UptimeSeconds = [int64]$v.Uptime.TotalSeconds
    ProcessorCount = $v.ProcessorCount; Generation = $v.Generation; CheckpointType = [string]$v.CheckpointType
    ReplicationState = [string]$v.ReplicationState; ReplicationHealth = [string]$v.ReplicationHealth
    SnapshotCount = $snaps.Count; SnapshotList = $snapList; Disks = @($disks); Ips = @($ips); Switches = @($sw)
  }
}
$vmHost = Get-VMHost
$cpu = $null; try { $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average } catch {}
$memTotal = $null; $memFree = $null
try { $os = Get-CimInstance Win32_OperatingSystem; $memTotal = [int64]$os.TotalVisibleMemorySize * 1024; $memFree = [int64]$os.FreePhysicalMemory * 1024 } catch {}
$vmPath = [string]$vmHost.VirtualHardDiskPath
$stFree = $null; $stTotal = $null
try { if ($vmPath -match '^([A-Za-z]):\\' -and $vmPath -notmatch 'ClusterStorage') { $di = New-Object System.IO.DriveInfo($Matches[1]); $stFree = [int64]$di.AvailableFreeSpace; $stTotal = [int64]$di.TotalSize } } catch {}
$swCount = $null; try { $swCount = @(Get-VMSwitch -ErrorAction Stop).Count } catch {}
$cluster = $null; try { $cluster = [string](Get-Cluster -ErrorAction Stop).Name } catch {}
[PSCustomObject]@{
  Vms = @($vms)
  Host = [PSCustomObject]@{
    LogicalProcessorCount = $vmHost.LogicalProcessorCount; MemoryCapacity = $vmHost.MemoryCapacity
    CpuLoad = $cpu; MemTotal = $memTotal; MemFree = $memFree
    StoragePath = $vmPath; StorageFree = $stFree; StorageTotal = $stTotal; SwitchCount = $swCount; Cluster = $cluster
  }
} | ConvertTo-Json -Compress -Depth 6
"""

# Signature of "this host has no Hyper-V PowerShell module at all" (no Hyper-V role, or role present but the
# management cmdlets aren't installed) — distinguished from a real/transient failure so the expected
# majority of managed Windows hosts that simply aren't hypervisors never logs a scary error every cycle.
_NOT_HYPERV_MARKERS = ("is not recognized as the name of a cmdlet", "CommandNotFoundException")

# Fallback for a PowerShell that still serialises the enums as numbers.
_VM_STATE_NAMES = {1: "Other", 2: "Running", 3: "Off", 4: "Stopping", 6: "Saved", 9: "Paused", 10: "Starting",
                   11: "Reset", 32773: "Saving", 32776: "Pausing", 32777: "Resuming", 32779: "FastSaved",
                   32780: "FastSaving", 32781: "ForceShutdown", 32782: "ForceReboot", 32783: "Hibernated",
                   32785: "RunningCritical", 32786: "OffCritical", 32787: "StoppingCritical",
                   32788: "SavedCritical", 32789: "PausedCritical", 32790: "StartingCritical"}


def _is_not_hyperv(error_text: str) -> bool:
    return any(m in error_text for m in _NOT_HYPERV_MARKERS)


def _run_ps_sync(ip: str, port: int, username: str, password: str, domain: Optional[str], script: str, timeout_sec: int):
    """Blocking — run via loop.run_in_executor. Returns the pywinrm response; the session is always released."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=timeout_sec + 5, operation_timeout_sec=timeout_sec,
    )
    try:
        return vs._run_ps_safe(session, script)
    finally:
        vs._close_winrm(session)


def _check_hyperv_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Read-only Hyper-V cmdlets — needs the WinRM account to be in the target's local Hyper-V
    Administrators group (or Administrators), same requirement as any other Get-VM usage."""
    result = _run_ps_sync(ip, port, username, password, domain, _HYPERV_SCRIPT, CHECK_TIMEOUT_SEC)
    stderr = result.std_err.decode("utf-8", errors="ignore")
    if _is_not_hyperv(stderr):
        return {"ok": False, "not_hyperv": True}
    if result.status_code != 0:
        return {"ok": False, "error": stderr[-2000:] or f"exit code {result.status_code}"}
    raw = result.std_out.decode("utf-8", errors="ignore").strip()
    if not raw:
        return {"ok": False, "error": "empty response"}
    try:
        return {"ok": True, "parsed": json.loads(raw)}
    except Exception as e:
        return {"ok": False, "error": f"couldn't parse Hyper-V JSON: {e}"}


# ── Parsing (pure) ───────────────────────────────────────────────────────────

def _int_or_none(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _float_or_none(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _as_list(x) -> list:
    """ConvertTo-Json renders a lone result as a bare object and an empty one as null."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _enum(x, names: Optional[dict] = None) -> Optional[str]:
    if x is None or x == "":
        return None
    if names and (isinstance(x, int) or (isinstance(x, str) and x.isdigit())):
        return names.get(int(x), str(x))
    return str(x)


def _parse_iso(s) -> Optional[datetime]:
    """Naive UTC, like every other timestamp in the database. The host script always sends UTC
    ('o' format, e.g. 2026-10-01T10:00:00.0000000Z), so the first 19 characters are enough."""
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def _parse_hyperv(parsed: dict) -> dict:
    vms = []
    for v in _as_list(parsed.get("Vms")):
        if not isinstance(v, dict) or not v.get("Name"):
            continue
        disks = []
        for d in _as_list(v.get("Disks")):
            if isinstance(d, dict):
                disks.append({"file": d.get("File"), "type": d.get("Type"),
                              "file_bytes": _int_or_none(d.get("FileBytes")), "max_bytes": _int_or_none(d.get("MaxBytes"))})
        snaps = []
        for s in _as_list(v.get("SnapshotList")):
            if isinstance(s, dict):
                snaps.append({"name": s.get("Name"), "created": s.get("Created")})
        file_total = sum(d["file_bytes"] for d in disks if d["file_bytes"] is not None) if any(d["file_bytes"] is not None for d in disks) else None
        max_total = sum(d["max_bytes"] for d in disks if d["max_bytes"] is not None) if any(d["max_bytes"] is not None for d in disks) else None
        snap_dates = sorted(d for d in (_parse_iso(s["created"]) for s in snaps) if d)
        vms.append({
            "guid": (v.get("Id") or None),
            "name": v["Name"],
            "state": _enum(v.get("State"), _VM_STATE_NAMES),
            "status": v.get("Status"),
            "cpu_usage_pct": _int_or_none(v.get("CPUUsage")),
            "memory_assigned_bytes": _int_or_none(v.get("MemoryAssigned")),
            "memory_demand_bytes": _int_or_none(v.get("MemoryDemand")),
            "memory_startup_bytes": _int_or_none(v.get("MemoryStartup")),
            "memory_min_bytes": _int_or_none(v.get("MemoryMinimum")),
            "memory_max_bytes": _int_or_none(v.get("MemoryMaximum")),
            "dynamic_memory": bool(v["DynamicMemory"]) if isinstance(v.get("DynamicMemory"), bool) else None,
            "uptime_sec": _int_or_none(v.get("UptimeSeconds")),
            "heartbeat": _enum(v.get("Heartbeat")),
            "vcpu_count": _int_or_none(v.get("ProcessorCount")),
            "generation": _int_or_none(v.get("Generation")),
            "checkpoint_type": _enum(v.get("CheckpointType")),
            "replication_state": _enum(v.get("ReplicationState")),
            "replication_health": _enum(v.get("ReplicationHealth")),
            "snapshot_count": _int_or_none(v.get("SnapshotCount")),
            "oldest_snapshot_at": snap_dates[0] if snap_dates else None,
            "snapshots": snaps,
            "disks": disks, "disk_count": len(disks), "disk_file_bytes": file_total, "disk_max_bytes": max_total,
            "ips": [str(i) for i in _as_list(v.get("Ips")) if i],
            "switches": [str(s) for s in _as_list(v.get("Switches")) if s],
        })

    host_raw = parsed.get("Host") or {}
    if isinstance(host_raw, list):  # defensive — Get-VMHost is always singular, but never trust it blindly
        host_raw = host_raw[0] if host_raw else {}
    mem_total, mem_free = _int_or_none(host_raw.get("MemTotal")), _int_or_none(host_raw.get("MemFree"))
    mem_used_pct = round((mem_total - mem_free) / mem_total * 100, 1) if mem_total and mem_free is not None and mem_total > 0 else None
    cpu = _float_or_none(host_raw.get("CpuLoad"))
    return {
        "vms": vms,
        "logical_processor_count": _int_or_none(host_raw.get("LogicalProcessorCount")),
        "memory_capacity_bytes": _int_or_none(host_raw.get("MemoryCapacity")) or mem_total,
        "cpu_used_pct": round(cpu, 1) if cpu is not None else None,
        "mem_used_pct": mem_used_pct,
        "storage_path": host_raw.get("StoragePath") or None,
        "storage_free_bytes": _int_or_none(host_raw.get("StorageFree")),
        "storage_total_bytes": _int_or_none(host_raw.get("StorageTotal")),
        "switch_count": _int_or_none(host_raw.get("SwitchCount")),
        "cluster_name": host_raw.get("Cluster") or None,
    }


# ── Poll + persist ───────────────────────────────────────────────────────────

def _jdump(x) -> Optional[str]:
    return json.dumps(x, ensure_ascii=False) if x else None


def _persist(db, hv_host: HypervHost, parsed: dict, now: datetime) -> None:
    hv_host.last_status = "ok"
    hv_host.last_error = None
    hv_host.last_ok_at = now
    hv_host.fail_streak = 0
    hv_host.logical_processor_count = parsed["logical_processor_count"]
    hv_host.memory_capacity_bytes = parsed["memory_capacity_bytes"]
    hv_host.cpu_used_pct = parsed["cpu_used_pct"]
    hv_host.mem_used_pct = parsed["mem_used_pct"]
    hv_host.storage_path = parsed["storage_path"]
    hv_host.storage_free_bytes = parsed["storage_free_bytes"]
    hv_host.storage_total_bytes = parsed["storage_total_bytes"]
    hv_host.switch_count = parsed["switch_count"]
    hv_host.cluster_name = parsed["cluster_name"]
    hv_host.vm_count_total = len(parsed["vms"])
    hv_host.vm_count_running = sum(1 for v in parsed["vms"] if v["state"] == "Running")
    hv_host.last_check_at = now

    existing = {r.name: r for r in db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv_host.id)).scalars().all()}
    seen = set()
    for v in parsed["vms"]:
        seen.add(v["name"])
        row = existing.get(v["name"])
        if not row:
            row = HypervVM(hyperv_host_id=hv_host.id, name=v["name"], first_seen_at=now)
            db.add(row)
        if row.state != v["state"] or row.state_since is None:
            row.state_since = now
        row.state = v["state"]
        row.status = v["status"]
        row.vm_guid = v["guid"]
        row.cpu_usage_pct = v["cpu_usage_pct"]
        row.memory_assigned_bytes = v["memory_assigned_bytes"]
        row.memory_demand_bytes = v["memory_demand_bytes"]
        row.memory_startup_bytes = v["memory_startup_bytes"]
        row.memory_min_bytes = v["memory_min_bytes"]
        row.memory_max_bytes = v["memory_max_bytes"]
        row.dynamic_memory = v["dynamic_memory"]
        row.uptime_sec = v["uptime_sec"]
        row.heartbeat = v["heartbeat"]
        row.vcpu_count = v["vcpu_count"]
        row.generation = v["generation"]
        row.checkpoint_type = v["checkpoint_type"]
        row.replication_state = v["replication_state"]
        row.replication_health = v["replication_health"]
        row.snapshot_count = v["snapshot_count"]
        row.oldest_snapshot_at = v["oldest_snapshot_at"]
        row.snapshots = _jdump(v["snapshots"])
        row.disks = _jdump(v["disks"])
        row.disk_count = v["disk_count"]
        row.disk_file_bytes = v["disk_file_bytes"]
        row.disk_max_bytes = v["disk_max_bytes"]
        row.ips = _jdump(v["ips"])
        row.switches = _jdump(v["switches"])
        row.last_seen_at = now
    db.flush()

    # A VM that is gone from a successful listing was deleted or moved: drop it (and its history).
    for name, row in existing.items():
        if name not in seen:
            db.execute(delete(HypervSample).where(HypervSample.kind == "vm", HypervSample.ref_id == row.id))
            db.delete(row)

    db.add(HypervSample(kind="host", ref_id=hv_host.id, ts=now, cpu_pct=hv_host.cpu_used_pct, mem_pct=hv_host.mem_used_pct))
    for row in db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv_host.id)).scalars().all():
        if row.state != "Running":
            continue
        demand_pct = None
        if row.memory_assigned_bytes and row.memory_demand_bytes is not None:
            demand_pct = round(row.memory_demand_bytes / row.memory_assigned_bytes * 100, 1)
        db.add(HypervSample(kind="vm", ref_id=row.id, ts=now, cpu_pct=row.cpu_usage_pct, mem_pct=demand_pct,
                            mem_bytes=row.memory_demand_bytes))


async def check_hyperv_host(host_id: int) -> dict:
    """Polls one managed Windows host for Hyper-V data and persists it. Read-only aside from the agent's
    own DB. Never raises — always returns a dict with "ok" (or "error")."""
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
            timeout=CHECK_TIMEOUT_SEC + 20,
        )
    except (asyncio.TimeoutError, TimeoutError):
        result = {"ok": False, "error": "timeout"}
    except Exception as e:
        result = {"ok": False, "error": str(e)}

    now = datetime.utcnow()
    with SessionLocal() as db:
        hv_host = db.execute(select(HypervHost).where(HypervHost.windows_host_id == host_id)).scalar_one_or_none()
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
            # A poll that fails keeps the last known VM data (shown as stale) — only the streak and the
            # status change, so one dropped WinRM call never makes a healthy board look empty.
            hv_host.last_status = "error"
            hv_host.last_error = result.get("error")
            hv_host.fail_streak = (hv_host.fail_streak or 0) + 1
            hv_host.last_check_at = now
            db.commit()
            return {"error": result.get("error")}

        parsed = _parse_hyperv(result["parsed"])
        _persist(db, hv_host, parsed, now)
        db.commit()

    try:
        activity.record("hyperv_check", host_id=host_id, hostname=hostname, vm_count=len(parsed["vms"]))
    except Exception as e:
        print(f"[hyperv_manage] activity record error: {e}")
    return {"ok": True, "vm_count": len(parsed["vms"])}


async def refresh_managed_hyperv_hosts(force: bool = False) -> dict:
    """One poll of every managed Windows host that runs (or might run) Hyper-V — up to 3 in parallel.
    A host already known NOT to be a hypervisor is only re-checked once a day."""
    cutoff = datetime.utcnow() - timedelta(hours=NOT_HYPERV_RECHECK_HOURS)
    with SessionLocal() as db:
        known = {h.windows_host_id: h for h in db.execute(select(HypervHost)).scalars().all()}
        ids = []
        for h in db.execute(select(WindowsHost).where(WindowsHost.managed == True)).scalars().all():  # noqa: E712
            hv = known.get(h.id)
            if not force and hv and hv.last_status == "not_hyperv" and hv.last_check_at and hv.last_check_at > cutoff:
                continue
            ids.append(h.id)

    sem = asyncio.Semaphore(3)

    async def one(host_id: int):
        async with sem:
            try:
                return (await check_hyperv_host(host_id)).get("ok", False)
            except Exception as e:
                print(f"[hyperv_manage] refresh error for host {host_id}: {e}")
                return False

    results = await asyncio.gather(*(one(i) for i in ids))
    _prune_history()
    return {"checked": sum(1 for r in results if r), "total": len(ids)}


def _prune_history() -> None:
    try:
        with SessionLocal() as db:
            db.execute(delete(HypervSample).where(HypervSample.ts < datetime.utcnow() - timedelta(days=HISTORY_DAYS)))
            db.commit()
    except Exception as e:
        print(f"[hyperv_manage] history prune error: {e}")


# ── Own loop ─────────────────────────────────────────────────────────────────

_task: Optional[asyncio.Task] = None


async def _loop():
    await asyncio.sleep(40)
    while True:
        try:
            await refresh_managed_hyperv_hosts()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[hyperv_manage] loop error: {e}")
        await asyncio.sleep(POLL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None


# ── Fast path: alert events from already-persisted state ─────────────────────

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


# insight kind -> alert event type (see hyperv_insights.py for what each one means)
INSIGHT_EVENTS = {
    "vm_no_heartbeat": "hyperv_vm_no_heartbeat",
    "vm_snapshot_old": "hyperv_snapshot_old",
    "vm_replication": "hyperv_replication_problem",
    "host_memory_high": "hyperv_host_pressure",
    "host_cpu_high": "hyperv_host_pressure",
    "host_storage_low": "hyperv_host_pressure",
    "host_cpu_overcommit": "hyperv_host_pressure",
}


async def collect_hyperv_events() -> list:
    """Cheap, DB-only diff against the state file — no WinRM call here, just reads what the last poll
    persisted (up to POLL_SEC stale). Reported:
      · a VM going Running <-> not Running (a graceful shutdown is not told apart from a crash);
      · a host becoming unreachable (HOST_DOWN_AFTER_FAILS failed polls in a row) and coming back;
      · a problem appearing in the insights list for the kinds in INSIGHT_EVENTS (once per appearance —
        when it goes away and comes back it is reported again).
    The very first run only records a baseline for the insight problems, so enabling this never floods
    Central with everything that has been wrong for weeks."""
    from services import hyperv_insights

    with SessionLocal() as db:
        rows = db.execute(
            select(HypervVM, HypervHost, WindowsHost)
            .join(HypervHost, HypervVM.hyperv_host_id == HypervHost.id)
            .join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
        ).all()
        hosts = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .where(HypervHost.last_status != "not_hyperv")
        ).all()
        insights = hyperv_insights.compute(db)

    state = _load_state()
    events = []
    now_iso = datetime.utcnow().isoformat()

    def emit(event_type: str, name: str, **extra):
        ev = {"type": event_type, "device_name": name, "count": 1, "detected_at": now_iso, **extra}
        events.append(ev)
        try:
            activity.record(event_type, device_name=name, **{k: v for k, v in extra.items() if isinstance(v, (str, int, float))})
        except Exception as e:
            print(f"[hyperv_manage] activity record error: {e}")

    for vm, hv_host, host in rows:
        key = f"{hv_host.id}:{vm.name}"
        prev_state = state.get(key)
        new_state = vm.state
        host_name = host.hostname or host.ip
        if prev_state is not None and prev_state != new_state:
            was_running = prev_state == "Running"
            now_running = new_state == "Running"
            event_type = ("hyperv_vm_down" if was_running and not now_running
                          else "hyperv_vm_up" if now_running and not was_running else None)  # e.g. Off -> Saved: neither edge
            if event_type:
                emit(event_type, f"{host_name}: {vm.name}", host_id=host.id, vm_name=vm.name,
                     from_state=prev_state, to_state=new_state)
        state[key] = new_state

    for hv_host, host in hosts:
        key = f"host:{hv_host.id}"
        bucket = "down" if (hv_host.last_status == "error" and (hv_host.fail_streak or 0) >= HOST_DOWN_AFTER_FAILS) else "up"
        prev = state.get(key)
        if prev is not None and prev != bucket:
            emit("hyperv_host_down" if bucket == "down" else "hyperv_host_up", host.hostname or host.ip,
                 host_id=host.id, detail=(hv_host.last_error or "")[:300] if bucket == "down" else "")
        state[key] = bucket

    baseline = "_ins_init" not in state
    current = {}
    for ins in insights:
        etype = INSIGHT_EVENTS.get(ins["kind"])
        if etype:
            current[f"ins:{ins['key']}"] = (etype, ins)
    for k in [k for k in state if k.startswith("ins:") and k not in current]:
        del state[k]
    for k, (etype, ins) in current.items():
        if k not in state:
            state[k] = 1
            if not baseline:
                name = f"{ins['host']}: {ins['vm']}" if ins.get("vm") else ins["host"]
                emit(etype, name, host_id=ins["windows_host_id"], vm_name=ins.get("vm") or "", kind=ins["kind"],
                     severity=ins["severity"], detail=ins.get("text") or "")
    state["_ins_init"] = 1

    _save_state(state)
    return events


# ── Listing / admin (local agent UI) ─────────────────────────────────────────

def _iso(dt: Optional[datetime]) -> Optional[str]:
    """Explicit UTC, so the browser converts to local time correctly."""
    return dt.isoformat() + "Z" if dt else None


def _jload(s: Optional[str]) -> list:
    if not s:
        return []
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except Exception:
        return []


def host_dict(hv: HypervHost, host: WindowsHost) -> dict:
    return {
        "id": hv.id, "windows_host_id": host.id, "ip": host.ip, "hostname": host.hostname, "os_name": host.os_name,
        "logical_processor_count": hv.logical_processor_count,
        "memory_capacity_bytes": hv.memory_capacity_bytes,
        "vm_count_total": hv.vm_count_total, "vm_count_running": hv.vm_count_running,
        "cpu_used_pct": hv.cpu_used_pct, "mem_used_pct": hv.mem_used_pct,
        "storage_path": hv.storage_path, "storage_free_bytes": hv.storage_free_bytes, "storage_total_bytes": hv.storage_total_bytes,
        "switch_count": hv.switch_count, "cluster_name": hv.cluster_name,
        "last_check_at": _iso(hv.last_check_at), "last_ok_at": _iso(hv.last_ok_at),
        "last_status": hv.last_status, "last_error": hv.last_error, "fail_streak": hv.fail_streak or 0,
    }


def vm_dict(v: HypervVM, detail: bool = False) -> dict:
    d = {
        "id": v.id, "hyperv_host_id": v.hyperv_host_id, "name": v.name, "state": v.state, "status": v.status,
        "cpu_usage_pct": v.cpu_usage_pct,
        "memory_assigned_bytes": v.memory_assigned_bytes, "memory_demand_bytes": v.memory_demand_bytes,
        "memory_startup_bytes": v.memory_startup_bytes, "memory_min_bytes": v.memory_min_bytes,
        "memory_max_bytes": v.memory_max_bytes, "dynamic_memory": v.dynamic_memory,
        "uptime_sec": v.uptime_sec, "heartbeat": v.heartbeat, "vcpu_count": v.vcpu_count, "generation": v.generation,
        "checkpoint_type": v.checkpoint_type,
        "replication_state": v.replication_state, "replication_health": v.replication_health,
        "snapshot_count": v.snapshot_count, "oldest_snapshot_at": _iso(v.oldest_snapshot_at),
        "disk_count": v.disk_count, "disk_file_bytes": v.disk_file_bytes, "disk_max_bytes": v.disk_max_bytes,
        "ips": _jload(v.ips), "switches": _jload(v.switches),
        "state_since": _iso(v.state_since), "last_seen_at": _iso(v.last_seen_at),
    }
    if detail:
        d["disks"] = _jload(v.disks)
        d["snapshots"] = _jload(v.snapshots)
        d["vm_guid"] = v.vm_guid
    return d


def list_hosts() -> list:
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .order_by(WindowsHost.ip)
        ).all()
        return [host_dict(hv, host) for hv, host in rows if hv.last_status != "not_hyperv"]


def list_vms(hyperv_host_id: int) -> list:
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervVM).where(HypervVM.hyperv_host_id == hyperv_host_id).order_by(HypervVM.name)
        ).scalars().all()
        return [vm_dict(v) for v in rows]


def get_vm(vm_id: int) -> Optional[dict]:
    with SessionLocal() as db:
        v = db.get(HypervVM, vm_id)
        return vm_dict(v, detail=True) if v else None


def history(kind: str, ref_id: int, hours: int = 24, points: int = 96) -> list:
    """Time series for a trend chart, averaged into at most `points` buckets."""
    hours = max(1, min(hours, HISTORY_DAYS * 24))
    since = datetime.utcnow() - timedelta(hours=hours)
    with SessionLocal() as db:
        rows = db.execute(
            select(HypervSample).where(HypervSample.kind == kind, HypervSample.ref_id == ref_id, HypervSample.ts >= since)
            .order_by(HypervSample.ts)
        ).scalars().all()
    if not rows:
        return []
    bucket = max(1, hours * 3600 // points)
    out: dict = {}
    for r in rows:
        k = int(r.ts.timestamp() // bucket)
        b = out.setdefault(k, {"n_cpu": 0, "cpu": 0.0, "n_mem": 0, "mem": 0.0})
        if r.cpu_pct is not None:
            b["n_cpu"] += 1; b["cpu"] += r.cpu_pct
        if r.mem_pct is not None:
            b["n_mem"] += 1; b["mem"] += r.mem_pct
    return [{"t": datetime.utcfromtimestamp(k * bucket).isoformat() + "Z",
             "cpu": round(b["cpu"] / b["n_cpu"], 1) if b["n_cpu"] else None,
             "mem": round(b["mem"] / b["n_mem"], 1) if b["n_mem"] else None} for k, b in sorted(out.items())]


def overview() -> dict:
    """Everything the dashboard shows, from the database only: per host the figures, an hourly CPU /
    memory trend (24 h) and the VM tiles; the fleet-wide totals; the problems list."""
    from services import hyperv_insights

    with SessionLocal() as db:
        rows = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .where(HypervHost.last_status != "not_hyperv").order_by(WindowsHost.hostname, WindowsHost.ip)
        ).all()
        insights = hyperv_insights.compute(db)
        sev: dict = {}
        for i in insights:
            if i.get("vm"):
                sev.setdefault((i["hyperv_host_id"], i["vm"]), []).append(i["severity"])
        hosts = []
        totals = {"hosts": 0, "hosts_ok": 0, "hosts_down": 0, "vms": 0, "running": 0, "off": 0, "other": 0,
                  "tiles": {"ok": 0, "warn": 0, "crit": 0, "off": 0}, "vcpu": 0, "lp": 0,
                  "mem_assigned": 0, "mem_capacity": 0, "problems": {"high": 0, "medium": 0, "low": 0}}
        for hv, host in rows:
            vms = db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv.id).order_by(HypervVM.name)).scalars().all()
            tiles = []
            for v in vms:
                tile = hyperv_insights.vm_tile(v.state, sev.get((hv.id, v.name), []))
                totals["tiles"][tile] += 1
                tiles.append({**vm_dict(v), "tile": tile, "flags": [i["kind"] for i in insights if i["hyperv_host_id"] == hv.id and i.get("vm") == v.name]})
            running = [v for v in vms if v.state == "Running"]
            hd = host_dict(hv, host)
            hd["vcpu_assigned"] = sum(v.vcpu_count or 0 for v in running)
            hd["memory_assigned_bytes"] = sum(v.memory_assigned_bytes or 0 for v in running)
            hd["down"] = hv.last_status == "error" and (hv.fail_streak or 0) >= HOST_DOWN_AFTER_FAILS
            hd["vms"] = tiles
            hd["trend"] = history("host", hv.id, hours=24, points=48)
            hosts.append(hd)
            totals["hosts"] += 1
            totals["hosts_down" if hd["down"] else "hosts_ok"] += 1
            totals["vms"] += len(vms)
            totals["running"] += len(running)
            totals["off"] += sum(1 for v in vms if v.state == "Off")
            totals["other"] += sum(1 for v in vms if v.state not in ("Running", "Off"))
            totals["vcpu"] += hd["vcpu_assigned"]
            totals["lp"] += hv.logical_processor_count or 0
            totals["mem_assigned"] += hd["memory_assigned_bytes"]
            totals["mem_capacity"] += hv.memory_capacity_bytes or 0
        for i in insights:
            totals["problems"][i["severity"]] += 1
    return {"generated_at": _iso(datetime.utcnow()), "totals": totals, "hosts": hosts, "insights": insights,
            "poll_sec": POLL_SEC}


# ── Redacted summary for Central ─────────────────────────────────────────────

def public_summary() -> list:
    """Copy for the snapshot's plaintext envelope (mirrors linux_manage / windows_manage). Names, states
    and figures only: no VM IPs, disk file names or checkpoint names. The first fields are the original
    ones (older Central pages keep working); the rest feed the graphical page. Hosts that stopped
    answering are included, marked status "error", so Central can say so."""
    from services import hyperv_insights

    with SessionLocal() as db:
        rows = db.execute(
            select(HypervHost, WindowsHost).join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)
            .where(HypervHost.last_status.in_(("ok", "error")))
        ).all()
        # an error host is only worth showing when there is older data to show with it
        rows = [(hv, host) for hv, host in rows if hv.last_status == "ok" or hv.last_ok_at is not None]
        insights = hyperv_insights.compute(db)
        by_host: dict = {}
        for ins in insights:
            by_host.setdefault(ins["hyperv_host_id"], []).append(ins)
        result = []
        for hv, host in rows:
            vms = db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv.id).order_by(HypervVM.name)).scalars().all()
            vm_flags: dict = {}
            for ins in by_host.get(hv.id, []):
                if ins.get("vm"):
                    vm_flags.setdefault(ins["vm"], []).append(ins)
            running = [v for v in vms if v.state == "Running"]
            result.append({
                "id": hv.id, "ip": host.ip, "hostname": host.hostname,
                "logical_processor_count": hv.logical_processor_count,
                "memory_capacity_bytes": hv.memory_capacity_bytes,
                "vm_count_total": hv.vm_count_total, "vm_count_running": hv.vm_count_running,
                "vms_not_running": [v.name for v in vms if v.state != "Running"],
                "last_check_at": hv.last_check_at.isoformat() if hv.last_check_at else None,
                # new
                "status": hv.last_status, "cluster_name": hv.cluster_name, "os_name": host.os_name,
                "cpu_used_pct": hv.cpu_used_pct, "mem_used_pct": hv.mem_used_pct,
                "storage_free_bytes": hv.storage_free_bytes, "storage_total_bytes": hv.storage_total_bytes,
                "vcpu_assigned": sum(v.vcpu_count or 0 for v in running),
                "memory_assigned_bytes": sum(v.memory_assigned_bytes or 0 for v in running),
                "vms": [{
                    "name": v.name, "state": v.state, "cpu": v.cpu_usage_pct, "vcpu": v.vcpu_count,
                    "mem_assigned": v.memory_assigned_bytes, "mem_demand": v.memory_demand_bytes,
                    "uptime_sec": v.uptime_sec, "heartbeat": v.heartbeat, "snapshots": v.snapshot_count,
                    "replication": v.replication_health if v.replication_state not in (None, "Disabled") else None,
                    "flags": [i["kind"] for i in vm_flags.get(v.name, [])],
                    "tile": hyperv_insights.vm_tile(v.state, [i["severity"] for i in vm_flags.get(v.name, [])]),
                } for v in vms[:MAX_VMS_IN_SUMMARY]],
                "problems": [{"kind": i["kind"], "severity": i["severity"], "vm": i.get("vm")} for i in by_host.get(hv.id, [])][:50],
            })
        return result
