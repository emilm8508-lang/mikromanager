"""
Servers and hardware: the checks of stage 6 of docs/plan-jakosc-danych.md.

  normalize_health()   a BMC / iSM / RACADM / OMSA health value -> OK / Warning / Critical, or a parser error - never the raw value. Seen in
                       production: psb's Dell "HYPER-V" read through the iDRAC Service Module showed health "5" - CIM HealthState 5 is OK
  component_detail()   which power supply, fan, sensor or disk is behind a component's state (sanmed's SANMED-HYPERV: Power Critical)
  license()            a Windows host's licence from SoftwareLicensingProduct: the edition, evaluation or not, when it expires. Seen:
                       mcprojekt's DC2, FS1, TECHSERVICE and sanmed's RDP on "Standard Evaluation" - an evaluation ends, and the server
                       then shuts itself down every hour
  boot_space()         /boot running out with updates waiting (a new kernel needs room) - sanmed's oracle1: 0.2 GB free, 10 updates
  restart_age()        a restart pending for days
  power_temp()         a power / temperature jump read against the load: busy (the VMs work) or cooling (hot while idle, a fan) - seen:
                       mcprojekt's HYPERV-R2 at 478 W instead of its usual 187 W with the CPUs at 85 °C

The cycle (every 30 minutes) raises one SOC alert per finding and closes it when the finding is gone.
"""
import asyncio
import json
import re
import statistics
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

# CIM_ManagedSystemElement.HealthState, Dell CIM PrimaryStatus / RollupStatus, CIM OperationalStatus, SNMP (DELL / IDRAC MIB ObjectStatus)
_NUMERIC = {
    "healthstate": {0: None, 5: "OK", 10: "Warning", 15: "Warning", 20: "Critical", 25: "Critical", 30: "Critical"},
    "primarystatus": {0: None, 1: "OK", 2: "Warning", 3: "Critical"},
    "rollupstatus": {0: None, 1: "OK", 2: "Warning", 3: "Critical"},
    "operationalstatus": {0: None, 2: "OK", 3: "Warning", 4: "Warning", 5: "Warning", 6: "Critical", 7: "Critical", 10: "Critical", 13: "Critical"},
    "snmp": {1: None, 2: None, 3: "OK", 4: "Warning", 5: "Critical", 6: "Critical"},
}
_TEXT = [(re.compile(r"^(ok|healthy|good|normal|online|enabled|running)$", re.I), "OK"),
         (re.compile(r"warning|degraded|non-?critical|minor|predictive|stressed", re.I), "Warning"),
         (re.compile(r"critical|error|fail|major|non-?recoverable|fatal|lost", re.I), "Critical"),
         (re.compile(r"^(unknown|n/?a|none|absent|not present|-)?$", re.I), None)]


def normalize_health(value, key: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """(state, parser error). state is OK / Warning / Critical or None (unknown); a value nothing maps is (None, "unknown health value ...")."""
    if value is None:
        return None, None
    s = str(value).strip()
    if re.fullmatch(r"-?\d+", s):
        table = _NUMERIC.get((key or "").replace("_", "").lower())
        if table is None:
            return None, f"numeric health value {s} without its scale ({key or 'no field name'})"
        n = int(s)
        if n not in table:
            return None, f"unknown {key} value {s}"
        return table[n], None
    for rx, state in _TEXT:
        if rx.search(s):
            return state, None
    return None, f"unknown health value '{s[:40]}'"


def component_detail(details: Optional[dict]) -> Dict[str, List[str]]:
    """{"power": ["PS1: Critical (input lost)"], "fans_temperature": [...], "storage": [...], "memory": [...], "cpu": [...]} for the parts
    that are not OK."""
    out: Dict[str, List[str]] = {}
    if not details:
        return out

    def bad(item) -> bool:
        return isinstance(item, dict) and normalize_health(item.get("health"))[0] in ("Warning", "Critical")

    def add(comp: str, text: str):
        out.setdefault(comp, []).append(text[:120])

    power = details.get("power") or {}
    for p in power.get("psus") or []:
        if bad(p):
            add("power", f"{p.get('name') or 'power supply'}: {p.get('health')}" + (f" ({p['state']})" if p.get("state") else ""))
    if power.get("redundancy") and normalize_health(power["redundancy"])[0] in ("Warning", "Critical"):
        add("power", f"redundancy: {power['redundancy']}")
    for f in details.get("fans") or []:
        if bad(f):
            add("fans_temperature", f"{f.get('name') or 'fan'}: {f.get('health')}" + (f" ({f.get('rpm')} RPM)" if f.get("rpm") is not None else ""))
    for t in details.get("temps") or []:
        if bad(t):
            add("fans_temperature", f"{t.get('name') or 'sensor'}: {t.get('health')}" + (f" ({t.get('c')} °C)" if t.get("c") is not None else ""))
    st = details.get("storage") or {}
    for kind in ("controllers", "drives", "volumes"):
        for d in st.get(kind) or []:
            if bad(d):
                add("storage", f"{d.get('name') or kind[:-1]}: {d.get('health')}" + (f" ({d['state']})" if d.get("state") else ""))
    for d in details.get("dimms") or []:
        if bad(d):
            add("memory", f"DIMM {d.get('slot')}: {d.get('health')}")
    for c in details.get("cpus") or []:
        if bad(c):
            add("cpu", f"{c.get('name') or 'CPU'}: {c.get('health')}")
    return out


# ── Windows licence ──────────────────────────────────────────────────────────

LICENSE_STATUS = {0: "unlicensed", 1: "licensed", 2: "oob_grace", 3: "oot_grace", 4: "non_genuine_grace", 5: "notification", 6: "extended_grace"}
LICENSE_STEPS = (30, 14, 3)


def license(raw, now: datetime) -> Optional[dict]:
    """The Windows licence from SoftwareLicensingProduct rows (Name, Description, LicenseStatus, GracePeriodRemaining in minutes):
    {"name", "status", "evaluation", "expires_at", "days_left"} for the active one, or None."""
    rows = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    rows = [r for r in rows if isinstance(r, dict) and r.get("Name")]
    if not rows:
        return None
    r = sorted(rows, key=lambda x: (0 if x.get("LicenseStatus") == 1 else 1, -(x.get("GracePeriodRemaining") or 0)))[0]
    text = f"{r.get('Name')} {r.get('Description') or ''}"
    evaluation = bool(re.search(r"eval", text, re.I))
    minutes = r.get("GracePeriodRemaining") or 0
    expires = now + timedelta(minutes=int(minutes)) if (evaluation or r.get("LicenseStatus") != 1) and minutes else None
    return {"name": str(r.get("Name"))[:120], "status": LICENSE_STATUS.get(r.get("LicenseStatus"), str(r.get("LicenseStatus"))),
            "evaluation": evaluation, "expires_at": expires, "days_left": round((expires - now).total_seconds() / 86400, 1) if expires else None}


def license_alert(lic: Optional[dict], important: bool) -> Optional[Tuple[int, str]]:
    """(step, severity) when an evaluation / grace licence ends within 30 / 14 / 3 days (or has ended); None otherwise.
    Critical for a domain controller or a file server (and anything marked important) in the last 14 days."""
    if not lic or lic.get("days_left") is None:
        return None
    d = lic["days_left"]
    step = next((s for s in sorted(LICENSE_STEPS) if d <= s), None)
    if step is None:
        return None
    if d <= 0:
        return 0, "critical"
    sev = {30: "medium", 14: "high", 3: "critical"}[step]
    if important and step <= 14:
        sev = "critical"
    return step, sev


# ── disks, restarts ──────────────────────────────────────────────────────────

BOOT_MIN_FREE = 300 * 1024 * 1024        # room for a new kernel and its initramfs
BOOT_CRIT_FREE = 150 * 1024 * 1024


def boot_space(mount: str, total: Optional[int], used: Optional[int], upgradable: Optional[int]) -> Optional[Tuple[str, str]]:
    """(severity, message) for a /boot (or /boot/efi) with too little room for the waiting updates."""
    if mount not in ("/boot", "/boot/efi") or not total or used is None:
        return None
    free = total - used
    if free >= BOOT_MIN_FREE:
        return None
    gb = free / 1024 ** 3
    waiting = upgradable or 0
    if free < BOOT_CRIT_FREE and waiting:
        return "high", f"{mount}: {gb:.2f} GB free with {waiting} updates waiting - a new kernel will not fit; remove old kernels first"
    return ("medium" if waiting else "low"), f"{mount}: {gb:.2f} GB free" + (f" with {waiting} updates waiting" if waiting else "")


RESTART_DAYS = 7


def note_reboot(host, pending: bool, since: Optional[datetime], source: str) -> None:
    """A host's pending restart as the host says it (3.66): `since` only from a source - the date of /var/run/reboot-required, the install of
    the newest kernel, the first update installed after the last boot, the agent's own installation - never the time it was first read.
    Unknown: None with source "unknown". The earliest known time is kept."""
    host.reboot_required = bool(pending)
    if not pending:
        host.reboot_required_since, host.reboot_since_source = None, None
        return
    if since and (not host.reboot_required_since or since < host.reboot_required_since):
        host.reboot_required_since, host.reboot_since_source = since, source
    elif not host.reboot_required_since:
        host.reboot_since_source = "unknown"


def parse_linux_reboot(output: str) -> Tuple[bool, Optional[datetime], str]:
    """The reboot check's output (linux_manage._reboot_check_command): "REBOOT_REQUIRED <epoch of the cause> <boot epoch> file|kernel"."""
    for line in (output or "").splitlines():
        parts = line.split()
        if not parts or parts[0] != "REBOOT_REQUIRED":
            continue
        nums = [int(x) for x in parts[1:3] if x.isdigit()]
        src = "file" if parts[-1] == "file" else "kernel_install"
        if len(nums) == 2 and nums[0] > nums[1]:          # the cause came after the last boot: that is when the restart became pending
            return True, datetime.utcfromtimestamp(nums[0]), src
        if len(nums) == 1 and src == "file":
            return True, datetime.utcfromtimestamp(nums[0]), src
        return True, None, "unknown"
    return False, None, ""


def restart_age(since: Optional[datetime], now: datetime, important: bool, days: int = RESTART_DAYS) -> Optional[Tuple[str, int]]:
    """(severity, days) for a restart pending longer than `days`."""
    if not since:
        return None
    age = (now - since).days
    if age < days:
        return None
    return ("medium" if important or age >= 3 * days else "low"), age


# ── power / temperature against the load ─────────────────────────────────────

def power_temp(power_w: Optional[float], typical_w: Optional[float], cpu_c: Optional[float], load_pct: Optional[float],
               fans_health: Optional[str], thermal_health: Optional[str]) -> Optional[dict]:
    """None when nothing stands out; else {"verdict": load | cooling | unclear, "reason", "severity"}. Stands out: power 1.8x the usual, or
    a CPU at 85 °C or more. Busy = the host's / VMs' CPU load at 60 % or more; cooling = hot while not busy, or the BMC's fans / thermal
    not OK."""
    high_power = bool(power_w and typical_w and power_w >= 1.8 * typical_w)
    hot = cpu_c is not None and cpu_c >= 85
    if not (high_power or hot):
        return None
    facts = []
    if high_power:
        facts.append(f"{power_w:.0f} W instead of the usual {typical_w:.0f} W")
    if cpu_c is not None:
        facts.append(f"CPU {cpu_c:.0f} °C")
    if load_pct is not None:
        facts.append(f"load {load_pct:.0f} %")
    cooling_bad = any(normalize_health(h)[0] in ("Warning", "Critical") for h in (fans_health, thermal_health) if h)
    busy = load_pct is not None and load_pct >= 60
    if cooling_bad or (hot and load_pct is not None and load_pct < 30):
        return {"verdict": "cooling", "severity": "high", "reason": ", ".join(facts) + (" - the BMC reports fans / thermal not OK" if cooling_bad else " while the load is low: check the fans, the air flow, the room")}
    if busy:
        return {"verdict": "load", "severity": "low", "reason": ", ".join(facts) + " - the load explains it (the VMs / services are busy)"}
    return {"verdict": "unclear", "severity": "medium", "reason": ", ".join(facts) + (" - the load is not known" if load_pct is None else " - not explained by the load")}


def typical(values: Iterable[float]) -> Optional[float]:
    v = [x for x in values if x is not None]
    return statistics.median(v) if len(v) >= 6 else None


# ── the cycle ────────────────────────────────────────────────────────────────

INTERVAL_SEC = 1800
_task: Optional[asyncio.Task] = None
_last: Dict[str, object] = {"at": None, "findings": 0, "error": None}
_DC_FS_NAME = re.compile(r"(^|[-_])(dc|fs)\d*([-_]|$)", re.I)


def _important_by_ref(db) -> Dict[Tuple[str, int], Tuple[bool, str]]:
    """(ref kind, id) -> (important, name): an asset marked critical / important, or suggested so (DC, file server, hypervisor ...)."""
    from models.database import Asset
    from services import asset_type as at
    out = {}
    for a in db.query(Asset).all():
        refs = json.loads(a.refs or "{}")
        det = json.loads(a.details or "{}")
        lv = at.normalize_level(a.criticality) or at.suggest(asset_type=a.asset_type, dclass=det.get("_class"), name=a.name, role=a.role)[0]
        for k in ("windows_host_id", "linux_host_id", "dell_server_id"):
            if isinstance(refs.get(k), int):
                out[(k, refs[k])] = (lv in ("critical", "important"), a.name or a.ip)
    return out


def findings(now: Optional[datetime] = None) -> List[dict]:
    """Every current finding: [{rule, device, key, severity, title, message, ip}]. Also keeps reboot_required_since up to date."""
    from models.database import SessionLocal, WindowsHost, LinuxHost, LinuxHostDisk, DellServer, HypervHost, HypervVM
    from services import metrics, bmc_details
    now = now or datetime.utcnow()
    out: List[dict] = []
    with SessionLocal() as db:
        imp = _important_by_ref(db)
        wins = db.query(WindowsHost).all()
        lins = db.query(LinuxHost).all()
        for kind, hosts in (("windows_host_id", wins), ("linux_host_id", lins)):
            for h in hosts:
                # 3.66: never "now" - since when a restart is pending comes from the host (note_reboot); unknown stays unknown
                if h.reboot_required and not h.reboot_required_since and not getattr(h, "reboot_since_source", None):
                    h.reboot_since_source = "unknown"
                elif not h.reboot_required and (h.reboot_required_since or getattr(h, "reboot_since_source", None)):
                    h.reboot_required_since, h.reboot_since_source = None, None
                important, _n = imp.get((kind, h.id), (False, None))
                name = h.hostname or h.ip
                r = restart_age(h.reboot_required_since, now, important)
                if r:
                    out.append({"rule": "server.restart_pending", "device": name, "ip": h.ip, "key": "", "severity": r[0], "title": "Restart pending for days",
                                "message": f"{name}: a restart has been pending for {r[1]} days (updates are not in effect until it restarts)"})
        for h in wins:
            if h.license_expires_at is None:
                continue
            lic = {"days_left": round((h.license_expires_at - now).total_seconds() / 86400, 1)}
            important, _n = imp.get(("windows_host_id", h.id), (False, None))
            a = license_alert(lic, important or bool(_DC_FS_NAME.search(h.hostname or "")))
            if a:
                name = h.hostname or h.ip
                when = h.license_expires_at.strftime("%Y-%m-%d")
                out.append({"rule": "server.license_expiring", "device": name, "ip": h.ip, "key": "", "severity": a[1],
                            "title": "Windows licence ends" if a[0] else "Windows licence has ended",
                            "message": f"{name}: {h.license_name or 'Windows'} ({'evaluation' if h.license_eval else h.license_status}) ends {when}"
                                       f" ({lic['days_left']} days) - activate a licence, or an evaluation server shuts itself down every hour"})
        disks: Dict[int, list] = {}
        for d in db.query(LinuxHostDisk).all():
            disks.setdefault(d.host_id, []).append(d)
        for h in lins:
            for d in disks.get(h.id, []):
                b = boot_space(d.mount_point, d.total_bytes, d.used_bytes, h.upgradable_count)
                if b:
                    name = h.hostname or h.ip
                    out.append({"rule": "server.boot_space", "device": name, "ip": h.ip, "key": d.mount_point, "severity": b[0],
                                "title": "/boot too small for the updates", "message": f"{name}: {b[1]}"})
        hv_by_win = {hv.windows_host_id: hv.id for hv in db.query(HypervHost).all()}
        vms: Dict[int, list] = {}
        for vm in db.query(HypervVM).all():
            if vm.cpu_usage_pct is not None and str(vm.state or "").lower() in ("running", "2"):
                vms.setdefault(vm.hyperv_host_id, []).append(vm.cpu_usage_pct)
        win_by_id = {h.id: h for h in wins}
        for s in db.query(DellServer).all():
            det = json.loads(s.details_json) if s.details_json else {}
            comps = json.loads(s.components_json) if s.components_json else {}
            watts = (det.get("power") or {}).get("watts")
            cpu_temps = [t.get("c") for t in det.get("temps") or [] if isinstance(t, dict) and t.get("c") is not None and "cpu" in str(t.get("name") or "").lower()]
            cpu_c = max(cpu_temps) if cpu_temps else None
            typ = typical(v for _a, v in metrics.points(bmc_details.series_key(s.id, "power_w"), days=7, max_points=400))
            host = win_by_id.get(s.windows_host_id)
            loads = [host.cpu_used_pct] if host is not None and host.cpu_used_pct is not None else []
            if host is not None and hv_by_win.get(host.id) in vms:
                vm_loads = vms[hv_by_win[host.id]]
                loads.append(sum(vm_loads) / len(vm_loads))
            load = max(loads) if loads else None
            pt = power_temp(watts, typ, cpu_c, load, comps.get("fans_temperature"), None)
            if pt:
                name = s.name or s.service_tag or s.idrac_ip
                out.append({"rule": "server.power_temp", "device": name, "ip": s.idrac_ip, "key": "", "severity": pt["severity"],
                            "title": {"load": "High power / temperature: load", "cooling": "High temperature: cooling", "unclear": "High power / temperature"}[pt["verdict"]],
                            "message": f"{name}: {pt['reason']}", "verdict": pt["verdict"]})
        db.commit()
    return out


def run_cycle(now: Optional[datetime] = None) -> dict:
    """Raises every finding (once; afterwards only refreshed) and closes the server.* alerts whose finding is gone."""
    from models.database import SessionLocal, SocAlert
    from services import soc
    now = now or datetime.utcnow()
    found = findings(now)
    active = set()
    for f in found:
        fp = f"{f['rule']}|{f['device'].strip().lower()}|{f['key']}"[:240]
        active.add(fp)
        detail = {"message": f["message"]}
        if f.get("verdict"):
            detail["verdict"] = f["verdict"]
        soc.raise_alert(rule=f["rule"], device=f["device"], title=f["title"], severity=f["severity"],
                        category="hardware" if f["rule"] == "server.power_temp" else "system",
                        fp_detail=f["key"], ip=f.get("ip"), detail=detail, now=now, count=0)
    with SessionLocal() as db:
        stale = [(a.rule, a.device_name, a.fingerprint) for a in db.query(SocAlert).filter(SocAlert.rule.like("server.%"), SocAlert.status.in_(soc.OPEN)).all()
                 if a.fingerprint not in active]
    for rule, device, fp in stale:
        soc.resolve(rule=rule, device=device, fp_detail=fp.split("|", 2)[2] if fp.count("|") >= 2 else "")
    _last.update(at=now.isoformat() + "Z", findings=len(found), error=None)
    return {"findings": len(found), "closed": len(stale)}


def status() -> dict:
    return dict(_last)


async def _loop():
    await asyncio.sleep(240)
    while True:
        try:
            await asyncio.get_event_loop().run_in_executor(None, run_cycle)
        except Exception as e:
            _last["error"] = f"{type(e).__name__}: {e}"
            print(f"[server_health] cycle error: {type(e).__name__}: {e}")
        await asyncio.sleep(INTERVAL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())
