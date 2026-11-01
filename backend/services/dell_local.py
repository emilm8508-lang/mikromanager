"""
Local (in-band) Dell iDRAC health query, for a server whose iDRAC has no
routable network address — confirmed with the user: several of their Dell
servers only expose iDRAC on the internal USB NIC (typically a fixed
169.254.x.x address), reachable ONLY from software running on that same
physical host's own OS. Since every host here is Windows Server (with or
without Hyper-V), this WinRMs into the companion WindowsHost and runs a
LOCAL query there, over the SAME shared credential windows_manage.py
already uses for that host — reusing the existing WinRM plumbing rather
than needing a whole separate agent per hypervisor.

Two different Dell tools can answer this locally, and per the user
("różnie, najlepiej żeby agent był uniwersalny i sprawdzał wszystkie
możliwości" — it varies, best if the agent tries every possibility),
neither is assumed present — both are tried, in order:

  1. iDRAC Service Module (iSM) — a lightweight, actively-maintained Dell
     service that exposes iDRAC data to the host OS via WMI. Modern,
     preferred when present.
  2. RACADM CLI — Dell's older command-line tool; run locally (no -r/
     remote-host flag) it talks to the LOCAL iDRAC over the same internal
     channel regardless of iDRAC's own network configuration.

Neither this module's WMI namespace/class name NOR its exact racadm
command output has been verified against a live Dell server or iDRAC in
this environment (no real Dell hardware reachable here) — both paths are
written defensively (a wrong namespace/class/command just fails cleanly
and falls through to the next method, or to a clear "neither tool found"
error) and are the part of this whole feature most likely to need
adjustment once tried against real hardware.
"""
import asyncio
import json
import re
from typing import Optional

from services import vuln_scan as vs
from services import windows_manage


# ── Method 1: iDRAC Service Module (WMI) ───────────────────────────────────

# Namespace confirmed live (root\cimv2\dell does not exist; iSM registers
# root\cimv2\DCIM). With iDRAC's "WMI Information" option disabled that
# namespace holds only DCIM_iSMService, so this fails with "Invalid class"
# and RACADM takes over. The class name itself is still unverified.
_ISM_SCRIPT = r"""
try {
    $cs = Get-CimInstance -Namespace root\cimv2\DCIM -ClassName DCIM_ComputerSystem -ErrorAction Stop
    $cs | Select-Object * | ConvertTo-Json -Compress -Depth 4
} catch {
    "@@ERROR@@" + $_.Exception.Message
}
"""


def _check_ism_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Best-effort: a missing
    namespace/class (iSM not installed, or a different version exposing a
    different class under a different name) is expected and treated as
    "not available", but the UNDERLYING PowerShell/WMI error is always
    kept in "error" — needed to tell "iSM genuinely not installed" apart
    from "iSM IS installed (confirmed via its own web UI showing 'Status:
    Running') but this module's guessed namespace/class name is wrong for
    this version", which is exactly the kind of mismatch this whole
    function is least verified against (no real Dell hardware in the dev
    environment) and needs a real error message from the field to fix."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=30, operation_timeout_sec=25,
    )
    try:
        result = vs._run_ps_safe(session, _ISM_SCRIPT)
        if result.status_code != 0:
            return {"ok": False, "available": False,
                    "error": result.std_err.decode("utf-8", errors="ignore")[-500:] or "PowerShell exited non-zero"}
        raw = result.std_out.decode("utf-8", errors="ignore").strip()
        if raw.startswith("@@ERROR@@"):
            return {"ok": False, "available": False, "error": raw[len("@@ERROR@@"):][:500]}
        if not raw:
            return {"ok": False, "available": False, "error": "empty response (no error, no data)"}
        try:
            parsed = json.loads(raw)
        except Exception:
            return {"ok": False, "available": False, "error": f"non-JSON response: {raw[:300]}"}
        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else {}
        if not isinstance(parsed, dict) or not parsed:
            return {"ok": False, "available": False, "error": "query succeeded but returned no properties"}
        return {"ok": True, "available": True, "raw": parsed}
    finally:
        vs._close_winrm(session)


def _parse_ism(raw: dict) -> dict:
    """iSM's DCIM_ComputerSystem is expected to carry an overall health
    property — property NAME not confirmed live, so this checks a few
    plausible candidates defensively rather than assuming one specific
    key exists."""
    health = None
    for key in ("HealthState", "Status", "OperationalStatus", "PrimaryStatus"):
        if raw.get(key):
            health = str(raw[key])
            break
    return {
        "health_rollup": health,
        "model": raw.get("Model"),
        "service_tag": raw.get("IdentifyingNumber") or raw.get("SerialNumber"),
    }


# ── Method 2: RACADM CLI ────────────────────────────────────────────────────

# Run locally (no -r host) so it talks to whichever iDRAC is physically
# attached to THIS machine over the internal channel, regardless of
# whether that iDRAC has a routable IP at all.
_RACADM_FIND = r"""
$racadm = Get-Command racadm.exe -ErrorAction SilentlyContinue
if (-not $racadm) {
    $candidates = @(
        "$env:ProgramFiles\Dell\SysMgt\rac5\racadm.exe",
        "${env:ProgramFiles(x86)}\Dell\SysMgt\rac5\racadm.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $racadm = Get-Item $c; break } }
}
if (-not $racadm) {
    # Confirmed live: several hosts have racadm installed under a path
    # neither PATH nor the two hardcoded rac5 locations above cover
    # (different OpenManage/iDRAC-tools package versions use different
    # subfolder names) — a bounded recursive search under Dell's own
    # Program Files tree finds it regardless of the exact version.
    $found = Get-ChildItem -Path "$env:ProgramFiles\Dell","${env:ProgramFiles(x86)}\Dell" `
        -Filter "racadm.exe" -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $racadm = $found }
}
# Get-Command gives .Source, a file found on disk only .FullName
$exe = if ($racadm) { if ($racadm.Source) { $racadm.Source } else { $racadm.FullName } } else { $null }
"""
_RACADM_SCRIPT = _RACADM_FIND + r"""
if (-not $exe) {
    Write-Output "@@NOT_FOUND@@"
} else {
    Write-Output "@@SYSINFO@@"
    & $exe getsysinfo
    Write-Output "@@SENSORS@@"
    & $exe getsensorinfo
}
"""
# Full hardware inventory (CPUs, DIMMs, controllers, disks, virtual disks,
# fans, power supplies, NICs, system rollups). Slow — racadm itself warns
# it "may take several minutes" — so it runs as its own WinRM call with a
# long timeout, and a failure here never loses getsysinfo/getsensorinfo.
_RACADM_HWINV_SCRIPT = _RACADM_FIND + r"""
if ($exe) { & $exe hwinventory }
"""


def _check_racadm_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Locates racadm.exe (PATH,
    or the two standard Dell OpenManage install locations) and runs the
    two most universally-available read-only commands: getsysinfo (system
    identity + an overall health line on most versions) and getsensorinfo
    (per-sensor fan/temperature/voltage/PSU table) — deliberately not
    `racadm storage get`/`racadm raid get` here, since that subsystem's
    exact syntax varies enough across RACADM versions that guessing at it
    risks a confusing wrong-command error rather than a clean skip."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=45, operation_timeout_sec=40,
    )
    try:
        result = vs._run_ps_safe(session, _RACADM_SCRIPT)
        if result.status_code != 0:
            return {"ok": False, "error": result.std_err.decode("utf-8", errors="ignore")[-2000:]}
        output = result.std_out.decode("utf-8", errors="ignore")
        if "@@NOT_FOUND@@" in output:
            return {"ok": False, "available": False, "error": "racadm.exe not found on this host"}
        _, _, rest = output.partition("@@SYSINFO@@")
        sysinfo, _, sensors = rest.partition("@@SENSORS@@")
        return {"ok": True, "available": True, "sysinfo": sysinfo, "sensors": sensors}
    finally:
        vs._close_winrm(session)


def _racadm_hwinventory_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> str:
    """Blocking. The raw `racadm hwinventory` text, "" when it fails."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=200, operation_timeout_sec=190,
    )
    try:
        result = vs._run_ps_safe(session, _RACADM_HWINV_SCRIPT)
        return result.std_out.decode("utf-8", errors="ignore") if result.status_code == 0 else ""
    finally:
        vs._close_winrm(session)


_SYSINFO_LINE_RE = re.compile(r"^([A-Za-z][\w .()/-]*?)\s*=\s*(.+)$", re.MULTILINE)
# Confirmed live (PowerEdge T150, racadm 10.3): getsensorinfo prints one
# table per "Sensor Type : TEMPERATURE" / FAN / VOLTAGE / PROCESSOR /
# MEMORY / ... header, each row "<Sensor Name>  <Status>  <Reading> ...".
# Names contain single spaces, columns are separated by 2+ spaces, so a
# row is anchored on the first status word after such a gap. Rows without
# a status word (INTRUSION, REDUNDANCY, MAX DIMM TEMPERATURE, "N/A" for
# empty DIMM slots) simply don't match.
_SENSOR_TYPE_RE = re.compile(r"^\s*Sensor Type\s*:\s*(.+?)\s*$", re.IGNORECASE)
_SENSOR_ROW_RE = re.compile(
    r"^\S.*?\s{2,}(Ok|Critical|Warning|Non-Critical|Non-Recoverable|Unknown)\b", re.IGNORECASE,
)

# "Error" / "Degraded" confirmed live in hwinventory on a PowerEdge R640
# with a power supply that lost AC input (PrimaryStatus = Error).
_RACADM_STATUS_MAP = {
    "ok": "OK", "warning": "Warning", "non-critical": "Warning", "degraded": "Warning",
    "critical": "Critical", "non-recoverable": "Critical", "error": "Critical", "unknown": None,
}


def _st(v: Optional[str]) -> Optional[str]:
    return _RACADM_STATUS_MAP.get((v or "").strip().lower()) if v else None


def _num(v: Optional[str]) -> Optional[float]:
    """Leading number of "32768 MB", "5640 RPM", "25 %", "2666 MT/s"."""
    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", v or "")
    return float(m.group(1)) if m else None


def _int(v: Optional[str]) -> Optional[int]:
    n = _num(v)
    return int(n) if n is not None else None


def _sensor_readings(sensors: str) -> dict:
    """Readings from getsensorinfo (format confirmed live on a T150): every
    temperature with its upper thresholds, every fan's RPM and PWM, and the
    power draw when the server has a power-consumption sensor. Columns are
    separated by 2+ spaces: name, status, reading, then thresholds."""
    temps, fans, watts = [], [], None
    sensor_type = ""
    for line in sensors.splitlines():
        m = _SENSOR_TYPE_RE.match(line)
        if m:
            sensor_type = m.group(1).lower()
            continue
        if not line.strip() or line.lstrip().startswith(("<", "[")):
            continue
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 3:
            continue
        name, status, reading = cols[0], cols[1], cols[2]
        if sensor_type.startswith("temp") and reading.upper().endswith("C"):
            crit = _num(cols[4]) if len(cols) > 4 else None
            warn = _num(cols[6]) if len(cols) > 6 and not cols[6].upper().startswith("NA") else None
            temps.append({"name": name, "c": _num(reading), "warn": warn, "crit": crit, "health": _st(status)})
        elif sensor_type.startswith("fan") and "RPM" in reading.upper():
            pwm = next((_num(c) for c in cols[3:] if c.endswith("%")), None)
            fans.append({"name": name, "rpm": _num(reading), "pwm": pwm, "health": _st(status)})
        elif ("pwr" in name.lower() or "power" in name.lower()) and reading.upper().endswith("W") and watts is None:
            watts = _num(reading)
    return {"temps": temps, "fans": fans, "watts": watts}


def _parse_hwinventory(text: str) -> dict:
    """racadm hwinventory → the same detail shape idrac_client.collect_details()
    returns for Redfish. Format confirmed live (PowerEdge R640, iDRAC 7.00):
    blocks "[InstanceID: FQDD]" of "Key = Value" lines, each with a "Device
    Type"; the same FQDD can appear twice (once more as a PCIDevice)."""
    blocks = []
    for chunk in re.split(r"^\[InstanceID:", text, flags=re.MULTILINE)[1:]:
        f = {}
        for line in chunk.splitlines()[1:]:
            if " = " in line or line.rstrip().endswith(" ="):
                k, _, v = line.partition("=")
                f[k.strip()] = v.strip()
        if f.get("Device Type"):
            blocks.append(f)
    by = lambda t: [b for b in blocks if b.get("Device Type") == t]
    if not blocks:
        return {}

    s = (by("System") or [{}])[0]
    rollups = {k[:-len("RollupStatus")]: _st(v) for k, v in s.items()
               if k.endswith("RollupStatus") and k != "RollupStatus" and _st(v)}
    idrac = (by("iDRACCard") or [{}])[0]
    out: dict = {"source": "racadm", "system": {
        "model": s.get("Model"), "service_tag": s.get("ServiceTag"), "bios": s.get("BIOSVersionString"),
        "hostname": s.get("HostName"), "power_state": s.get("PowerState"), "idrac_fw": idrac.get("FirmwareVersion"),
        "generation": s.get("SystemGeneration"), "exhaust_c": _num(s.get("EstimatedExhaustTemperature")),
        "airflow_cfm": _num(s.get("EstimatedSystemAirflow")), "dimm_slots": _int(s.get("MaxDIMMSlots")),
        "dimm_populated": _int(s.get("PopulatedDIMMSlots")),
        "mem_gb": round(_num(s.get("SysMemTotalSize")) / 1024, 1) if _num(s.get("SysMemTotalSize")) else None,
        "health": _st(s.get("RollupStatus") or s.get("PrimaryStatus")), "rollups": rollups,
    }}
    out["cpus"] = [{
        "name": c.get("DeviceDescription"), "model": c.get("Model"), "cores": _int(c.get("NumberOfEnabledCores")),
        "threads": _int(c.get("NumberOfEnabledThreads")), "mhz": _int(c.get("CurrentClockSpeed")),
        "max_mhz": _int(c.get("MaxClockSpeed")), "health": _st(c.get("PrimaryStatus")),
    } for c in by("CPU")]
    out["dimms"] = sorted([{
        "slot": (d.get("DeviceDescription") or "").replace("DIMM ", "") or d.get("FQDD"),
        "gb": round(_num(d.get("Size")) / 1024, 1) if _num(d.get("Size")) else None,
        "type": " ".join(x for x in (d.get("MemoryType"), d.get("MemoryTypeExtended")) if x) or None,
        "mhz": _int(d.get("CurrentOperatingSpeed")), "vendor": d.get("Manufacturer"),
        "part": d.get("PartNumber") or None, "ranks": d.get("Rank"), "health": _st(d.get("PrimaryStatus")),
    } for d in by("Memory")], key=lambda d: d["slot"] or "")

    disks, vdisks = by("PhysicalDisk"), by("VirtualDisk")
    used = {(x.get("FQDD") or "").split(":")[-1] for x in disks + vdisks}
    media = {"Solid State Drive": "SSD", "Hard Disk Drive": "HDD"}
    out["storage"] = {
        "controllers": [{
            "name": c.get("ProductName"), "firmware": c.get("ControllerFirmwareVersion"),
            "cache_mb": _int(c.get("CacheSizeInMB")), "health": _st(c.get("RollupStatus") or c.get("PrimaryStatus")),
        } for c in by("Controller") if c.get("FQDD") in used],
        "drives": [{
            "name": f"Disk {d.get('Slot')}" if d.get("Slot") else d.get("DeviceDescription"), "model": d.get("Model"),
            "media": media.get(d.get("MediaType"), d.get("MediaType")), "protocol": d.get("BusProtocol"),
            "gb": round(_num(d.get("SizeInBytes")) / 1e9, 1) if _num(d.get("SizeInBytes")) else None,
            "failure_predicted": None if not d.get("PredictiveFailureState") else "present" in d["PredictiveFailureState"].lower(),
            "life_left_pct": _num(d.get("RemainingRatedWriteEndurance")), "firmware": d.get("Revision"),
            "serial": d.get("SerialNumber") or None, "state": d.get("RaidStatus"), "health": _st(d.get("PrimaryStatus")),
        } for d in disks],
        "volumes": [{
            "name": v.get("Name"), "raid": v.get("RAIDTypes"),
            "gb": round(_num(v.get("SizeInBytes")) / 1e9, 1) if _num(v.get("SizeInBytes")) else None,
            "state": v.get("RAIDStatus"), "health": _st(v.get("PrimaryStatus")),
        } for v in vdisks],
    }
    fans = by("Fan")
    out["fans"] = [{
        "name": f.get("DeviceDescription"), "rpm": _num(f.get("CurrentReading")), "pwm": _num(f.get("PWM")),
        "health": _st(f.get("PrimaryStatus")),
    } for f in fans]
    fan_red = next((f.get("RedundancyStatus") for f in fans if f.get("RedundancyStatus")), None)
    out["fan_redundancy"] = None if not fan_red else ("OK" if "full" in fan_red.lower() else "Warning")
    psus = by("PowerSupply")
    psu_red = next((p.get("RedundancyStatus") for p in psus if p.get("RedundancyStatus")), None)
    out["power"] = {
        "watts": None, "capacity_w": None,
        "redundancy": None if not psu_red else ("OK" if "full" in psu_red.lower() else "Critical" if "lost" in psu_red.lower() else "Warning"),
        "psus": [{
            "name": p.get("DeviceDescription"), "model": p.get("Model"),
            "capacity_w": _int(p.get("TotalOutputPower") or p.get("EffectiveCapacity")), "output_w": None,
            "input_v": _num(p.get("InputVoltage")), "firmware": p.get("FirmwareVersion"),
            "state": p.get("DetailedState"), "health": _st(p.get("PrimaryStatus")),
        } for p in psus],
    }
    out["nics"] = [{
        "name": n.get("DeviceDescription"), "model": re.sub(r"\s+-\s+[0-9A-F:]{17}$", "", n.get("ProductName") or "", flags=re.I) or None,
        "mac": n.get("CurrentMACAddress"), "speed_mbps": _int(n.get("LinkSpeed")),
        "link": "LinkUp" if n.get("LinkSpeed") else "LinkDown", "health": _st(n.get("PrimaryStatus")),
    } for n in by("NIC")]
    out["batteries"] = [{"name": b.get("DeviceDescription"), "health": _st(b.get("PrimaryStatus"))} for b in by("ControllerBattery")]
    return out


def _racadm_details(sysinfo: str, sensors: str, hwinv: str) -> dict:
    """The RACADM detail view: hwinventory when it came back, with the live
    temperatures (and fans, when hwinventory had none) from getsensorinfo."""
    details = _parse_hwinventory(hwinv) if hwinv else {}
    if not details:
        fields = {k.strip(): v.strip() for k, v in _SYSINFO_LINE_RE.findall(sysinfo)}
        details = {"source": "racadm", "system": {
            "model": fields.get("System Model"), "service_tag": fields.get("Service Tag"),
            "bios": fields.get("System BIOS Version"), "hostname": fields.get("Host Name"),
            "power_state": (fields.get("Power Status") or "").capitalize() or None,
            "idrac_fw": fields.get("Firmware Version"), "health": _st(fields.get("RollupStatus")),
            "exhaust_c": _num(fields.get("EstimatedExhaustTemperature")),
        }}
    r = _sensor_readings(sensors)
    details["temps"] = r["temps"]
    if r["fans"] and not details.get("fans"):
        details["fans"] = r["fans"]
    if r["watts"] is not None:
        details.setdefault("power", {"psus": []})["watts"] = r["watts"]
    return details


def _parse_racadm(sysinfo: str, sensors: str) -> dict:
    # Strip both sides — WinRM output carries \r\n line endings, and "."
    # in the regex happily swallows the \r into the value.
    fields = {k.strip(): v.strip() for k, v in _SYSINFO_LINE_RE.findall(sysinfo)}
    # Confirmed live (PowerEdge T150, iDRAC 7.30, racadm 10.3): the overall
    # health line is "RollupStatus = Ok" — the other keys are kept for
    # older RACADM versions that may name it differently.
    overall = None
    for key in ("RollupStatus", "System Health", "Health", "Overall Health"):
        if key in fields:
            overall = _RACADM_STATUS_MAP.get(fields[key].lower(), fields[key])
            break
    power = fields.get("Power Status")

    sensor_healths = []
    sensor_type = ""
    for line in sensors.splitlines():
        m = _SENSOR_TYPE_RE.match(line)
        if m:
            sensor_type = m.group(1).lower()
            continue
        m = _SENSOR_ROW_RE.match(line)
        if m and sensor_type:
            mapped = _RACADM_STATUS_MAP.get(m.group(1).lower())
            if mapped:
                sensor_healths.append((sensor_type, mapped))

    def _worst_for(*prefixes: str) -> Optional[str]:
        # NOT "_worst_for(a) or _worst_for(b)" — "OK" is a non-empty,
        # truthy string, so that pattern would short-circuit and never
        # even look at the second prefix's readings once the first one
        # had ANY match at all, silently ignoring e.g. every temperature
        # sensor whenever at least one fan reading was present.
        order = {"Critical": 0, "Warning": 1, "OK": 2}
        matching = [h for t, h in sensor_healths if any(t.startswith(p) for p in prefixes)]
        return min(matching, key=lambda h: order[h]) if matching else None

    return {
        "health_rollup": overall,
        "model": fields.get("System Model") or fields.get("Model"),
        "service_tag": fields.get("Service Tag") or fields.get("System Service Tag"),
        "bios_version": fields.get("System BIOS Version") or fields.get("BIOS Version"),
        "power_state": power.capitalize() if power else None,
        "fans_temperature": _worst_for("fan", "temp"),
        "power": _worst_for("power", "voltage", "battery", "current", "amperage"),
        "cpu": _worst_for("processor"),
        "memory": _worst_for("memory"),
    }


# ── Method 3: OpenManage Server Administrator (OMSA) CLI ───────────────────

# Confirmed with the user: at least one server has "Dell Server
# Administrator" (OMSA) installed rather than iSM/RACADM — an older,
# heavier Dell tool (own web UI on port 1311 + omreport/omconfig CLI).
# Its LOCAL CLI use is authenticated entirely by the OS session running
# it (whoever is an admin on the box can query it) — no separate iDRAC
# account involved at all, which is exactly what the user described
# ("uwierzytelnienie tam jest danymi konta admin serwera"). That means
# no credential handling is needed here beyond the shared WinRM session
# already used for iSM/RACADM above.
#
# Like iSM's WMI class names, the exact omreport output below is
# UNVERIFIED against a live OMSA install from this dev environment (no
# real Dell hardware here) — written defensively (a parsing miss just
# leaves that one field None, never crashes) and is the next thing to
# confirm/adjust against real output, same as iSM/RACADM were earlier.
_OMSA_SCRIPT = r"""
$omreport = Get-Command omreport.exe -ErrorAction SilentlyContinue
if (-not $omreport) {
    $found = Get-ChildItem -Path "$env:ProgramFiles\Dell","${env:ProgramFiles(x86)}\Dell" `
        -Filter "omreport.exe" -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $omreport = $found }
}
if (-not $omreport) {
    Write-Output "@@NOT_FOUND@@"
} else {
    Write-Output "@@CHASSIS@@"
    & $omreport.Source chassis
    Write-Output "@@SUMMARY@@"
    & $omreport.Source system summary
}
"""


def _check_omsa_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking — run via loop.run_in_executor. Locates omreport.exe (PATH,
    or a bounded recursive search under Dell's Program Files tree — OMSA's
    install layout varies by version) and runs the two most universally
    stable read-only commands: `chassis` (per-component health summary)
    and `system summary` (identity — model/service tag/BIOS)."""
    import winrm
    user = vs._ntlm_user(username, domain)
    scheme = "https" if port == 5986 else "http"
    session = winrm.Session(
        f"{scheme}://{ip}:{port}/wsman",
        auth=(user, password),
        transport="ntlm",
        server_cert_validation="ignore",
        read_timeout_sec=45, operation_timeout_sec=40,
    )
    try:
        result = vs._run_ps_safe(session, _OMSA_SCRIPT)
        if result.status_code != 0:
            return {"ok": False, "error": result.std_err.decode("utf-8", errors="ignore")[-2000:]}
        output = result.std_out.decode("utf-8", errors="ignore")
        if "@@NOT_FOUND@@" in output:
            return {"ok": False, "available": False, "error": "omreport.exe not found on this host"}
        _, _, rest = output.partition("@@CHASSIS@@")
        chassis, _, summary = rest.partition("@@SUMMARY@@")
        return {"ok": True, "available": True, "chassis": chassis, "summary": summary}
    finally:
        vs._close_winrm(session)


# omreport chassis prints a "SEVERITY : COMPONENT" table, e.g.
# "Ok       : Fans" — anchored on the severity word at line start since
# component names themselves can contain colons/spaces.
_OMSA_HEALTH_LINE_RE = re.compile(
    r"^(Ok|Critical|Warning|Non-Critical|Non-Recoverable|Unknown)\s*:\s*(.+?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
# omreport system summary prints a loose "Attribute<spaces>Value" table.
_OMSA_ATTR_LINE_RE = re.compile(r"^([A-Za-z][\w .()/-]*?)\s{2,}(\S.*?)\s*$", re.MULTILINE)

_OMSA_STATUS_MAP = {
    "ok": "OK", "warning": "Warning", "non-critical": "Warning",
    "critical": "Critical", "non-recoverable": "Critical", "unknown": None,
}


def _parse_omsa(chassis: str, summary: str) -> dict:
    component_healths = []
    for status, component in _OMSA_HEALTH_LINE_RE.findall(chassis):
        mapped = _OMSA_STATUS_MAP.get(status.strip().lower())
        if mapped:
            component_healths.append((component.strip().lower(), mapped))

    def _worst_for(*prefixes: str) -> Optional[str]:
        order = {"Critical": 0, "Warning": 1, "OK": 2}
        matching = [h for c, h in component_healths if any(p in c for p in prefixes)]
        return min(matching, key=lambda h: order[h]) if matching else None

    order = {"Critical": 0, "Warning": 1, "OK": 2}
    all_healths = [h for _, h in component_healths]
    overall = min(all_healths, key=lambda h: order[h]) if all_healths else None

    fields = dict(_OMSA_ATTR_LINE_RE.findall(summary))
    return {
        "health_rollup": overall,
        "model": fields.get("System Model") or fields.get("Chassis Model"),
        "service_tag": fields.get("System Service Tag") or fields.get("Service Tag"),
        "bios_version": fields.get("System BIOS Version") or fields.get("BIOS Version"),
        "fans_temperature": _worst_for("fan", "temperature"),
        "power": _worst_for("power", "voltage", "battery"),
    }


# ── Orchestration ────────────────────────────────────────────────────────

async def collect_local_health(host_id: int) -> dict:
    """Tries iSM, then RACADM, then OMSA (omreport) — in that order,
    against the WindowsHost identified by host_id — using that SPECIFIC
    host's own resolved credential (its own per-host override if one is
    assigned in the Windows tab, else the shared WinRM credential — see
    windows_manage._credential_for_host()'s docstring for why a per-host
    override exists at all). Previously always used the shared credential
    directly regardless of any per-host override, so a host whose
    correct credential differed from the shared one failed identically
    across ALL THREE local methods with the same generic "credentials
    rejected" error — that error actually came from the WinRM/NTLM
    handshake itself failing before any of the three tools got a chance
    to run, not from the tools individually rejecting a working session.
    Per the user's explicit ask ("różnie, najlepiej żeby agent był
    uniwersalny i sprawdzał wszystkie możliwości"), all three are tried
    defensively — different servers have different tools installed, and
    OMSA specifically is confirmed present on at least one of the user's
    servers where iSM/RACADM aren't. Returns {"ok": False, "error": ...}
    only if ALL THREE methods fail to find any usable tool at all."""
    from models.database import SessionLocal, WindowsHost
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host:
            return {"ok": False, "error": "companion Windows host not found"}
        ip, port = host.ip, host.winrm_port

    cred = windows_manage._credential_for_host(host)
    if not cred:
        return {"ok": False, "error": "no credential configured for this Windows host "
                                       "(assign one on its card, or set a shared credential "
                                       "in zakładka Windows → ustawienia)"}
    username, password, domain = cred

    loop = asyncio.get_event_loop()

    try:
        ism = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _check_ism_sync, ip, port, username, password, domain),
            timeout=40,
        )
    except Exception as e:
        ism = {"ok": False, "available": False, "error": str(e)}

    if ism.get("ok") and ism.get("available"):
        parsed = _parse_ism(ism["raw"])
        return {"ok": True, "access_method": "local_ism", **parsed,
                "power_state": None, "components": {
                    "system": parsed.get("health_rollup"),
                    "cpu": None, "memory": None, "power": None,
                    "fans_temperature": None, "storage": None,
                }, "sel_entries": []}

    try:
        racadm = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _check_racadm_sync, ip, port, username, password, domain),
            timeout=60,
        )
    except Exception as e:
        racadm = {"ok": False, "available": False, "error": str(e)}

    if racadm.get("ok") and racadm.get("available"):
        parsed = _parse_racadm(racadm["sysinfo"], racadm["sensors"])
        try:
            hwinv = await asyncio.wait_for(
                loop.run_in_executor(vs._EXECUTOR, _racadm_hwinventory_sync, ip, port, username, password, domain),
                timeout=210,
            )
        except Exception:
            hwinv = ""
        details = _racadm_details(racadm["sysinfo"], racadm["sensors"], hwinv)
        # hwinventory's own rollups (PSRollupStatus, StorageRollupStatus, ...)
        # see what getsensorinfo does not — a power supply without AC input
        # shows there as "Error" while every voltage sensor still reads Ok.
        ru = (details.get("system") or {}).get("rollups") or {}
        worst = lambda *v: next((h for h in ("Critical", "Warning", "OK") if h in v), None)
        return {"ok": True, "access_method": "local_racadm", **parsed,
                "service_tag": parsed.get("service_tag"),
                "health_rollup": worst(parsed.get("health_rollup"), (details.get("system") or {}).get("health")),
                "components": {
                    "system": worst(parsed.get("health_rollup"), (details.get("system") or {}).get("health")),
                    "cpu": worst(parsed.get("cpu"), ru.get("CPU")),
                    "memory": worst(parsed.get("memory"), ru.get("Memory")),
                    "power": worst(parsed.get("power"), ru.get("PS"), ru.get("Volt"), ru.get("Current")),
                    "fans_temperature": worst(parsed.get("fans_temperature"), ru.get("Fan"), ru.get("Temp")),
                    "storage": ru.get("Storage"),
                }, "sel_entries": [], "details": details}

    try:
        omsa = await asyncio.wait_for(
            loop.run_in_executor(vs._EXECUTOR, _check_omsa_sync, ip, port, username, password, domain),
            timeout=60,
        )
    except Exception as e:
        omsa = {"ok": False, "available": False, "error": str(e)}

    if omsa.get("ok") and omsa.get("available"):
        parsed = _parse_omsa(omsa["chassis"], omsa["summary"])
        return {"ok": True, "access_method": "local_omsa", **parsed,
                "power_state": None, "components": {
                    "system": parsed.get("health_rollup"),
                    "cpu": None, "memory": None,
                    "power": parsed.get("power"), "fans_temperature": parsed.get("fans_temperature"),
                    "storage": None,
                }, "sel_entries": []}

    # Surface ALL THREE underlying errors instead of one generic "is one
    # of them installed?" message — confirmed necessary live: a host can
    # show iSM as "Status: Running" in its own web UI yet still fail here,
    # meaning the real problem is this module's guessed WMI namespace/
    # class name (or racadm.exe's/omreport.exe's path), not absence of
    # the tool. Without the actual per-method error there was no way to
    # tell those apart.
    return {"ok": False, "error": (
        f"iSM: {ism.get('error', 'unknown error')} | "
        f"RACADM: {racadm.get('error', 'unknown error')} | "
        f"OMSA: {omsa.get('error', 'unknown error')}"
    )}
