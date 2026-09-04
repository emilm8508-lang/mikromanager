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

_ISM_SCRIPT = r"""
try {
    $cs = Get-CimInstance -Namespace root\cimv2\dell -ClassName DCIM_ComputerSystem -ErrorAction Stop
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
        result = session.run_ps(_ISM_SCRIPT)
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
_RACADM_SCRIPT = r"""
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
if (-not $racadm) {
    Write-Output "@@NOT_FOUND@@"
} else {
    Write-Output "@@SYSINFO@@"
    & $racadm.Source getsysinfo
    Write-Output "@@SENSORS@@"
    & $racadm.Source getsensorinfo
}
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
        result = session.run_ps(_RACADM_SCRIPT)
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


_SYSINFO_LINE_RE = re.compile(r"^([A-Za-z][\w .()/-]*?)\s*=\s*(.+)$", re.MULTILINE)
# getsensorinfo's table columns: Type, Name, Status, Reading, Units — names
# and thresholds can contain spaces, so this only anchors on the trailing
# status word (a small fixed vocabulary) rather than trying to split all
# columns positionally.
_SENSOR_LINE_RE = re.compile(
    r"^(Fan|Temp|Voltage|Battery|Power Supply|Amperage|Memory|CPU)\S*\s+.+?\s+"
    r"(Ok|Critical|Warning|Non-Critical|Non-Recoverable|Unknown)\b", re.MULTILINE | re.IGNORECASE,
)

_RACADM_STATUS_MAP = {
    "ok": "OK", "warning": "Warning", "non-critical": "Warning",
    "critical": "Critical", "non-recoverable": "Critical", "unknown": None,
}


def _parse_racadm(sysinfo: str, sensors: str) -> dict:
    fields = dict(_SYSINFO_LINE_RE.findall(sysinfo))
    overall = None
    for key in ("System Health", "Health", "Overall Health"):
        if key in fields:
            overall = fields[key].strip()
            break

    sensor_healths = []
    for sensor_type, status in _SENSOR_LINE_RE.findall(sensors):
        mapped = _RACADM_STATUS_MAP.get(status.strip().lower())
        if mapped:
            sensor_healths.append((sensor_type.strip().lower(), mapped))

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
        "bios_version": fields.get("BIOS Version"),
        "fans_temperature": _worst_for("fan", "temp"),
        "power": _worst_for("power", "voltage"),
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
        result = session.run_ps(_OMSA_SCRIPT)
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
    against the WindowsHost identified by host_id — using that host's
    own already-configured shared WinRM credential (services/
    windows_manage.py's WindowsManageSettings), not a separate one.
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

    cred = windows_manage._shared_credential()
    if not cred:
        return {"ok": False, "error": "no shared Windows credential configured "
                                       "(zakładka Windows → ustawienia)"}
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
        return {"ok": True, "access_method": "local_racadm", **parsed,
                "power_state": None, "service_tag": parsed.get("service_tag"),
                "components": {
                    "system": parsed.get("health_rollup"),
                    "cpu": None, "memory": None,
                    "power": parsed.get("power"), "fans_temperature": parsed.get("fans_temperature"),
                    "storage": None,
                }, "sel_entries": []}

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
