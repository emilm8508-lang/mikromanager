"""
Remote access tools on the hosts - AnyDesk first (3.78, round 3 stage E of docs/plan-runda-3.md).

Never guessed, always with its source and when it was read:
  Windows (WinRM, every RECHECK_H per host, with the host log read)  the uninstall key (64- and 32-bit), the AnyDesk service (state, start
           mode), AnyDesk.exe's file version, AnyDesk processes outside the install folder (portable), AnyDesk*.exe in the users' Downloads /
           Desktop (one level, no disk search), from C:\\ProgramData\\AnyDesk\\system.conf ONLY the AnyDesk ID and a yes / no for unattended
           access (whether an unattended password / profile is set - never its value), the last incoming connections from
           connection_trace.txt (also logons, source anydesk_trace)
  Linux (SSH)  dpkg / rpm, systemctl, the ID from /etc/anydesk/system.conf (that key only)
  network      a host without either that talks to AnyDesk's relays (TCP 6568) is "unknown, likely (network)" - never "present"

The model is general (remote_access_tools: tool, present, install_type, version ...): another tool is a new detector, not a migration.

Rules (data/remote_access.json "rules", on by default): a new AnyDesk (medium; high on an important / critical asset), a portable AnyDesk
running on a server (high - a common way in for intruders), unattended access on a server or critical asset (medium), a version older than
min_version (8.0.8 by default: after AnyDesk's 2024 incident its old code-signing certificate was revoked and 8.0.8 is the release AnyDesk
pointed users to - kept in the settings, not in the code).

Personal data: an AnyDesk ID and the IDs that connected identify devices and, through them, people - the same retention and access as the
logons (services/logons.py): Central's MCP shows the IDs to an admin account only.
"""
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, RemoteAccessTool

RECHECK_H = 6
_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access.json")
# the releases signed with AnyDesk's new certificate after its 2024 incident: 7.0.15 on the 7.x line, 8.0.8 on 8.x (older ones were
# signed with the stolen, now revoked certificate - AnyDesk's 8.0.8 changelog: "Exchanged code signing certificate ... Please update.")
DEFAULTS = {"min_version": "8.0.8", "min_versions": {"7": "7.0.15", "8": "8.0.8"}, "rules": {"new_install": True, "portable_on_server": True, "unattended": True, "outdated": True}}
ANYDESK_PORT = 6568
_net_seen: Dict[str, float] = {}


def settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_PATH, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d.get("min_version"), str) and re.fullmatch(r"\d+(\.\d+){0,3}", d["min_version"]):
            s["min_version"] = d["min_version"]
            s["min_versions"] = {}                         # one threshold set by the operator replaces the per-line ones
        for k, v in (d.get("rules") or {}).items():
            if k in s["rules"] and isinstance(v, bool):
                s["rules"][k] = v
    except (OSError, ValueError, AttributeError):
        pass
    return s


def _vt(v: Optional[str]):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or None


def outdated(version: Optional[str], minimum: Optional[str] = None) -> Optional[bool]:
    """Older than the minimum of its own line (7.x: 7.0.15, 8.x: 8.0.8), or than one minimum the operator set; a line before 7 is old."""
    a = _vt(version)
    if a is None:
        return None
    s = settings()
    per = s.get("min_versions") or {}
    if minimum is None and per:
        if str(a[0]) in per:
            return a < _vt(per[str(a[0])])
        lowest = min((_vt(v) for v in per.values()), default=None)
        return a < lowest if lowest and a[0] < lowest[0] else False
    b = _vt(minimum or s["min_version"])
    return None if b is None else a < b


# ── Windows ───────────────────────────────────────────────────────────────────

WINDOWS_SCRIPT = r"""
$o = [ordered]@{ reg = $null; svc = $null; file = $null; procs = @(); found = @(); id = $null; unattended = $null; trace = @() }
foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk') {
  if (Test-Path $k) { $p = Get-ItemProperty $k; $o.reg = [ordered]@{ version = [string]$p.DisplayVersion; path = [string]$p.InstallLocation } }
}
$s = Get-CimInstance Win32_Service -Filter "Name LIKE 'AnyDesk%'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($s) { $o.svc = [ordered]@{ name = $s.Name; state = $s.State; start = $s.StartMode } }
foreach ($f in 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe', 'C:\Program Files\AnyDesk\AnyDesk.exe') {
  if (Test-Path $f) { $o.file = [ordered]@{ path = $f; version = [string](Get-Item $f).VersionInfo.ProductVersion } }
}
$o.procs = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'AnyDesk%'" -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.ExecutablePath })
foreach ($d in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
  foreach ($sub in 'Downloads', 'Desktop') {
    $o.found += @(Get-ChildItem (Join-Path $d.FullName $sub) -Filter 'AnyDesk*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object { $_.FullName })
  }
}
$conf = 'C:\ProgramData\AnyDesk\system.conf'
if (Test-Path $conf) {
  $o.unattended = $false
  foreach ($l in (Get-Content $conf -TotalCount 2000 -ErrorAction SilentlyContinue)) {
    if ($l -match '^ad\.anynet\.id=(\d{6,12})\s*$') { $o.id = $matches[1] }
    elseif ($l -match '^ad\.(anynet\.pwd_hash|security\.permission_profiles\._unattended_access[^=]*|security\.unattended[^=]*)=(.+)$' -and $matches[2].Trim() -ne '' -and $matches[2].Trim() -ne 'false') { $o.unattended = $true }
  }
}
$tr = 'C:\ProgramData\AnyDesk\connection_trace.txt'
if (Test-Path $tr) { $o.trace = @(Get-Content $tr -Tail 20 -ErrorAction SilentlyContinue | Where-Object { $_ -match '^Incoming' }) }
ConvertTo-Json -InputObject ([pscustomobject]$o) -Depth 4 -Compress
"""

_TRACE = re.compile(r"^Incoming\s+(\d{4}-\d{2}-\d{2}),\s*(\d{2}:\d{2})\s+(\S+)\s+(\d+)\s+(\d+)\s*$")


def parse_windows(p: dict) -> dict:
    """The script's output -> one remote_access_tools row (no password, no hash: the script outputs only a yes / no for unattended)."""
    reg, svc, f = p.get("reg") or None, p.get("svc") or None, p.get("file") or None
    procs = [x for x in (p.get("procs") or []) if isinstance(x, str) and x]
    found = [x for x in (p.get("found") or []) if isinstance(x, str) and x]
    installed_dir = re.compile(r"^c:\\program files( \(x86\))?\\anydesk\\", re.I)
    portable = [x for x in procs if not installed_dir.match(x)]
    present = bool(reg or svc or f or procs)
    trace = []
    for line in p.get("trace") or []:
        m = _TRACE.match(str(line).strip())
        if m:
            try:
                at = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M")
            except ValueError:
                continue
            trace.append({"at": at, "remote_id": m.group(4)[:12], "result": "rejected" if m.group(3).upper() == "REJECTED" else "accepted"})
    row = {"tool": "anydesk", "present": "yes" if present else ("unknown" if found else "no"),
           "install_type": "portable" if portable and not (reg or svc) else ("service" if (reg or svc) else ("portable" if found else "unknown")),
           "version": (f or {}).get("version") or (reg or {}).get("version") or None,
           "running": bool(procs) or ((svc or {}).get("state") or "").lower() == "running",
           "service_start": {"auto": "auto", "manual": "manual", "disabled": "disabled"}.get(((svc or {}).get("start") or "").lower()),
           "tool_id": p.get("id") if isinstance(p.get("id"), str) and p.get("id").isdigit() else None,
           "unattended": "yes" if p.get("unattended") is True else ("no" if p.get("unattended") is False else "unknown"),
           "portable_paths": (portable + found)[:5], "trace": trace[-10:],
           "source": "registry" if reg else ("service" if svc else ("file" if f else ("process" if procs else ("file" if found else "registry"))))}
    return row


# ── Linux ─────────────────────────────────────────────────────────────────────

LINUX_COMMAND = ("sh -c \"echo @@PKG@@; (dpkg-query -W -f='${Version}' anydesk 2>/dev/null || rpm -q --qf '%{VERSION}' anydesk 2>/dev/null); "
                 "echo; echo @@SVC@@; systemctl is-active anydesk 2>/dev/null; systemctl is-enabled anydesk 2>/dev/null; "
                 "echo @@ID@@; grep -E '^ad\\.anynet\\.id=' /etc/anydesk/system.conf 2>/dev/null | head -n 1\"")


def parse_linux(out: str) -> dict:
    def part(name):
        m = re.search(rf"@@{name}@@\s*(.*?)(?=@@\w+@@|$)", out or "", re.S)
        return (m.group(1) if m else "").strip().splitlines()
    pkg = next((l.strip() for l in part("PKG") if re.match(r"^\d", l.strip())), None)
    svc = [l.strip() for l in part("SVC") if l.strip()]
    mid = next((re.match(r"^ad\.anynet\.id=(\d{6,12})$", l.strip()).group(1) for l in part("ID") if re.match(r"^ad\.anynet\.id=\d{6,12}$", l.strip())), None)
    present = bool(pkg) or "active" in svc
    return {"tool": "anydesk", "present": "yes" if present else "no", "install_type": "service" if present else "unknown",
            "version": pkg, "running": "active" in svc,
            "service_start": "auto" if "enabled" in svc else ("disabled" if "disabled" in svc else None),
            "tool_id": mid, "unattended": "unknown", "portable_paths": [], "trace": [], "source": "package" if pkg else "service"}


# ── store, rules ──────────────────────────────────────────────────────────────

def record(host_ip: str, host_name: Optional[str], row: dict, now: Optional[datetime] = None) -> List[str]:
    """Stores what was read on a host and runs the rules. Returns the rules raised."""
    from services import soc, logons
    now = now or datetime.utcnow()
    s = settings()
    raised = []
    with SessionLocal() as db:
        a = db.execute(select(Asset).where(Asset.ip == host_ip).limit(1)).scalars().first()
        prev = db.execute(select(RemoteAccessTool).where(RemoteAccessTool.host_ip == host_ip, RemoteAccessTool.tool == row["tool"])).scalars().first()
        was_present = prev is not None and prev.present == "yes"
        had_record = prev is not None
        if prev is None:
            prev = RemoteAccessTool(host_ip=host_ip, tool=row["tool"], first_seen_at=now)
            db.add(prev)
        prev.asset_id = a.id if a else None
        for k in ("present", "install_type", "version", "running", "service_start", "tool_id", "unattended", "source"):
            setattr(prev, k, row.get(k))
        prev.portable_paths = json.dumps(row.get("portable_paths") or [])[:2000]
        prev.outdated = outdated(row.get("version")) if row.get("present") == "yes" else None
        last = (row.get("trace") or [None])[-1]
        prev.last_incoming = json.dumps({"at": last["at"].isoformat() + "Z", "remote_id": last["remote_id"], "result": last["result"]}) if last else prev.last_incoming
        prev.seen_at = now
        server = bool(a and (a.role == "server" or a.asset_type in ("server", "virtual") or "server" in (a.os_name or "").lower()))
        from services import asset_type as at, assets as assets_svc
        lv = at.normalize_level(a.criticality) if a else None
        if a and not lv:
            sug = assets_svc.suggested_level(a.id)
            lv = sug[0] if sug else None
        important = lv in ("important", "critical")
        db.commit()
    name = host_name or host_ip
    rules = s["rules"]

    def alert(rule, title, sev, msg, key=""):
        soc.raise_alert(rule=f"remote.{rule}", device=name, ip=host_ip, title=title, severity=sev, category="system", fp_detail=f"{row['tool']}|{key}",
                        count=0, detail={"message": msg, "description": title}, source="rules", mitre="T1219")
        raised.append(rule)

    if row.get("present") == "yes":
        if rules["new_install"] and had_record and not was_present:
            alert("new_install", "AnyDesk installed", "high" if important else "medium",
                  f"AnyDesk {row.get('version') or ''} appeared on {name} ({row.get('install_type')}) - it was not there at the last read")
        if rules["portable_on_server"] and server and row.get("install_type") == "portable" and row.get("running"):
            alert("portable_on_server", "Portable AnyDesk running on a server", "high",
                  f"AnyDesk running from {', '.join(row.get('portable_paths') or []) or 'outside its install folder'} on {name}", "portable")
        if rules["unattended"] and row.get("unattended") == "yes" and (server or lv == "critical"):
            alert("unattended", "AnyDesk unattended access enabled", "medium",
                  f"{name}: AnyDesk accepts connections without anyone confirming them - restrict it (an access list, two factors) or remove it", "unattended")
        if rules["outdated"] and outdated(row.get("version")):
            alert("outdated", "AnyDesk out of date", "medium",
                  f"{name}: AnyDesk {row.get('version')} - signed with the certificate revoked after AnyDesk's 2024 incident; update it", "outdated")
    # incoming AnyDesk connections are logons too (services/logons.py, source anydesk_trace)
    if row.get("trace"):
        logons.record([{"host_ip": host_ip, "host_name": host_name, "user": f"AnyDesk {t['remote_id']}", "logon_type": "anydesk",
                        "at": t["at"], "result": "success" if t["result"] == "accepted" else "failure", "source": "anydesk_trace"} for t in row["trace"]], now)
    return raised


def note_network(src: str, now: float) -> None:
    """A local host talking to AnyDesk's relays (TCP 6568) - from NetFlow."""
    _net_seen[src] = now


def network_likely() -> Dict[str, float]:
    return dict(_net_seen)


def for_asset(asset_id: Optional[int], ip: Optional[str], asset_type: Optional[str], refs: dict) -> List[dict]:
    """The remote_access_tools of an asset: what was read, or present "unknown" with the reason (no_agent / no_credential / not_supported),
    and a network hint as "likely (network)" - never "yes"."""
    out = []
    with SessionLocal() as db:
        rows = db.execute(select(RemoteAccessTool).where((RemoteAccessTool.asset_id == asset_id) | (RemoteAccessTool.host_ip == ip))).scalars().all() if (asset_id or ip) else []
    for r in rows:
        out.append(_brief(r))
    if not any(x["tool"] == "anydesk" for x in out):
        host = asset_type in ("windows", "linux", "server", "virtual")
        managed = any(refs.get(k) for k in ("windows_host_id", "linux_host_id"))
        if host or (ip and ip in _net_seen):
            e = {"tool": "anydesk", "present": "unknown", "reason": ("no_credential" if managed else "no_agent") if host else "not_supported"}
            if ip and ip in _net_seen:
                e["likely"] = "network"
                e["network_seen_at"] = datetime.utcfromtimestamp(_net_seen[ip]).isoformat() + "Z"
            out.append(e)
    return out


def _brief(r: RemoteAccessTool) -> dict:
    return {"tool": r.tool, "present": r.present, "install_type": r.install_type, "version": r.version, "running": r.running,
            "service_start": r.service_start, "anydesk_id": r.tool_id, "unattended_access": r.unattended, "outdated": r.outdated,
            "last_incoming": json.loads(r.last_incoming) if r.last_incoming else None, "source": r.source,
            "seen_at": r.seen_at.isoformat() + "Z" if r.seen_at else None}


def public_rows() -> Dict[str, dict]:
    """ip -> compact AnyDesk facts for Central's inventory rows."""
    with SessionLocal() as db:
        rows = db.execute(select(RemoteAccessTool).where(RemoteAccessTool.tool == "anydesk")).scalars().all()
    return {r.host_ip: {"p": r.present, "it": r.install_type, "v": r.version, "r": 1 if r.running else 0, "u": r.unattended, "id": r.tool_id,
                        "o": 1 if r.outdated else 0, "li": json.loads(r.last_incoming) if r.last_incoming else None,
                        "at": r.seen_at.isoformat() + "Z" if r.seen_at else None} for r in rows}


def report(rows: List[dict]) -> dict:
    """The client's AnyDesk report: hosts with it, servers and workstations apart, portable and unattended counted."""
    ra = public_rows()
    servers, stations = [], []
    for x in rows:
        e = ra.get(x.get("ip") or "")
        if not e or e["p"] != "yes":
            continue
        item = {"n": x["name"], "ip": x["ip"], "v": e["v"], "it": e["it"], "u": e["u"], "li": (e["li"] or {}).get("at") if e["li"] else None}
        (servers if (x.get("role") == "server" or x.get("type") in ("server", "virtual")) else stations).append(item)
    allp = [e for e in ra.values() if e["p"] == "yes"]
    return {"hosts": len(allp), "portable": sum(1 for e in allp if e["it"] == "portable"), "unattended": sum(1 for e in allp if e["u"] == "yes"),
            "outdated": sum(1 for e in allp if e["o"]), "likely_network": len([ip for ip in _net_seen if ip not in ra]),
            "servers": servers[:50], "workstations": stations[:100]}
