"""Credentialed hardware scan of Windows computers for the asset inventory (services/assets.py).

One read-only WMI/CIM query set per computer, over the WinRM connection and credentials the agent already uses for
patch management (the host's own credential, else the credential attached to its vulnerability-scan entry, else the shared
Windows credential): BIOS / serial, board, CPU, RAM modules, physical disks, network adapters (MAC), video, logged-on
user, attached monitors (EDID: maker, model, serial, size, year), installed printers and USB devices. Nothing is changed
on the computer. The result lands in Asset.details / AssetPeripheral and lifts the asset to scan level "credentialed".

Linux (SSH) and SNMP are added to this module in the next stages."""
import asyncio
import json
import math
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, AssetPeripheral, Credential, VulnHost, WindowsHost
from services import vuln_scan as vs
from services.crypto import decrypt

SCAN_TIMEOUT_SEC = int(os.environ.get("MIKROTIK_ASSET_SCAN_TIMEOUT_SEC", "120"))
SCAN_INTERVAL_HOURS = float(os.environ.get("MIKROTIK_ASSET_SCAN_HOURS", "12"))     # how stale a scan may get before the scheduler repeats it
SCAN_CONCURRENCY = 3
LOOP_SEC = 600
MAX_USB = 40

# One query per piece of hardware; the whole thing is sent gzip-compressed (hyperv_manage.pack_script) because the plain text
# is longer than a Windows command line allows.
_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
function D($v){if($v){-join($v|?{$_ -ne 0}|%{[char]$_})}}
function T($x){if($x){([datetime]$x).ToString('yyyy-MM-dd')}}
$cs=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem;$b=Get-CimInstance Win32_BIOS
$bb=Get-CimInstance Win32_BaseBoard;$en=Get-CimInstance Win32_SystemEnclosure
$bp=@(Get-CimInstance -Namespace root\wmi WmiMonitorBasicDisplayParams)
$ports=@(Get-CimInstance Win32_TCPIPPrinterPort)
[pscustomobject]@{
cs=[pscustomobject]@{man=$cs.Manufacturer;model=$cs.Model;name=$cs.Name;domain=$cs.Domain;pod=[bool]$cs.PartOfDomain;user=$cs.UserName;ram=[int64]$cs.TotalPhysicalMemory}
os=[pscustomobject]@{cap=$os.Caption;ver=$os.Version;build=$os.BuildNumber;arch=$os.OSArchitecture;inst=T $os.InstallDate;boot=$(if($os.LastBootUpTime){$os.LastBootUpTime.ToString('s')})}
bios=[pscustomobject]@{v=$b.SMBIOSBIOSVersion;man=$b.Manufacturer;s=$b.SerialNumber;rd=T $b.ReleaseDate}
bb=[pscustomobject]@{man=$bb.Manufacturer;pr=$bb.Product;s=$bb.SerialNumber}
en=[pscustomobject]@{types=@($en.ChassisTypes);tag=$en.SMBIOSAssetTag;s=$en.SerialNumber}
cpu=@(Get-CimInstance Win32_Processor|%{[pscustomobject]@{n=$_.Name;c=$_.NumberOfCores;l=$_.NumberOfLogicalProcessors;mhz=$_.MaxClockSpeed}})
mem=@(Get-CimInstance Win32_PhysicalMemory|%{[pscustomobject]@{slot=$_.DeviceLocator;cap=[int64]$_.Capacity;spd=$_.Speed;m=$_.Manufacturer;pn=$_.PartNumber}})
slots=(Get-CimInstance Win32_PhysicalMemoryArray|select -f 1).MemoryDevices
pd=@(Get-CimInstance Win32_DiskDrive|%{[pscustomobject]@{n=$_.Model;sz=[int64]$_.Size;i=$_.InterfaceType;s=$_.SerialNumber;mt=$_.MediaType}})
ld=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|%{[pscustomobject]@{n=$_.DeviceID;t=[int64]$_.Size;f=[int64]$_.FreeSpace}})
nic=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'|%{[pscustomobject]@{n=$_.Description;mac=$_.MACAddress;ip=@($_.IPAddress);dhcp=[bool]$_.DHCPEnabled;gw=@($_.DefaultIPGateway);dns=@($_.DNSServerSearchOrder)}})
gpu=@(Get-CimInstance Win32_VideoController|%{[pscustomobject]@{n=$_.Name;dv=$_.DriverVersion;ram=[int64]$_.AdapterRAM;rx=$_.CurrentHorizontalResolution;ry=$_.CurrentVerticalResolution}})
mon=@(Get-CimInstance -Namespace root\wmi WmiMonitorID|?{$_.Active}|%{$i=$_.InstanceName;$p=$bp|?{$_.InstanceName -eq $i}|select -f 1;[pscustomobject]@{m=D $_.ManufacturerName;n=D $_.UserFriendlyName;s=D $_.SerialNumberID;p=D $_.ProductCodeID;y=$_.YearOfManufacture;w=$p.MaxHorizontalImageSize;h=$p.MaxVerticalImageSize}})
prn=@(Get-CimInstance Win32_Printer|%{$pt=$_.PortName;$ip=$ports|?{$_.Name -eq $pt}|select -f 1;[pscustomobject]@{n=$_.Name;d=$_.DriverName;p=$pt;a=$ip.HostAddress;net=[bool]$_.Network;def=[bool]$_.Default;sh=$_.ShareName;loc=$_.Location}})
usb=@(Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID LIKE 'USB\\VID%'"|%{[pscustomobject]@{n=$_.Name;m=$_.Manufacturer;c=$_.PNPClass;id=$_.PNPDeviceID;sv=$_.Service}})
}|ConvertTo-Json -Compress -Depth 6|%{[regex]::Replace($_,'[^\x00-\x7F]',{param($m)'\u{0:x4}' -f [int][char]$m.Value})}
"""

# EDID three-letter maker codes of the common monitor brands
_MONITOR_MAKERS = {
    "DEL": "Dell", "SAM": "Samsung", "LEN": "Lenovo", "AOC": "AOC", "ACI": "ASUS", "AUS": "ASUS", "GSM": "LG", "LGD": "LG Display",
    "HWP": "HP", "HPN": "HP", "PHL": "Philips", "BNQ": "BenQ", "ACR": "Acer", "NEC": "NEC", "VSC": "ViewSonic", "MSI": "MSI",
    "IVM": "Iiyama", "EIZ": "Eizo", "SNY": "Sony", "HSD": "Hannspree", "SHP": "Sharp", "MEI": "Panasonic", "TOS": "Toshiba",
    "FUS": "Fujitsu", "BOE": "BOE (panel)", "AUO": "AU Optronics", "CMN": "Chimei (panel)", "IVO": "InfoVision (panel)",
    "LEN ": "Lenovo", "APP": "Apple", "MSF": "Microsoft", "GBT": "Gigabyte", "XMI": "Xiaomi", "KOS": "Kogan", "CMO": "Chimei (panel)",
}

_PLACEHOLDER_SERIALS = {"", "0", "none", "n/a", "na", "default string", "to be filled by o.e.m.", "system serial number",
                        "to be filled by o.e.m", "not specified", "not available", "123456789", "0123456789", "unknown", "serial number"}

# printers that are drivers, not devices
_VIRTUAL_PRINTER_PORTS = ("portprompt:", "nul:", "shrfax:", "xpsport:", "file:", "microsoft.", "webex")
_VIRTUAL_PRINTER_NAMES = ("microsoft print to pdf", "microsoft xps", "onenote", "fax", "send to", "adobe pdf", "pdfcreator", "cutepdf",
                          "bullzip", "foxit", "snagit", "webex", "teams", "dopdf", "primopdf")
_USB_SKIP_SERVICES = ("usbccgp", "usbhub", "usbhub3", "usbhub3_unified", "usbxhci", "usbehci", "hidusb")   # hubs, composite parents, HID interface parents
_USB_SKIP = ("root hub", "host controller")

_CHASSIS = {8: "laptop", 9: "laptop", 10: "laptop", 14: "laptop", 30: "laptop", 31: "laptop", 32: "laptop",
            3: "desktop", 4: "desktop", 6: "desktop", 7: "desktop", 13: "desktop", 15: "desktop", 16: "desktop", 24: "desktop", 35: "desktop", 36: "desktop",
            5: "server", 17: "server", 23: "server", 25: "server", 28: "server"}

_running: set = set()
_attempts: Dict[int, datetime] = {}     # last try per asset, so an unreachable laptop is retried hourly, not every cycle
RETRY_HOURS = 1.0
_task: Optional[asyncio.Task] = None


# ── Parsing (pure) ───────────────────────────────────────────────────────────

def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _s(x) -> Optional[str]:
    if x is None or isinstance(x, (dict, list)):          # an empty EDID field arrives as an empty object
        return None
    x = str(x).strip()
    return x or None


def _int(x) -> Optional[int]:
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _serial(x) -> Optional[str]:
    x = _s(x)
    return None if x is None or x.lower() in _PLACEHOLDER_SERIALS or set(x) <= {"0", "-", " "} else x


def _maker(code: Optional[str]) -> Optional[str]:
    c = (_s(code) or "").upper()
    return _MONITOR_MAKERS.get(c) or (c or None)


def parse(parsed: dict) -> dict:
    """The script's JSON -> {"asset": fields for the Asset row, "details": hardware sections, "peripherals": [...]}."""
    cs, os_, bios, bb, en = (parsed.get(k) or {} for k in ("cs", "os", "bios", "bb", "en"))
    out: Dict = {"asset": {}, "details": {}, "peripherals": []}

    chassis = None
    for t in _as_list(en.get("types")):
        if _int(t) in _CHASSIS:
            chassis = _CHASSIS[_int(t)]
            break
    cap = _s(os_.get("cap")) or ""
    out["asset"] = {
        "manufacturer": _s(cs.get("man")), "model": _s(cs.get("model")),
        "serial": _serial(bios.get("s")) or _serial(en.get("s")) or _serial(bb.get("s")),
        "os_name": cap.replace("Microsoft ", "").strip() or None, "os_version": _s(os_.get("ver")),
        "role": ("server" if "server" in cap.lower() else "workstation") if cap else None,
    }

    system = {"chassis": chassis, "manufacturer": _s(cs.get("man")), "model": _s(cs.get("model")), "domain": _s(cs.get("domain")),
              "logged_user": _s(cs.get("user")), "architecture": _s(os_.get("arch")), "build": _s(os_.get("build")),
              "install_date": _s(os_.get("inst")), "last_boot": _s(os_.get("boot")), "asset_tag": _serial(en.get("tag"))}
    out["details"]["system"] = {k: v for k, v in system.items() if v is not None}
    out["details"]["bios"] = {k: v for k, v in {
        "vendor": _s(bios.get("man")), "version": _s(bios.get("v")), "serial": _serial(bios.get("s")), "release_date": _s(bios.get("rd")),
        "board_manufacturer": _s(bb.get("man")), "board_product": _s(bb.get("pr")), "board_serial": _serial(bb.get("s")),
    }.items() if v is not None}

    cpus = [c for c in _as_list(parsed.get("cpu")) if isinstance(c, dict)]
    if cpus:
        out["details"]["cpu"] = {k: v for k, v in {
            "name": " ".join((_s(cpus[0].get("n")) or "").split()) or None, "sockets": len(cpus),
            "cores": sum(_int(c.get("c")) or 0 for c in cpus) or None, "logical": sum(_int(c.get("l")) or 0 for c in cpus) or None,
            "max_mhz": _int(cpus[0].get("mhz")),
        }.items() if v is not None}

    mods = [m for m in _as_list(parsed.get("mem")) if isinstance(m, dict)]
    out["details"]["memory"] = {k: v for k, v in {
        "total_bytes": _int(cs.get("ram")) or (sum(_int(m.get("cap")) or 0 for m in mods) or None),
        "slots_used": len(mods) or None, "slots_total": _int(parsed.get("slots")), "speed_mhz": _int(mods[0].get("spd")) if mods else None,
    }.items() if v is not None}
    out["details"]["memory_modules"] = [{k: v for k, v in {
        "slot": _s(m.get("slot")), "capacity_bytes": _int(m.get("cap")), "speed_mhz": _int(m.get("spd")),
        "manufacturer": _s(m.get("m")), "part_number": _s(m.get("pn")),
    }.items() if v is not None} for m in mods]

    out["details"]["physical_disks"] = [{k: v for k, v in {
        "name": _s(d.get("n")), "size_bytes": _int(d.get("sz")), "interface": _s(d.get("i")), "media": _s(d.get("mt")), "serial": _serial(d.get("s")),
    }.items() if v is not None} for d in _as_list(parsed.get("pd")) if isinstance(d, dict)]
    out["details"]["disks"] = [{"name": d["n"], "total_bytes": d["t"], "used_bytes": d["t"] - (d["f"] or 0),
                                "pct": round((d["t"] - (d["f"] or 0)) * 100.0 / d["t"], 1)}
                               for d in ({"n": _s(x.get("n")), "t": _int(x.get("t")) or 0, "f": _int(x.get("f"))} for x in _as_list(parsed.get("ld")) if isinstance(x, dict))
                               if d["n"] and d["t"] > 0]

    nics = []
    for n in _as_list(parsed.get("nic")):
        if not isinstance(n, dict):
            continue
        nics.append({k: v for k, v in {
            "name": _s(n.get("n")), "mac": (_s(n.get("mac")) or "").upper() or None,
            "ips": [i for i in _as_list(n.get("ip")) if i and ":" not in str(i)] or None,
            "dhcp": bool(n.get("dhcp")), "gateway": [g for g in _as_list(n.get("gw")) if g] or None, "dns": [d for d in _as_list(n.get("dns")) if d] or None,
        }.items() if v is not None})
    out["details"]["network_adapters"] = nics
    if nics:
        main = next((n for n in nics if n.get("gateway") and n.get("mac")), None) or next((n for n in nics if n.get("mac")), None)
        if main:
            out["asset"]["mac"] = main["mac"]

    out["details"]["gpu"] = [{k: v for k, v in {
        "name": _s(g.get("n")), "driver": _s(g.get("dv")), "vram_bytes": _int(g.get("ram")) if (_int(g.get("ram")) or 0) > 0 else None,
        "resolution": f'{_int(g.get("rx"))}×{_int(g.get("ry"))}' if _int(g.get("rx")) and _int(g.get("ry")) else None,
    }.items() if v is not None} for g in _as_list(parsed.get("gpu")) if isinstance(g, dict) and _s(g.get("n"))]

    # monitors (EDID)
    for m in _as_list(parsed.get("mon")):
        if not isinstance(m, dict):
            continue
        w, h = _int(m.get("w")), _int(m.get("h"))
        inches = round(math.hypot(w, h) / 2.54, 1) if w and h else None
        maker = _maker(m.get("m"))
        name = _s(m.get("n")) or (f"{maker} {_s(m.get('p')) or ''}".strip() if maker else "Monitor")
        out["peripherals"].append({"kind": "monitor", "name": name, "manufacturer": maker, "model": _s(m.get("p")) or _s(m.get("n")),
                                   "serial": _serial(m.get("s")),
                                   "details": {k: v for k, v in {"size_in": inches, "year": _int(m.get("y")) or None}.items() if v}})

    # printers: installed drivers that point at a real device
    for p in _as_list(parsed.get("prn")):
        if not isinstance(p, dict):
            continue
        name, port = _s(p.get("n")) or "", (_s(p.get("p")) or "")
        if any(name.lower().startswith(v) for v in _VIRTUAL_PRINTER_NAMES) or port.lower().startswith(_VIRTUAL_PRINTER_PORTS):
            continue
        out["peripherals"].append({"kind": "printer", "name": name, "manufacturer": None, "model": _s(p.get("d")), "serial": None,
                                   "details": {k: v for k, v in {"port": port or None, "address": _s(p.get("a")), "network": True if (p.get("net") or p.get("a")) else None,
                                                                 "default": True if p.get("def") else None, "share": _s(p.get("sh")), "location": _s(p.get("loc"))}.items() if v}})

    # USB devices (hubs, composite parents and per-interface entries are noise)
    usb = []
    for u in _as_list(parsed.get("usb")):
        if not isinstance(u, dict):
            continue
        name, dev = _s(u.get("n")) or "", (_s(u.get("id")) or "")
        if not name or "&MI_" in dev.upper() or (_s(u.get("sv")) or "").lower() in _USB_SKIP_SERVICES or any(x in name.lower() for x in _USB_SKIP):
            continue
        usb.append({"kind": "usb", "name": name, "manufacturer": None if (_s(u.get("m")) or "").startswith("(Standard") else _s(u.get("m")), "model": None, "serial": None,
                    "details": {k: v for k, v in {"class": _s(u.get("c")), "id": dev.split("\\")[1] if dev.count("\\") >= 1 else None}.items() if v}})
    out["peripherals"].extend(usb[:MAX_USB])
    return out


# ── Running a scan ───────────────────────────────────────────────────────────

def is_windows(a: Asset) -> bool:
    return bool(a.ip) and (a.asset_type == "windows" or (a.asset_type in ("virtual", "other", "server") and "windows" in (a.os_name or "").lower()))


def can_scan(asset_id: int) -> bool:
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        return bool(a) and is_windows(a)


def _credential(a: Asset) -> Optional[tuple]:
    """(username, password, domain, port) for this computer, or None."""
    from services import windows_manage as wm
    refs = json.loads(a.refs or "{}")
    port = 5985
    with SessionLocal() as db:
        host = db.get(WindowsHost, refs["windows_host_id"]) if refs.get("windows_host_id") else None
        if host:
            port = host.winrm_port or 5985
            cred = wm._credential_for_host(host)
            if cred:
                return (*cred, port)
        vh = db.get(VulnHost, refs["vuln_host_id"]) if refs.get("vuln_host_id") else None
        if vh and vh.credential_id:
            c = db.get(Credential, vh.credential_id)
            if c:
                try:
                    return c.username, decrypt(c.password_enc), c.domain, port
                except Exception:
                    pass
    shared = wm._shared_credential()
    return (*shared, port) if shared else None


def _scan_sync(ip: str, port: int, username: str, password: str, domain: Optional[str]) -> dict:
    from services import hyperv_manage as hm
    r = hm._run_ps_sync(ip, port, username, password, domain, _SCRIPT, SCAN_TIMEOUT_SEC)
    err = r.std_err.decode("utf-8", errors="ignore")
    raw = r.std_out.decode("utf-8", errors="ignore").strip()
    if r.status_code != 0 and not raw:
        return {"ok": False, "error": err[-600:] or f"exit code {r.status_code}"}
    try:
        return {"ok": True, "parsed": json.loads(raw)}
    except Exception as e:
        return {"ok": False, "error": f"unreadable answer ({e}): {(err or raw)[-300:]}"}


def _store(asset_id: int, parsed: dict) -> None:
    res = parse(parsed)
    now = datetime.utcnow()
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return
        for f, v in res["asset"].items():
            if v and (f != "role" or not a.role):
                setattr(a, f, v)
        d = json.loads(a.details or "{}")
        d.update(res["details"])
        a.details = json.dumps(d)
        a.scan_level, a.last_scan_at, a.last_scan_status, a.last_scan_error = "credentialed", now, "ok", None
        for p in db.execute(select(AssetPeripheral).where(AssetPeripheral.asset_id == a.id)).scalars().all():
            db.delete(p)
        for p in res["peripherals"]:
            db.add(AssetPeripheral(asset_id=a.id, kind=p["kind"], name=p["name"], manufacturer=p["manufacturer"], model=p["model"],
                                   serial=p["serial"], details=json.dumps(p["details"]), last_seen_at=now))
        db.commit()


def _fail(asset_id: int, error: str) -> None:
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if a:
            a.last_scan_status, a.last_scan_error = "error", error[:500]
            db.commit()


def running_ids() -> List[int]:
    return sorted(_running)


async def scan_asset(asset_id: int) -> dict:
    """Scan one computer now. Returns {"ok": True} or {"error": ...}."""
    if asset_id in _running:
        return {"error": "scan already running"}
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return {"error": "asset not found"}
        if not is_windows(a):
            return {"error": "no credentialed scan is available for this kind of device yet"}
        ip = a.ip
        cred = _credential(a)
    _attempts[asset_id] = datetime.utcnow()
    if not cred:
        _fail(asset_id, "no credential (assign one to this computer, or set the shared Windows credential)")
        return {"error": "no credential configured"}
    username, password, domain, port = cred
    _running.add(asset_id)
    try:
        loop = asyncio.get_event_loop()
        try:
            res = await asyncio.wait_for(loop.run_in_executor(vs._EXECUTOR, _scan_sync, ip, port, username, password, domain), timeout=SCAN_TIMEOUT_SEC + 20)
        except (asyncio.TimeoutError, TimeoutError):
            _fail(asset_id, "timeout")
            return {"error": "timeout"}
        except Exception as e:
            _fail(asset_id, str(e))
            return {"error": str(e)}
        if not res["ok"]:
            _fail(asset_id, res["error"])
            return {"error": res["error"]}
        _store(asset_id, res["parsed"])
        return {"ok": True}
    finally:
        _running.discard(asset_id)


def due_ids(hours: float = SCAN_INTERVAL_HOURS) -> List[int]:
    """Computers whose last successful scan is missing or older than `hours`; any one is tried at most hourly."""
    now = datetime.utcnow()
    out = []
    with SessionLocal() as db:
        for a in db.execute(select(Asset)).scalars().all():
            if not is_windows(a) or a.id in _running:
                continue
            if now - _attempts.get(a.id, datetime.min) < timedelta(hours=RETRY_HOURS):
                continue
            if a.last_scan_at is None or now - a.last_scan_at > timedelta(hours=hours):
                out.append(a.id)
    return out


async def scan_all(ids: Optional[List[int]] = None) -> dict:
    """Scans every due computer (or `ids`), a few at a time."""
    todo = ids if ids is not None else due_ids()
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    results = {"ok": 0, "failed": 0}

    async def one(i: int):
        async with sem:
            r = await scan_asset(i)
            results["ok" if r.get("ok") else "failed"] += 1

    await asyncio.gather(*(one(i) for i in todo), return_exceptions=True)
    return {**results, "total": len(todo)}


async def _loop():
    await asyncio.sleep(180)
    while True:
        try:
            await scan_all()
        except Exception as e:
            print(f"[asset_scan] loop error: {e}")
        await asyncio.sleep(LOOP_SEC)


def start():
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
    _task = None
