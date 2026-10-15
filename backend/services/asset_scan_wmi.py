"""The same read-only hardware scan of a Windows computer as services/asset_scan.py, but over WMI / DCOM (TCP 135 + the RPC ports) instead of WinRM.

An ordinary workstation has WinRM switched off and often nothing but the default firewall; with an administrator credential the
WMI service is still reachable (the "Windows Management Instrumentation" firewall group is on in a domain by default). It uses impacket's
DCOM client, runs the same queries as the PowerShell script - computer, OS, BIOS, board, CPU, RAM modules, disks, adapters, graphics,
monitors (EDID), printers, USB - and returns the very same dictionary, so `asset_scan.parse()` turns it into the asset's data.
Nothing is changed on the computer."""
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

CONNECT_TIMEOUT = 4.0

_CIM = "//./root/cimv2"
_WMI = "//./root/wmi"

_QUERIES = {
    "cs": (_CIM, "SELECT Manufacturer, Model, Name, Domain, PartOfDomain, UserName, TotalPhysicalMemory FROM Win32_ComputerSystem"),
    "os": (_CIM, "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime FROM Win32_OperatingSystem"),
    "bios": (_CIM, "SELECT SMBIOSBIOSVersion, Manufacturer, SerialNumber, ReleaseDate FROM Win32_BIOS"),
    "bb": (_CIM, "SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard"),
    "en": (_CIM, "SELECT ChassisTypes, SMBIOSAssetTag, SerialNumber FROM Win32_SystemEnclosure"),
    "cpu": (_CIM, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor"),
    "mem": (_CIM, "SELECT DeviceLocator, Capacity, Speed, Manufacturer, PartNumber FROM Win32_PhysicalMemory"),
    "slots": (_CIM, "SELECT MemoryDevices FROM Win32_PhysicalMemoryArray"),
    "pd": (_CIM, "SELECT Model, Size, InterfaceType, SerialNumber, MediaType FROM Win32_DiskDrive"),
    "ld": (_CIM, "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3"),
    "nic": (_CIM, "SELECT Description, MACAddress, IPAddress, DHCPEnabled, DefaultIPGateway, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"),
    "gpu": (_CIM, "SELECT Name, DriverVersion, AdapterRAM, CurrentHorizontalResolution, CurrentVerticalResolution FROM Win32_VideoController"),
    "prn": (_CIM, "SELECT Name, DriverName, PortName, Network, Default, ShareName, Location FROM Win32_Printer"),
    "ports": (_CIM, "SELECT Name, HostAddress FROM Win32_TCPIPPrinterPort"),
    "usb": (_CIM, "SELECT Name, Manufacturer, PNPClass, PNPDeviceID, Service FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB\\\\VID%'"),
    "monid": (_WMI, "SELECT InstanceName, Active, ManufacturerName, UserFriendlyName, SerialNumberID, ProductCodeID, YearOfManufacture FROM WmiMonitorID"),
    "monbp": (_WMI, "SELECT InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize FROM WmiMonitorBasicDisplayParams"),
}


# ── Pure conversions ─────────────────────────────────────────────────────────

def _val(v: Any) -> Any:
    return v.get("value") if isinstance(v, dict) else v


def _date(v: Any) -> Optional[str]:
    """CIM datetime "20220301000000.000000+000" -> 2022-03-01."""
    s = str(v or "")
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}" if len(s) >= 8 and s[:8].isdigit() else None


def _stamp(v: Any) -> Optional[str]:
    s = str(v or "")
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}" if len(s) >= 14 and s[:14].isdigit() else None


def _text(v: Any) -> Optional[str]:
    """EDID strings arrive as a list of character codes (0 = padding)."""
    if isinstance(v, (list, tuple)):
        t = "".join(chr(int(c)) for c in v if isinstance(c, int) and c != 0)
        return t or None
    return str(v) if v not in (None, "") else None


def _list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def build(rows: Dict[str, List[dict]]) -> dict:
    """The rows of every query (a list of {property: value} per query key) -> the dictionary the PowerShell script returns."""
    one = lambda k: (rows.get(k) or [{}])[0]
    cs, os_, bios, bb, en = one("cs"), one("os"), one("bios"), one("bb"), one("en")
    ports = {str(r.get("Name")): r.get("HostAddress") for r in rows.get("ports") or []}
    bp = {str(r.get("InstanceName")): r for r in rows.get("monbp") or []}
    mons = []
    for m in rows.get("monid") or []:
        if m.get("Active") is False:
            continue
        p = bp.get(str(m.get("InstanceName")), {})
        mons.append({"m": _text(m.get("ManufacturerName")), "n": _text(m.get("UserFriendlyName")), "s": _text(m.get("SerialNumberID")),
                     "p": _text(m.get("ProductCodeID")), "y": _int(m.get("YearOfManufacture")),
                     "w": _int(p.get("MaxHorizontalImageSize")), "h": _int(p.get("MaxVerticalImageSize"))})
    return {
        "cs": {"man": cs.get("Manufacturer"), "model": cs.get("Model"), "name": cs.get("Name"), "domain": cs.get("Domain"),
               "pod": bool(cs.get("PartOfDomain")), "user": cs.get("UserName"), "ram": _int(cs.get("TotalPhysicalMemory"))},
        "os": {"cap": os_.get("Caption"), "ver": os_.get("Version"), "build": os_.get("BuildNumber"), "arch": os_.get("OSArchitecture"),
               "inst": _date(os_.get("InstallDate")), "boot": _stamp(os_.get("LastBootUpTime"))},
        "bios": {"v": bios.get("SMBIOSBIOSVersion"), "man": bios.get("Manufacturer"), "s": bios.get("SerialNumber"), "rd": _date(bios.get("ReleaseDate"))},
        "bb": {"man": bb.get("Manufacturer"), "pr": bb.get("Product"), "s": bb.get("SerialNumber")},
        "en": {"types": _list(en.get("ChassisTypes")), "tag": en.get("SMBIOSAssetTag"), "s": en.get("SerialNumber")},
        "cpu": [{"n": c.get("Name"), "c": _int(c.get("NumberOfCores")), "l": _int(c.get("NumberOfLogicalProcessors")), "mhz": _int(c.get("MaxClockSpeed"))} for c in rows.get("cpu") or []],
        "mem": [{"slot": m.get("DeviceLocator"), "cap": _int(m.get("Capacity")), "spd": _int(m.get("Speed")), "m": m.get("Manufacturer"), "pn": m.get("PartNumber")} for m in rows.get("mem") or []],
        "slots": _int(one("slots").get("MemoryDevices")),
        "pd": [{"n": d.get("Model"), "sz": _int(d.get("Size")), "i": d.get("InterfaceType"), "s": d.get("SerialNumber"), "mt": d.get("MediaType")} for d in rows.get("pd") or []],
        "ld": [{"n": d.get("DeviceID"), "t": _int(d.get("Size")), "f": _int(d.get("FreeSpace"))} for d in rows.get("ld") or []],
        "nic": [{"n": n.get("Description"), "mac": n.get("MACAddress"), "ip": _list(n.get("IPAddress")), "dhcp": bool(n.get("DHCPEnabled")),
                 "gw": _list(n.get("DefaultIPGateway")), "dns": _list(n.get("DNSServerSearchOrder"))} for n in rows.get("nic") or []],
        "gpu": [{"n": g.get("Name"), "dv": g.get("DriverVersion"), "ram": _int(g.get("AdapterRAM")), "rx": _int(g.get("CurrentHorizontalResolution")),
                 "ry": _int(g.get("CurrentVerticalResolution"))} for g in rows.get("gpu") or []],
        "mon": mons,
        "prn": [{"n": p.get("Name"), "d": p.get("DriverName"), "p": p.get("PortName"), "a": ports.get(str(p.get("PortName"))), "net": bool(p.get("Network")),
                 "def": bool(p.get("Default")), "sh": p.get("ShareName"), "loc": p.get("Location")} for p in rows.get("prn") or []],
        "usb": [{"n": u.get("Name"), "m": u.get("Manufacturer"), "c": u.get("PNPClass"), "id": u.get("PNPDeviceID"), "sv": u.get("Service")} for u in rows.get("usb") or []],
    }


def collect(session) -> dict:
    """Runs every query through `session.query(namespace, wql) -> [ {property: value} ]` (a query that fails is just empty)."""
    rows: Dict[str, List[dict]] = {}
    for key, (ns, wql) in _QUERIES.items():
        try:
            rows[key] = session.query(ns, wql)
        except Exception as e:
            if key in ("cs", "os") and any(m in str(e).lower() for m in ("access_denied", "logon_failure", "access denied")):
                raise                                   # a rejected credential is not an empty answer
            rows[key] = []
    return build(rows)


# ── impacket ─────────────────────────────────────────────────────────────────

class _Session:
    """One DCOM connection, WMI login per namespace. Blocking."""

    def __init__(self, ip: str, username: str, password: str, domain: str):
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi
        self._wmi = wmi
        self._dcom = DCOMConnection(ip, username, password, domain or "", "", "", "", oxidResolver=True)
        iface = self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        self._login = wmi.IWbemLevel1Login(iface)
        self._services: Dict[str, Any] = {}

    def _svc(self, ns: str):
        from impacket.dcerpc.v5.dtypes import NULL
        if ns not in self._services:
            self._services[ns] = self._login.NTLMLogin(ns, NULL, NULL)
        return self._services[ns]

    def query(self, ns: str, wql: str) -> List[dict]:
        out: List[dict] = []
        enum = self._svc(ns).ExecQuery(wql)
        while True:
            try:
                obj = enum.Next(0xffffffff, 1)[0]
                out.append({k: _val(v) for k, v in obj.getProperties().items()})
            except Exception as e:
                if "S_FALSE" in str(e):
                    break
                raise
        try:
            enum.RemRelease()
        except Exception:
            pass
        return out

    def close(self) -> None:
        for svc in self._services.values():
            try:
                svc.RemRelease()
            except Exception:
                pass
        try:
            self._login.RemRelease()
        except Exception:
            pass
        try:
            self._dcom.disconnect()
        except Exception:
            pass


def port_open(ip: str, port: int = 135, timeout: float = CONNECT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_sync(ip: str, username: str, password: str, domain: Optional[str]) -> dict:
    """Blocking. {"ok": True, "parsed": {...}} or {"ok": False, "error": text}."""
    if not port_open(ip):
        return {"ok": False, "error": "DCOM/WMI: TCP 135 is not reachable (firewall, or not a Windows computer)"}
    user = username.split("\\", 1)[1] if "\\" in username else username
    domain = domain or (username.split("\\", 1)[0] if "\\" in username else "")
    sess = None
    try:
        sess = _Session(ip, user, password, domain)
        return {"ok": True, "parsed": collect(sess)}
    except ImportError:
        return {"ok": False, "error": "DCOM/WMI scan needs the 'impacket' package (pip install impacket)"}
    except Exception as e:
        return {"ok": False, "error": f"DCOM/WMI: {type(e).__name__}: {e}"[:600]}
    finally:
        if sess is not None:
            sess.close()
