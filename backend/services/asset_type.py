"""
The type of an asset nothing manages, decided from every signal together - and which signals decided it.

Before 3.59 the first rule that matched won: an open 445 made "windows" (Samba answers it too), a MikroTik network-card prefix made
"network". Seen in production: MEDIABOXPI (psb, a Raspberry Pi serving lighttpd) as "windows"; MCPROJEKTPC007 (a PC) as "network" because
the MAC glued to it was a router's (that part is fixed in services/directory_merge.py). Here each signal adds weight to a type and the
heaviest type wins; `sources` says which signals made it, so the inventory can show why. Managed hosts (WinRM / SSH, the RouterOS API,
Hyper-V, a BMC) keep the type their source knows - this is only for the rest.

Pure: backend/tests/test_inventory_identity.py.
"""
import re
from typing import Dict, Iterable, List, Optional, Tuple

_PRINTER_PORTS = {9100, 631, 515}
_COMPUTER_PORTS = {22, 135, 445, 3389, 5985, 5986}
_WIN_BANNER = re.compile(r"microsoft-iis|microsoft-httpapi|\bwindows\b|microsoft ftp", re.I)
_LINUX_BANNER = re.compile(r"lighttpd|nginx|openssh[_ -][\w.]+ (debian|ubuntu|raspbian)|apache[^ ]* \((debian|ubuntu|raspbian|centos|red hat|fedora)\)|"
                           r"\blinux\b|dropbear|openwrt|busybox|samba|cups", re.I)
_PRINTER_NAME = re.compile(r"printer|drukark|\bhp[0-9a-f]{6}\b|^brn[0-9a-f]{12}$|^brw[0-9a-f]{12}$|brother|epson|canon|xerox|lexmark|kyocera|ricoh|"
                           r"konica|^km[0-9a-f]{6}|\bmfp\b|sharp-bp|^npi[0-9a-f]{6}", re.I)
_WIN_NAME = re.compile(r"^(desktop|laptop|win)-[a-z0-9]{4,}$|pc\d{2,}$|^nb\d{2,}|^ws\d{2,}", re.I)
_PI_NAME = re.compile(r"raspberry|\brpi\b|raspi|\bpi\d?$|pi$", re.I)


def decide(*, ports: Iterable[int] = (), banners: str = "", name: Optional[str] = None, oui_type: Optional[str] = None,
           oui_vendor: Optional[str] = None, ttl_hint: Optional[str] = None, sweep_hint: Optional[str] = None,
           mobile_name: bool = False) -> Tuple[str, List[str]]:
    """(type, sources). type is one of windows / linux / printer / mobile / network / camera / virtual / other."""
    ports = set(ports or ())
    score: Dict[str, float] = {}
    why: Dict[str, List[str]] = {}

    def add(t: str, w: float, src: str):
        score[t] = score.get(t, 0.0) + w
        why.setdefault(t, []).append(src)

    if 3389 in ports:
        add("windows", 40, "port 3389")
    if ports & {5985, 5986}:
        add("windows", 40, "WinRM port")
    if 135 in ports:
        add("windows", 25, "port 135")
    if 445 in ports:
        add("windows", 12, "port 445")
    if 22 in ports:
        add("linux", 15, "port 22")
    if ports & _PRINTER_PORTS and not ports & _COMPUTER_PORTS:
        add("printer", 40, "printer port")
    if banners and _WIN_BANNER.search(banners):
        add("windows", 40, "Windows service banner")
    if banners and _LINUX_BANNER.search(banners):
        m = _LINUX_BANNER.search(banners)
        add("linux", 35, f"banner {m.group(0)}")
    if ttl_hint == "windows":
        add("windows", 15, "TTL 128")
    elif ttl_hint == "unix":
        add("linux", 10, "TTL 64")
        if "windows" in score:
            score["windows"] -= 15
            why["windows"].append("but TTL 64 (not Windows)")
    n = (name or "").strip()
    if n and _PRINTER_NAME.search(n):
        add("printer", 50, "printer name")
    if n and _WIN_NAME.search(n):
        add("windows", 30, "PC name")
    if n and _PI_NAME.search(n):
        add("linux", 25, "Raspberry Pi name")
    if mobile_name:
        add("mobile", 35, "phone name")
    if oui_type in ("printer", "camera", "mobile", "virtual"):
        add(oui_type, 30, f"maker {oui_vendor or oui_type}")
    elif oui_type == "network":
        add("network", 20, f"maker {oui_vendor or 'network'}")
    if oui_vendor and re.search(r"raspberry", oui_vendor, re.I):
        add("linux", 30, "maker Raspberry Pi")
    if sweep_hint == "windows":
        add("windows", 20, "LAN sweep: Windows")
    elif sweep_hint == "printer":
        add("printer", 30, "LAN sweep: printer")
    if not score:
        return "other", []
    best = max(score, key=lambda t: (score[t], t))
    if score[best] < 15:
        return "other", why.get(best, [])
    return best, why[best]


# ── criticality ──────────────────────────────────────────────────────────────

LEVELS = ("critical", "important", "normal", "ignore")
_LEGACY = {"critical": "critical", "high": "important", "medium": "normal", "low": "normal",
           "important": "important", "normal": "normal", "ignore": "ignore"}
_DC_NAME = re.compile(r"(^|[-_])(dc|ad|pdc|bdc)\d*([-_]|$)|domain.?controller", re.I)
_FS_NAME = re.compile(r"(^|[-_])(fs|nas|files?|filesrv|fileserver|storage)\d*([-_]|$)", re.I)
_SQL_NAME = re.compile(r"sql|oracle|postgres|mariadb|mysql|\bdb\d*\b", re.I)
_HV_NAME = re.compile(r"hyper-?v|esxi|proxmox|\bpve\d*\b|vmhost|xen", re.I)
_DB_PORTS = {1433, 1521, 3306, 5432}


def normalize_level(v: Optional[str]) -> Optional[str]:
    """critical / important / normal / ignore; the old low / medium / high are read as normal / normal / important."""
    return _LEGACY.get((v or "").strip().lower()) if v else None


def suggest(*, asset_type: Optional[str], dclass: Optional[str], name: Optional[str], role: Optional[str], ports: Iterable[int] = (),
            hyperv_host: bool = False, os_name: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """(level, reason) - the default the operator sees until they set one: edge routers, domain controllers, hypervisors, file and
    SQL servers are "important"; everything else "normal"."""
    n = name or ""
    ports = set(ports or ())
    if dclass == "gateway":
        return "important", "edge router"
    if hyperv_host or _HV_NAME.search(n):
        return "important", "hypervisor"
    server = role == "server" or asset_type in ("server", "virtual") or "server" in (os_name or "").lower()
    if server and _DC_NAME.search(n):
        return "important", "domain controller"
    if server and _FS_NAME.search(n):
        return "important", "file server"
    if server and (ports & _DB_PORTS or _SQL_NAME.search(n)):
        return "important", "database server"
    return "normal", None
