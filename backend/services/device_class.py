"""What kind of device an asset is, beyond its type: gateway / router / switch / access point, Apple, Raspberry Pi, virtual machine.

The asset type (windows, linux, network, printer ...) says what it is for the inventory; the class says what it does on the network - what the
map draws and what the operator filters by. Evidence, strongest first: what manages it (a "WAN" interface list = gateway router), the model and
name (CRS / CSS = switch, cAP / wAP / UniFi AP = access point, RB / CCR = router), the maker from the network card's prefix (Apple, Raspberry Pi
Trading, VMware ...), the host name (iPhone, MacBook, raspberrypi) and, for an unknown computer, nothing - a wrong guess is worse than none."""
import re
from typing import Optional, Set

CLASSES = ("gateway", "router", "switch", "ap", "apple", "raspberry", "vm")

_VM_VENDOR = re.compile(r"vmware|hyper-v|microsoft corp.*virtual|qemu|virtualbox|xen|parallels|red hat.*virtio|proxmox", re.I)
_SWITCH = re.compile(r"\b(crs|css)\d|\bswitch\b|\bsg\d{3}\b|\bsf\d{3}\b|\bsx\d{3}\b|catalyst|\bgs\d{3,4}\b|\bdgs-|\bjg\d{3}|\btl-sg|\bus-\d|usw\b|procurve|\b2530\b|\b1920\b", re.I)
_AP = re.compile(r"\b(cap|wap|nap|map|audience)\b|\bcap ac\b|\bcap ax\b|\bwap ac\b|unifi (ap|u6|uap)|\buap\b|\bu6\b|access ?point|\beap\d{3}\b|\bwax\d{3}\b|\bwac\d{3}\b|aruba ap|\bap-\d", re.I)
_ROUTER = re.compile(r"\brb\d|\bccr\d|\bhex\b|\bhap\b|\brouteros\b|\brouter\b|\bedgerouter\b|\bmikrotik\b|\bisr\d|\bsrx\b|\bfortigate\b|\bpfsense\b|\bopnsense\b|\bvyos\b|\bdd-wrt\b|\bopenwrt\b|\bcisco ios\b", re.I)
_APPLE_NAME = re.compile(r"iphone|ipad|ipod|macbook|\bimac\b|mac-?mini|mac-?pro|mac-?studio|apple-?tv|homepod|airpods?|\bmbp\b|\bmba\b|airport", re.I)
_RPI_NAME = re.compile(r"raspberry|\brpi\b|raspi", re.I)


def classify(*, type: Optional[str], name: Optional[str] = None, manufacturer: Optional[str] = None, model: Optional[str] = None,
             os_name: Optional[str] = None, oui_vendor: Optional[str] = None, wan_router: bool = False, apple_hint: bool = False) -> Optional[str]:
    """One of CLASSES, or None when nothing says."""
    maker = f"{manufacturer or ''} {oui_vendor or ''}"
    text = f"{name or ''} {model or ''} {os_name or ''} {manufacturer or ''}"
    if type == "virtual" or _VM_VENDOR.search(maker):
        return "vm"
    if type == "network":
        if wan_router:
            return "gateway"
        if _AP.search(text):
            return "ap"
        if _SWITCH.search(text):
            return "switch"
        if _ROUTER.search(text):
            return "router"
        return None
    if apple_hint or re.search(r"\bapple\b", maker, re.I) or _APPLE_NAME.search(name or ""):
        return "apple"
    if re.search(r"raspberry", maker, re.I) or _RPI_NAME.search(name or ""):
        return "raspberry"
    return None


def ttl_os_hint(ttl: Optional[int]) -> Optional[str]:
    """The operating-system family a reply's TTL points to (a reply started at 64 / 128 / 255 and lost one per hop)."""
    if not ttl:
        return None
    if ttl <= 64:
        return "unix"          # Linux, macOS, iOS, Android, most embedded
    if ttl <= 128:
        return "windows"
    return "network"           # routers and switches typically start at 255
