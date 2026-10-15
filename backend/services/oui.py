"""Who made a network card: the maker behind the first three bytes of a MAC address (IEEE OUI list, `oui.tsv.gz` next to this file,
about 40 000 assignments with the company names shortened), and from it a guess at what the device is.

Used by the asset inventory (services/assets.py) for the devices that no port scan and no login can say anything about - what a router's
DHCP / ARP table lists: a phone, a camera, a printer, a smart plug. The guess only fills the gap ("other"); it never overrides what a scan
or a credential found. A "private" (randomised) address, as phones use for Wi-Fi, has no maker."""
import gzip
import os
import re
from typing import Dict, Optional

_PATH = os.path.join(os.path.dirname(__file__), "oui.tsv.gz")
_table: Optional[Dict[str, str]] = None

# virtual NICs by prefix (some of them are not in the IEEE list at all - 52:54:00 is QEMU/KVM's own)
_VM_PREFIX = {
    "00155D": "Microsoft Hyper-V", "005056": "VMware", "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "080027": "VirtualBox",
    "525400": "QEMU / KVM", "00163E": "Xen", "001C42": "Parallels", "0003FF": "Microsoft Virtual PC", "BC2411": "Proxmox",
}

_KINDS = (
    ("printer", re.compile(r"\b(brother|seiko epson|epson|kyocera|ricoh|konica|lexmark|oki data|oki electric|xerox|zebra|toshiba tec|sharp document)\b", re.I)),
    ("camera", re.compile(r"(hikvision|dahua|axis communications|reolink|vivotek|amcrest|uniview|hanwha|mobotix|ezviz|foscam|avigilon|geovision|lilin|acti corp)", re.I)),
    ("mobile", re.compile(r"(xiaomi|oneplus|guangdong oppo|oppo mobile|vivo mobile|motorola mobility|realme|honor device|huawei device|nothing technology)", re.I)),
    ("network", re.compile(r"(routerboard|mikrotik|cisco|ubiquiti|tp-link|netgear|d-link|zyxel|aruba|ruckus|fortinet|juniper|tenda|cambium|edgecore|engenius|draytek|peplink|teltonika|extreme networks|brocade|alcatel-lucent ent)", re.I)),
)

# host names that give a device away when its MAC does not
_NAME_KINDS = (
    ("mobile", re.compile(r"iphone|ipad|android|galaxy|pixel|redmi|xiaomi|huawei|oppo|oneplus|\bsm-[a-z]\d{3}|\bhonor\b|\bpoco\b|realme", re.I)),
    ("camera", re.compile(r"ipcam|\bcam[-_ ]?\d|camera|kamera|hikvision|dahua|reolink|\bnvr\b|\bdvr\b|\bdome\b", re.I)),
)


def _load() -> Dict[str, str]:
    global _table
    if _table is None:
        t: Dict[str, str] = {}
        try:
            with gzip.open(_PATH, "rt", encoding="utf-8") as f:
                for line in f:
                    k, _, v = line.rstrip("\n").partition("\t")
                    if v:
                        t[k] = v
        except Exception as e:
            print(f"[oui] vendor table unavailable: {e}")
        _table = t
    return _table


def _prefix(mac: Optional[str]) -> Optional[str]:
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    return h[:6] if len(h) >= 6 else None


def is_private(mac: Optional[str]) -> bool:
    """A locally administered (randomised) address: the second-lowest bit of the first byte is set."""
    p = _prefix(mac)
    return bool(p and int(p[:2], 16) & 0x02)


def vendor(mac: Optional[str]) -> Optional[str]:
    p = _prefix(mac)
    if not p:
        return None
    return _VM_PREFIX.get(p) or _load().get(p)


def type_from_name(name: Optional[str]) -> Optional[str]:
    for kind, rx in _NAME_KINDS:
        if name and rx.search(name):
            return kind
    return None


def classify(mac: Optional[str], name: Optional[str] = None) -> dict:
    """{"vendor": str|None, "type": asset type|None, "private": bool} - type is one of printer / camera / mobile / network / virtual."""
    p = _prefix(mac)
    if p in _VM_PREFIX:
        return {"vendor": _VM_PREFIX[p], "type": "virtual", "private": False}
    v = vendor(mac)
    kind = next((k for k, rx in _KINDS if v and rx.search(v)), None)
    return {"vendor": v, "type": kind or type_from_name(name), "private": is_private(mac)}
