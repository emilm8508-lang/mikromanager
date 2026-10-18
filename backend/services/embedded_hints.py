"""Embedded devices that are often left on their factory password - a hint to check by hand, never a test.

Management controllers (iLO, iDRAC, BMC), serial-to-Ethernet servers (Lantronix XPort), label and industrial printers (SATO, Zebra, InfoPrint), network
printers, IP cameras, UPS network cards, NAS boxes and home-grade network gear are shipped with a known default login, and a good part of them stays
that way. Recognising such a device is enough to put it on the operator's list: the agent does NOT try any password - that would be an attack on the
device, and lock accounts out. The advice is to open its panel and set an own password (and, where it exists, to switch the service off).

The evidence is the same as for the device class: what the device says about itself (model, name, maker, the service banners the vulnerability scan
collected) and the maker of its network card."""
import re
from typing import Dict, List, Optional

# code -> (pattern, the pattern is matched against: "model name maker os banners")
RULES: Dict[str, re.Pattern] = {
    "ilo": re.compile(r"\bilo[ -]?\d?\b|integrated lights[- ]out|hp ?ilo|hpe? ?ilo", re.I),
    "idrac": re.compile(r"\bidrac\d?\b|integrated dell remote", re.I),
    "bmc": re.compile(r"supermicro|aspeed|\bipmi\b|\bbmc\b|megarac|ami ?megarac", re.I),
    "xport": re.compile(r"\bxport\b|lantronix|\buds-?\d|\bwiport\b|\bdevice server\b", re.I),
    "label_printer": re.compile(r"\bsato\b|zebra|intermec|\bzt\d{3}\b|\bzd\d{3}\b|infoprint|\btsc\b|datamax|godex", re.I),
    "printer": re.compile(r"jetdirect|laserjet|officejet|brother|epson|canon|ricoh|kyocera|konica|minolta|xerox|lexmark|\boki\b|samsung (m|c|x)\d|\bmfp\b|bizhub", re.I),
    "camera": re.compile(r"hikvision|dahua|\baxis\b|reolink|foscam|vivotek|uniview|amcrest|\bipcam|\bnvr\b|\bdvr\b|geovision|mobotix|hanwha|wisenet", re.I),
    "ups": re.compile(r"\bapc\b|schneider electric|\beaton\b|powerware|\bvertiv\b|liebert|network management card|\bups[- ]?(card|web)|\bnmc\b", re.I),
    "nas": re.compile(r"synology|diskstation|qnap|readynas|buffalo|western digital|\bwd my|terramaster|asustor|\bdsm\b", re.I),
    "soho": re.compile(r"ubiquiti|\bubnt\b|\bunifi\b|tp-?link|netgear|d-?link|zyxel|tenda|linksys|\bmercusys|\bhuawei (hg|echolife)|\btechnicolor|\bfritz!?box", re.I),
    "industrial": re.compile(r"siemens|simatic|\bmoxa\b|advantech|\bwago\b|phoenix contact|\bmodbus\b|beckhoff|\bhms\b|\bhirschmann|schneider (m\d|plc)", re.I),
    "raspberry": re.compile(r"raspberry|raspbian|\braspi\b", re.I),
}
CODES = tuple(RULES)


def match(*texts: Optional[str]) -> List[str]:
    """The codes of RULES that match any of the given texts (the device's model, name, maker, OS and service banners), most specific first."""
    blob = " ".join(t for t in texts if t)
    if not blob.strip():
        return []
    hits = [code for code, rx in RULES.items() if rx.search(blob)]
    if "label_printer" in hits and "printer" in hits:
        hits.remove("printer")                       # the more specific one says it
    return hits
