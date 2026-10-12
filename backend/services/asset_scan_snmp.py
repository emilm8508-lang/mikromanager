"""What a device tells over SNMP without any login - the "basic information" scan of the asset inventory (services/asset_scan.py).

Read-only SNMP v2c GETs/walks of the standard MIBs: MIB-II system group (description, name, location, contact, uptime), the
interface table (MAC), ENTITY-MIB (serial number, model, firmware, maker), HOST-RESOURCES (device description, memory) and
PRINTER-MIB (serial, page counter, status and the toner / ink / drum levels). The community string is the one of the device's
saved credential, then any other saved community, then "public"."""
import asyncio
from typing import Dict, List, Optional, Tuple

from services import asset_scan as base

TIMEOUT = 2.0
MAX_COMMUNITIES = 4

OID_SYS = "1.3.6.1.2.1.1"
OID_IF_PHYS = "1.3.6.1.2.1.2.2.1.6"
OID_ENT = "1.3.6.1.2.1.47.1.1.1.1"
OID_HR_DEVICE = "1.3.6.1.2.1.25.3.2.1"
OID_HR_PRINTER = "1.3.6.1.2.1.25.3.5.1"
OID_PRT_GENERAL = "1.3.6.1.2.1.43.5.1.1"
OID_PRT_LIFE = "1.3.6.1.2.1.43.10.2.1.4"
OID_PRT_SUPPLY = "1.3.6.1.2.1.43.11.1.1"
HR_DEVICE_PRINTER = "1.3.6.1.2.1.25.3.1.5"

# enterprise number (from sysObjectID 1.3.6.1.4.1.N) -> maker
_ENTERPRISES = {
    11: "HP", 2: "IBM", 9: "Cisco", 14988: "MikroTik", 41112: "Ubiquiti", 12356: "Fortinet", 25461: "Palo Alto Networks", 674: "Dell",
    2636: "Juniper", 1916: "Extreme Networks", 1991: "Brocade", 4526: "Netgear", 171: "D-Link", 11863: "TP-Link", 6876: "VMware",
    311: "Microsoft", 318: "APC", 534: "Eaton", 6574: "Synology", 24681: "QNAP", 47196: "Aruba", 2011: "Huawei", 6486: "Alcatel-Lucent",
    1602: "Canon", 1347: "Kyocera", 367: "Ricoh", 2435: "Brother", 236: "Samsung", 253: "Xerox", 1248: "Epson", 641: "Lexmark",
    18334: "Konica Minolta", 119: "NEC", 10: "Xerox", 3854: "Zebra", 2699: "Oki", 5951: "Citrix", 21317: "Zyxel",
    890: "Zyxel", 3955: "Linksys", 16901: "Axis", 25506: "H3C", 37476: "Ruckus", 4413: "Ruckus", 29671: "TRENDnet", 1872: "Alteon",
}
_PRINTER_STATUS = {1: "other", 2: "unknown", 3: "idle", 4: "printing", 5: "warming up"}
_SUPPLY_UNIT_PERCENT = 19


def _text(v) -> Optional[str]:
    from services.snmp_client import _decode
    t = _decode(v).replace("\x00", "").strip() if v is not None else ""
    return t or None


def _hex_mac(v) -> Optional[str]:
    if isinstance(v, (bytes, bytearray)) and len(v) == 6 and any(v):
        return ":".join(f"{b:02X}" for b in v)
    return None


def _num(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


async def _walk(client, oid: str, limit: int = 120, deadline: float = 6.0) -> List[Tuple[str, object]]:
    out: List[Tuple[str, object]] = []

    async def go():
        async for b in client._client.walk(oid):
            out.append((str(b.oid).lstrip("."), b.value))
            if len(out) >= limit:
                break
    try:
        await asyncio.wait_for(go(), timeout=deadline)
    except Exception:
        pass
    return out


async def _get(client, oid: str):
    try:
        return await client._get(oid)
    except Exception:
        return None


def _by_suffix(rows: List[Tuple[str, object]], base_oid: str) -> Dict[str, object]:
    pre = base_oid + "."
    return {o[len(pre):]: v for o, v in rows if o.startswith(pre)}


async def collect(ip: str, communities: List[str], port: int = 161) -> Optional[dict]:
    """The raw answers of the device, or None if it does not answer SNMP with any of the communities."""
    from services.snmp_client import SnmpClient
    client = None
    for c in communities[:MAX_COMMUNITIES]:
        cl = SnmpClient(ip, c, port=port, timeout=TIMEOUT)
        if await cl.probe():
            client = cl
            break
    if client is None:
        return None
    raw: Dict = {}
    for key, oid in (("descr", "1.1.0"), ("object_id", "1.2.0"), ("uptime", "1.3.0"), ("contact", "1.4.0"), ("name", "1.5.0"), ("location", "1.6.0")):
        raw[key] = await _get(client, f"1.3.6.1.2.1.{oid}")
    raw["if_mac"] = await _walk(client, OID_IF_PHYS, limit=40, deadline=4.0)
    raw["ent"] = {}
    for col, key in ((5, "class"), (8, "hw"), (9, "fw"), (10, "sw"), (11, "serial"), (12, "mfg"), (13, "model")):
        raw["ent"][key] = _by_suffix(await _walk(client, f"{OID_ENT}.{col}", limit=40, deadline=3.0), f"{OID_ENT}.{col}")
    raw["hr_type"] = _by_suffix(await _walk(client, f"{OID_HR_DEVICE}.2", limit=40, deadline=3.0), f"{OID_HR_DEVICE}.2")
    raw["hr_descr"] = _by_suffix(await _walk(client, f"{OID_HR_DEVICE}.3", limit=40, deadline=3.0), f"{OID_HR_DEVICE}.3")
    raw["hr_printer"] = _by_suffix(await _walk(client, f"{OID_HR_PRINTER}.1", limit=8, deadline=3.0), f"{OID_HR_PRINTER}.1")
    raw["prt_serial"] = await _get(client, f"{OID_PRT_GENERAL}.17.1")
    raw["prt_life"] = _by_suffix(await _walk(client, OID_PRT_LIFE, limit=8, deadline=3.0), OID_PRT_LIFE)
    sup = await _walk(client, OID_PRT_SUPPLY, limit=160, deadline=6.0)
    raw["supplies"] = {col: _by_suffix(sup, f"{OID_PRT_SUPPLY}.{col}") for col in (4, 5, 6, 7, 8, 9)}
    raw["is_printer"] = bool(raw["prt_life"] or raw["supplies"][6] or raw["prt_serial"] is not None
                             or any(str(v).lstrip(".") == HR_DEVICE_PRINTER for v in raw["hr_type"].values()))
    return raw


def _maker_of(object_id, descr: Optional[str], ent_mfg: Optional[str]) -> Optional[str]:
    if ent_mfg:
        return ent_mfg
    oid = str(object_id or "").lstrip(".")
    if oid.startswith("1.3.6.1.4.1."):
        try:
            n = int(oid.split(".")[6])
            if n in _ENTERPRISES:
                return _ENTERPRISES[n]
        except (IndexError, ValueError):
            pass
    low = (descr or "").lower()
    return next((name for name in dict.fromkeys(_ENTERPRISES.values()) if name.lower() in low), None)


def parse(raw: dict) -> dict:
    """The raw answers -> {"asset": ..., "details": ..., "peripherals": []} like the other scans' parse()."""
    descr, name, loc, contact = _text(raw.get("descr")), _text(raw.get("name")), _text(raw.get("location")), _text(raw.get("contact"))
    ticks = _num(raw.get("uptime"))
    ent = raw.get("ent") or {}

    # the chassis entry (class 3) holds the device's own serial/model; otherwise the first one that has a value
    def ent_val(key: str) -> Optional[str]:
        vals = {i: _text(v) for i, v in (ent.get(key) or {}).items() if _text(v)}
        if not vals:
            return None
        chassis = [i for i, v in (ent.get("class") or {}).items() if _num(v) == 3 and i in vals]
        return vals[min(chassis, key=lambda i: int(i))] if chassis else vals[min(vals, key=lambda i: int(i))]

    serial = base._serial(_text(raw.get("prt_serial"))) or base._serial(ent_val("serial"))
    model = ent_val("model")
    maker = _maker_of(raw.get("object_id"), descr, ent_val("mfg"))
    mac = next((m for m in (_hex_mac(v) for _, v in raw.get("if_mac") or []) if m), None)
    out: Dict = {"asset": {}, "details": {}, "peripherals": []}

    pr_idx = next((i for i, v in (raw.get("hr_type") or {}).items() if str(v).lstrip(".") == HR_DEVICE_PRINTER), None)
    hr_descr = _text((raw.get("hr_descr") or {}).get(pr_idx)) if pr_idx is not None else None
    if raw.get("is_printer"):
        model = hr_descr or model or (descr or "")[:80] or None
        sup = raw.get("supplies") or {}
        supplies = []
        for idx, d in sorted((sup.get(6) or {}).items(), key=lambda kv: [int(p) for p in kv[0].split(".") if p.isdigit()]):
            level, mx = _num((sup.get(9) or {}).get(idx)), _num((sup.get(8) or {}).get(idx))
            pct = None
            if level is not None and level >= 0:
                pct = max(0, min(100, round(level * 100 / mx))) if mx and mx > 0 else (level if _num((sup.get(7) or {}).get(idx)) == _SUPPLY_UNIT_PERCENT else None)
            elif level == 0:
                pct = 0
            supplies.append({"name": _text(d) or f"supply {idx}", "level_pct": pct})
        status = _num(next(iter((raw.get("hr_printer") or {}).values()), None))
        pages = next((n for n in (_num(v) for v in (raw.get("prt_life") or {}).values()) if n is not None), None)
        out["details"]["printer"] = {k: v for k, v in {
            "model": model, "serial": serial, "status": _PRINTER_STATUS.get(status) if status else None, "pages_total": pages,
            "location": loc, "contact": contact, "uptime_sec": ticks // 100 if ticks else None, "firmware_version": ent_val("fw") or ent_val("sw"),
            "description": descr, "supplies": supplies,
        }.items() if v not in (None, "", [])}
        out["asset"]["asset_type"] = "printer"
    else:
        out["details"]["snmp"] = {k: v for k, v in {
            "description": descr, "hostname": name, "location": loc, "contact": contact, "uptime_sec": ticks // 100 if ticks else None,
            "model": model, "serial": serial, "hardware_revision": ent_val("hw"), "firmware_version": ent_val("fw"), "software_version": ent_val("sw"),
            "object_id": str(raw.get("object_id") or "").lstrip(".") or None,
        }.items() if v}
    out["asset"].update({"manufacturer": maker, "model": model, "serial": serial, "mac": mac})
    return out
