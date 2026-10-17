"""Ports of any SNMP switch, read with the standard MIBs - so the rack view works for Cisco Small Business (SG200 / 250 / 300 / 350 ...)
and for any other vendor's switch that speaks SNMP v2c, not only for MikroTik.

What is read (all standard, read-only):
  IF-MIB            port names, state, speed, alias (the port description), counters (traffic is the change between two reads)
  Q-BRIDGE / BRIDGE the MAC table: which MAC was learned on which port (and VLAN)
  LLDP-MIB          the neighbours: remote name, port and management address, per local port
  POWER-ETHERNET    PoE: whether a port is powered, the supply's total and used power

The result has the same shape as the MikroTik snapshot of services/racks.py (`ifaces`, `neighbors`, `bridge`, `poe`, `stats`) so one
code path draws both. Nothing is written to the device."""
import asyncio
import re
import time
from typing import Dict, List, Optional, Tuple

from services.snmp_client import SnmpClient, IF_TYPE_NAMES, _decode

OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_QB_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_QB_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
OID_B_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_B_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
OID_LLDP_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
OID_LLDP_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.3"
OID_PETH_ADMIN = "1.3.6.1.2.1.105.1.1.1.3"
OID_PETH_DETECT = "1.3.6.1.2.1.105.1.1.1.6"
OID_PETH_MAIN_POWER = "1.3.6.1.2.1.105.1.3.1.1.2"
OID_PETH_MAIN_USED = "1.3.6.1.2.1.105.1.3.1.1.4"

_PETH_STATUS = {1: "disabled", 2: "searching", 3: "delivering", 4: "fault", 5: "test", 6: "fault"}
_working_community: Dict[str, str] = {}
_last_counters: Dict[str, Tuple[float, Dict[str, Tuple[int, int]]]] = {}
_SKIP_TYPES = ("loopback", "propVirtual", "l2vlan", "bridge", "tunnel", "mplsTunnel", "other", "softwareLoopback")


def _tail(oid: str, base: str) -> List[int]:
    """The numbers of an OID after its column `base` (the table index)."""
    o = oid.lstrip(".")
    if not o.startswith(base + "."):
        return []
    out = []
    for p in o[len(base) + 1:].split("."):
        if not p.isdigit():
            return []
        out.append(int(p))
    return out


def _mac(nums: List[int]) -> Optional[str]:
    return ":".join(f"{n:02X}" for n in nums) if len(nums) == 6 and all(0 <= n < 256 for n in nums) else None


def _bytes_mac(v) -> Optional[str]:
    if isinstance(v, (bytes, bytearray)) and len(v) == 6:
        return ":".join(f"{b:02X}" for b in v)
    return None


def _speed(mbps) -> Optional[str]:
    try:
        n = int(mbps)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return f"{n // 1000}Gbps" if n >= 1000 and n % 1000 == 0 else f"{n}Mbps"


async def _walk(c: SnmpClient, base: str) -> list:
    try:
        return await c._walk(base)
    except Exception:
        return []


async def find_community(ip: str, communities: List[str], port: int = 161) -> Optional[str]:
    """The first community the device answers to (remembered per address)."""
    tried = []
    first = _working_community.get(ip)
    for com in ([first] if first else []) + [x for x in communities if x and x != first]:
        tried.append(com)
        if await SnmpClient(ip, com, port=port, timeout=2.5).probe():
            _working_community[ip] = com
            return com
    return None


async def read(ip: str, communities: List[str], port: int = 161) -> Optional[dict]:
    """Snapshot of the switch's ports, or None when no community works / the device has no interface table."""
    com = await find_community(ip, communities, port)
    if not com:
        return None
    c = SnmpClient(ip, com, port=port, timeout=4.0)
    names_w, descr_w, types_w, admin_w, oper_w, speed_w, alias_w, hin_w, hout_w = await asyncio.gather(
        _walk(c, OID_IF_NAME), _walk(c, OID_IF_DESCR), _walk(c, OID_IF_TYPE), _walk(c, OID_IF_ADMIN), _walk(c, OID_IF_OPER),
        _walk(c, OID_IF_HIGH_SPEED), _walk(c, OID_IF_ALIAS), _walk(c, OID_IF_HC_IN), _walk(c, OID_IF_HC_OUT))

    def by_if(rows, base, conv=lambda v: v):
        d = {}
        for oid, v in rows:
            t = _tail(oid, base)
            if len(t) == 1:
                d[t[0]] = conv(v)
        return d

    names = by_if(names_w, OID_IF_NAME, _decode)
    descr = by_if(descr_w, OID_IF_DESCR, _decode)
    types = by_if(types_w, OID_IF_TYPE, lambda v: IF_TYPE_NAMES.get(int(v), str(v)) if v is not None else "")
    admin = by_if(admin_w, OID_IF_ADMIN, int)
    oper = by_if(oper_w, OID_IF_OPER, int)
    speed = by_if(speed_w, OID_IF_HIGH_SPEED, int)
    alias = by_if(alias_w, OID_IF_ALIAS, _decode)
    hin = by_if(hin_w, OID_IF_HC_IN, int)
    hout = by_if(hout_w, OID_IF_HC_OUT, int)
    if not (names or descr):
        return None
    idx_name = {i: (names.get(i) or descr.get(i) or f"if{i}") for i in set(names) | set(descr)}

    ifaces = []
    for i, name in sorted(idx_name.items()):
        t = types.get(i, "")
        if t in _SKIP_TYPES or t.lower().startswith(("lag", "ieee8023ad")):
            continue
        up = oper.get(i) == 1
        ifaces.append({"name": name, "type": t or "ethernet", "running": up, "disabled": admin.get(i) == 2, "comment": alias.get(i) or None,
                       "speed": _speed(speed.get(i)) if up else None, "ifindex": i})

    # traffic = counter change since the previous read of this device
    now = time.time()
    stats: Dict[str, dict] = {}
    cur = {idx_name[i]: (hin.get(i), hout.get(i)) for i in idx_name if i in hin or i in hout}
    prev = _last_counters.get(ip)
    if prev and now - prev[0] >= 5:
        for n, (a, b) in cur.items():
            pa, pb = prev[1].get(n, (None, None))
            if a is not None and pa is not None and b is not None and pb is not None and a >= pa and b >= pb:
                dt = now - prev[0]
                stats[n] = {"rx_mbps": round((a - pa) * 8 / dt / 1e6, 3), "tx_mbps": round((b - pb) * 8 / dt / 1e6, 3)}
    if not prev or now - prev[0] >= 5:
        _last_counters[ip] = (now, cur)

    neighbors, bridge, poe, poe_total = await asyncio.gather(_neighbors(c, idx_name), _fdb(c, idx_name), _poe(c, {f["ifindex"]: f["name"] for f in ifaces}), _poe_total(c))
    return {"ifaces": ifaces, "neighbors": neighbors, "bridge": bridge, "ethernet": [], "poe": poe, "poe_total": poe_total, "stats": stats, "vendor": "snmp"}


async def _neighbors(c: SnmpClient, idx_name: Dict[int, str]) -> List[dict]:
    sysn, pid, pdesc, csub, cid, mgmt = await asyncio.gather(
        _walk(c, OID_LLDP_SYSNAME), _walk(c, OID_LLDP_PORT_ID), _walk(c, OID_LLDP_PORT_DESC), _walk(c, OID_LLDP_CHASSIS_SUBTYPE), _walk(c, OID_LLDP_CHASSIS_ID), _walk(c, OID_LLDP_MAN_ADDR))

    def col(rows, base, conv=_decode):
        d = {}
        for oid, v in rows:
            t = _tail(oid, base)
            if len(t) == 3:
                d[tuple(t)] = conv(v)
        return d

    names, ports, descs = col(sysn, OID_LLDP_SYSNAME), col(pid, OID_LLDP_PORT_ID), col(pdesc, OID_LLDP_PORT_DESC)
    subs = col(csub, OID_LLDP_CHASSIS_SUBTYPE, lambda v: int(v))
    chassis = col(cid, OID_LLDP_CHASSIS_ID, lambda v: v)
    addr: Dict[Tuple[int, int, int], str] = {}
    for oid, _v in mgmt:
        t = _tail(oid, OID_LLDP_MAN_ADDR)
        if len(t) >= 9 and t[3] == 1 and t[4] == 4:              # timeMark.localPort.remIndex . subtype(1 = IPv4) . length(4) . a.b.c.d
            addr[(t[0], t[1], t[2])] = ".".join(str(x) for x in t[5:9])
    out = []
    for key in set(names) | set(ports) | set(descs):
        local = idx_name.get(key[1])
        if not local:
            continue
        mac = _bytes_mac(chassis.get(key)) if subs.get(key) == 4 else None
        port = descs.get(key) or ports.get(key)
        if port and re.fullmatch(r"[0-9A-Fa-f:]{17}", port):
            port = None                                          # a port id that is just a MAC says nothing
        out.append({"interface": local, "identity": names.get(key) or None, "interface-name": port or None, "mac-address": mac,
                    "address": addr.get(key), "platform": None})
    return out


async def _fdb(c: SnmpClient, idx_name: Dict[int, str]) -> List[dict]:
    """The MAC table. Q-BRIDGE (VLAN aware) first, the plain BRIDGE-MIB when the switch does not have it."""
    bp_rows, q_rows, qs_rows = await asyncio.gather(_walk(c, OID_BASE_PORT_IFINDEX), _walk(c, OID_QB_FDB_PORT), _walk(c, OID_QB_FDB_STATUS))
    bp2if = {}
    for oid, v in bp_rows:
        t = _tail(oid, OID_BASE_PORT_IFINDEX)
        if len(t) == 1 and v is not None:
            bp2if[t[0]] = int(v)
    out = []
    if q_rows:
        learned = {tuple(_tail(oid, OID_QB_FDB_STATUS)) for oid, v in qs_rows if v is not None and int(v) == 3} if qs_rows else None
        for oid, v in q_rows:
            t = _tail(oid, OID_QB_FDB_PORT)
            if len(t) != 7 or v is None:
                continue
            if learned is not None and tuple(t) not in learned:
                continue
            ifidx = bp2if.get(int(v), int(v))
            name, mac = idx_name.get(ifidx), _mac(t[1:])
            if name and mac:
                out.append({"mac-address": mac, "on-interface": name, "vid": str(t[0])})
        return out
    b_rows, bs_rows = await asyncio.gather(_walk(c, OID_B_FDB_PORT), _walk(c, OID_B_FDB_STATUS))
    learned = {tuple(_tail(oid, OID_B_FDB_STATUS)) for oid, v in bs_rows if v is not None and int(v) == 3} if bs_rows else None
    for oid, v in b_rows:
        t = _tail(oid, OID_B_FDB_PORT)
        if len(t) != 6 or v is None or (learned is not None and tuple(t) not in learned):
            continue
        name, mac = idx_name.get(bp2if.get(int(v), int(v))), _mac(t)
        if name and mac:
            out.append({"mac-address": mac, "on-interface": name})
    return out


async def _poe(c: SnmpClient, idx_name: Dict[int, str]) -> Dict[str, dict]:
    """{port name: {"mode", "on", "status"}} from POWER-ETHERNET-MIB. The MIB numbers ports by group (unit) and port index; both are matched to
    the interface name's trailing numbers (gi1, Gi1/0/5, te2/0/3 ...), which is how the switches that have it number them."""
    adm, det = await asyncio.gather(_walk(c, OID_PETH_ADMIN), _walk(c, OID_PETH_DETECT))
    if not det and not adm:
        return {}
    by_unit_port: Dict[Tuple[int, int], str] = {}
    for name in idx_name.values():
        m = re.search(r"(\d+)/(?:\d+/)?(\d+)$", name) or re.search(r"(\d+)$", name)
        if not m:
            continue
        by_unit_port[(int(m.group(1)), int(m.group(2))) if m.lastindex == 2 else (1, int(m.group(1)))] = name
    out: Dict[str, dict] = {}
    for rows, base, key in ((adm, OID_PETH_ADMIN, "mode"), (det, OID_PETH_DETECT, "status")):
        for oid, v in rows:
            t = _tail(oid, base)
            if len(t) != 2 or v is None:
                continue
            name = by_unit_port.get((t[0], t[1]))
            if not name:
                continue
            e = out.setdefault(name, {"mode": None, "on": None, "status": None})
            if key == "mode":
                e["mode"] = "auto" if int(v) == 1 else "off"
            else:
                e["status"] = _PETH_STATUS.get(int(v), "unknown")
                e["on"] = int(v) == 3
    return out


async def _poe_total(c: SnmpClient) -> Optional[dict]:
    """The supply's budget and what is drawn from it (watts), summed over the groups."""
    pw, used = await asyncio.gather(_walk(c, OID_PETH_MAIN_POWER), _walk(c, OID_PETH_MAIN_USED))
    total = sum(int(v) for _o, v in pw if v is not None)
    drawn = sum(int(v) for _o, v in used if v is not None)
    return {"budget_w": total, "used_w": drawn} if total or drawn else None
