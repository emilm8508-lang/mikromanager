"""Server racks: which device sits in which cabinet, and what is plugged into what.

A rack is a stack of units (U); every device (an inventory asset) or manual item (patch panel, UPS, shelf ...) occupies some of them.
What makes it more than a drawing is that it is read live from the network gear:

  * a MikroTik router / switch with a credential is asked for its ports (state, negotiated speed, traffic), its LLDP / MNDP neighbours
    and its bridge (MAC) table - so every port shows what is behind it: another switch (LLDP), or the device whose MAC was learned there;
  * a computer is tied to the switch port its network card's MAC was learned on (only switches that stand in the same rack are asked);
  * what no device can report (patch panels, unmanaged switches, wall sockets) is cabled by hand (RackLink).

`live(rack_id)` returns the ports per item and the links between the items of the rack; `public_summary()` is the sanitised copy
the Central relay receives (no credentials, no MAC tables - only names, ports and what is connected to what)."""
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete

from models.database import SessionLocal, Rack, RackItem, RackLink, Asset, Device, Credential

MANUAL_KINDS = ("patch_panel", "switch", "ups", "pdu", "cable_manager", "shelf", "blank", "other")
DEFAULT_HEIGHT = {"network": 1, "server": 2, "windows": 1, "linux": 1, "printer": 2, "virtual": 1}
_DEFAULT_PORTS = {"patch_panel": 24, "switch": 24}
CABLES = ("cat6", "fibre", "dac", "power", "other")
SNAPSHOT_TTL = 45.0
STALE_DAYS = 7
_VIRTUAL_IFACE_TYPES = ("bridge", "vlan", "loopback", "vrrp", "wg", "wireguard", "eoip", "gre", "ipip", "6to4", "bond", "veth", "vxlan", "tunnel",
                        "ppp", "pppoe", "l2tp", "sstp", "ovpn", "pptp", "l2vlan", "propvirtual", "mplstunnel", "ieee8023adlag", "other", "lte", "cap", "wifi", "wireless", "wlan")

_snapshots: Dict[int, tuple] = {}
_snap_lock = asyncio.Lock()


def _b(v) -> bool:
    return v is True or str(v).lower() in ("true", "yes", "1")


def _jload(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default


def _norm_mac(m) -> Optional[str]:
    h = "".join(c for c in str(m or "") if c in "0123456789abcdefABCDEF")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper() if len(h) == 12 else None


# ── CRUD ─────────────────────────────────────────────────────────────────────

class RackError(ValueError):
    pass


def _clean(s, n=120) -> Optional[str]:
    s = " ".join(str(s or "").split())[:n]
    return s or None


def _rack_out(r: Rack, items: List[RackItem]) -> dict:
    return {"id": r.id, "name": r.name, "location": r.location, "units": r.units, "notes": r.notes,
            "items": len(items), "used_u": sum(i.height for i in items)}


def list_racks() -> List[dict]:
    with SessionLocal() as db:
        items = db.execute(select(RackItem)).scalars().all()
        by_rack: Dict[int, list] = {}
        for i in items:
            by_rack.setdefault(i.rack_id, []).append(i)
        return [_rack_out(r, by_rack.get(r.id, [])) for r in db.execute(select(Rack).order_by(Rack.name)).scalars().all()]


def save_rack(rack_id: Optional[int], name: str, location: Optional[str], units: int, notes: Optional[str]) -> dict:
    name = _clean(name, 80)
    if not name:
        raise RackError("the rack needs a name")
    units = max(1, min(60, int(units or 42)))
    with SessionLocal() as db:
        if rack_id:
            r = db.get(Rack, rack_id)
            if not r:
                raise RackError("rack not found")
            top = max([i.u + i.height - 1 for i in db.execute(select(RackItem).where(RackItem.rack_id == r.id)).scalars().all()] or [0])
            if units < top:
                raise RackError(f"the rack holds a device up to U{top}; remove or move it first")
        else:
            r = Rack()
            db.add(r)
        r.name, r.location, r.units, r.notes = name, _clean(location), units, (notes or "").strip()[:2000] or None
        db.commit()
        db.refresh(r)
        return _rack_out(r, db.execute(select(RackItem).where(RackItem.rack_id == r.id)).scalars().all())


def delete_rack(rack_id: int) -> bool:
    with SessionLocal() as db:
        r = db.get(Rack, rack_id)
        if not r:
            return False
        db.execute(delete(RackLink).where(RackLink.rack_id == rack_id))
        db.execute(delete(RackItem).where(RackItem.rack_id == rack_id))
        db.delete(r)
        db.commit()
    return True


def _fits(db, rack: Rack, u: int, height: int, ignore_id: Optional[int] = None) -> None:
    if u < 1 or height < 1 or u + height - 1 > rack.units:
        raise RackError(f"does not fit: the rack has U1-U{rack.units}")
    for i in db.execute(select(RackItem).where(RackItem.rack_id == rack.id)).scalars().all():
        if i.id != ignore_id and not (u + height - 1 < i.u or u > i.u + i.height - 1):
            raise RackError(f"U{max(u, i.u)} is taken by '{i.label or 'a device'}'")


def add_item(rack_id: int, u: int, height: Optional[int], asset_id: Optional[int], kind: Optional[str], label: Optional[str],
             port_count: Optional[int] = None) -> dict:
    with SessionLocal() as db:
        rack = db.get(Rack, rack_id)
        if not rack:
            raise RackError("rack not found")
        item = RackItem(rack_id=rack_id, u=int(u))
        if asset_id:
            a = db.get(Asset, asset_id)
            if not a:
                raise RackError("asset not found")
            if db.execute(select(RackItem.id).where(RackItem.asset_id == asset_id)).first():
                raise RackError("this asset is already in a rack")
            item.asset_id, item.kind = asset_id, "asset"
            item.label = _clean(label) or a.name or a.ip
            item.height = int(height or DEFAULT_HEIGHT.get(a.asset_type, 1))
        else:
            if kind not in MANUAL_KINDS:
                raise RackError("unknown item kind")
            item.kind, item.label = kind, _clean(label) or kind.replace("_", " ")
            item.height = int(height or 1)
            item.port_count = max(0, min(96, int(port_count if port_count is not None else _DEFAULT_PORTS.get(kind, 0)))) or None
        _fits(db, rack, item.u, item.height)
        db.add(item)
        db.commit()
        return {"id": item.id}


def update_item(item_id: int, fields: dict) -> dict:
    with SessionLocal() as db:
        item = db.get(RackItem, item_id)
        if not item:
            raise RackError("item not found")
        rack = db.get(Rack, item.rack_id)
        u, h = int(fields.get("u", item.u)), int(fields.get("height", item.height))
        if "rack_id" in fields and int(fields["rack_id"]) != item.rack_id:
            rack = db.get(Rack, int(fields["rack_id"]))
            if not rack:
                raise RackError("rack not found")
            for l in db.execute(select(RackLink).where((RackLink.item_a_id == item.id) | (RackLink.item_b_id == item.id))).scalars().all():
                db.delete(l)                     # a cable does not follow a device into another cabinet
            item.rack_id = rack.id
        _fits(db, rack, u, h, ignore_id=item.id)
        item.u, item.height = u, h
        if "label" in fields:
            item.label = _clean(fields["label"]) or item.label
        if "notes" in fields:
            item.notes = (fields["notes"] or "").strip()[:2000] or None
        if "port_count" in fields and item.kind != "asset":
            item.port_count = max(0, min(96, int(fields["port_count"] or 0))) or None
        db.commit()
    return {"ok": True}


def delete_item(item_id: int) -> bool:
    with SessionLocal() as db:
        item = db.get(RackItem, item_id)
        if not item:
            return False
        db.execute(delete(RackLink).where((RackLink.item_a_id == item_id) | (RackLink.item_b_id == item_id)))
        db.delete(item)
        db.commit()
    return True


def add_link(rack_id: int, item_a_id: int, port_a: Optional[str], item_b_id: Optional[int], port_b: Optional[str],
             remote_text: Optional[str], label: Optional[str], cable: Optional[str]) -> dict:
    with SessionLocal() as db:
        ids = {i.id for i in db.execute(select(RackItem).where(RackItem.rack_id == rack_id)).scalars().all()}
        if item_a_id not in ids or (item_b_id and item_b_id not in ids):
            raise RackError("both ends must be items of this rack")
        if not item_b_id and not _clean(remote_text):
            raise RackError("name the other end")
        l = RackLink(rack_id=rack_id, item_a_id=item_a_id, port_a=_clean(port_a, 40), item_b_id=item_b_id or None, port_b=_clean(port_b, 40),
                     remote_text=_clean(remote_text) if not item_b_id else None, label=_clean(label, 80), cable=cable if cable in CABLES else None)
        db.add(l)
        db.commit()
        return {"id": l.id}


def delete_link(link_id: int) -> bool:
    with SessionLocal() as db:
        l = db.get(RackLink, link_id)
        if not l:
            return False
        db.delete(l)
        db.commit()
    return True


# ── Reading ──────────────────────────────────────────────────────────────────

def _asset_light(a: Asset, device: Optional[Device], now: datetime) -> dict:
    refs = _jload(a.refs, {})
    active = bool(a.last_seen_at and now - a.last_seen_at < timedelta(days=STALE_DAYS))
    return {"id": a.id, "name": a.name or a.ip or a.key, "type": a.asset_type, "role": a.role, "ip": a.ip, "mac": a.mac,
            "manufacturer": a.manufacturer, "model": a.model, "serial": a.serial, "location": a.location_override,
            "online": device.online if device is not None else active, "managed": bool(device and device.credential_id), "refs": {k: v for k, v in refs.items() if isinstance(v, int)}}


def get_rack(rack_id: int) -> Optional[dict]:
    now = datetime.utcnow()
    with SessionLocal() as db:
        r = db.get(Rack, rack_id)
        if not r:
            return None
        items = db.execute(select(RackItem).where(RackItem.rack_id == rack_id).order_by(RackItem.u)).scalars().all()
        assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_([i.asset_id for i in items if i.asset_id] or [0]))).scalars().all()}
        dev_ids = [_jload(a.refs, {}).get("device_id") for a in assets.values()]
        devices = {d.id: d for d in db.execute(select(Device).where(Device.id.in_([d for d in dev_ids if d] or [0]))).scalars().all()}
        out = []
        for i in items:
            a = assets.get(i.asset_id) if i.asset_id else None
            dev = devices.get(_jload(a.refs, {}).get("device_id")) if a else None
            out.append({"id": i.id, "kind": i.kind, "label": i.label, "u": i.u, "height": i.height, "port_count": i.port_count, "notes": i.notes,
                        "asset": _asset_light(a, dev, now) if a else None})
        links = [{"id": l.id, "a": l.item_a_id, "a_port": l.port_a, "b": l.item_b_id, "b_port": l.port_b, "remote": l.remote_text, "label": l.label,
                  "cable": l.cable, "kind": "manual"} for l in db.execute(select(RackLink).where(RackLink.rack_id == rack_id)).scalars().all()]
        return {**_rack_out(r, items), "items": out, "links": links}


def palette(rack_id: Optional[int] = None) -> List[dict]:
    """The assets that are in no rack yet; `suggested` marks the ones whose location is the rack's location."""
    now = datetime.utcnow()
    from services import assets as assets_svc
    with SessionLocal() as db:
        rack = db.get(Rack, rack_id) if rack_id else None
        placed = {i for i, in db.execute(select(RackItem.asset_id).where(RackItem.asset_id.is_not(None))).all()}
        locate = assets_svc._locator(db)
        out = []
        for a in db.execute(select(Asset).where(Asset.asset_type.in_(("network", "server", "windows", "linux", "printer", "other", "virtual")))).scalars().all():
            if a.id in placed or a.key.startswith(("mon:", "prt:", "vm:")) or a.asset_type == "virtual":
                continue
            loc = a.location_override or locate(a.ip)
            active = bool(a.last_seen_at and now - a.last_seen_at < timedelta(days=STALE_DAYS))
            infra = a.asset_type in ("network", "server") or a.role == "server"
            if not active and not infra:
                continue
            out.append({"id": a.id, "name": a.name or a.ip or a.key, "type": a.asset_type, "role": a.role, "ip": a.ip, "model": a.model, "location": loc,
                        "infra": infra, "suggested": bool(rack and rack.location and loc and loc.strip().lower() == rack.location.strip().lower())})
    out.sort(key=lambda x: (not x["suggested"], not x["infra"], (x["name"] or "").lower()))
    return out


def add_suggested(rack_id: int) -> dict:
    """Mounts every suggested device (location = the rack's location) at the first free units from the top: network gear first."""
    placed = 0
    order = {"network": 0, "server": 1}
    with SessionLocal() as db:
        rack = db.get(Rack, rack_id)
        if not rack:
            raise RackError("rack not found")
    for a in sorted([p for p in palette(rack_id) if p["suggested"]], key=lambda p: (order.get(p["type"], 2), p["name"] or "")):
        h = DEFAULT_HEIGHT.get(a["type"], 1)
        with SessionLocal() as db:
            taken = [(i.u, i.u + i.height - 1) for i in db.execute(select(RackItem).where(RackItem.rack_id == rack_id)).scalars().all()]
        for u in range(rack.units - h + 1, 0, -1):
            if all(u + h - 1 < lo or u > hi for lo, hi in taken):
                try:
                    add_item(rack_id, u, h, a["id"], None, None)
                    placed += 1
                except RackError:
                    pass
                break
    return {"placed": placed}


# ── Live data ────────────────────────────────────────────────────────────────

def _physical(iface: dict) -> bool:
    t = str(iface.get("type") or "").lower()
    name = str(iface.get("name") or "")
    if not name or t in _VIRTUAL_IFACE_TYPES:
        return False
    return t.startswith(("ether", "sfp", "gigabit", "fast", "ten", "qsfp")) or t == ""


def _speed(txt) -> Optional[str]:
    t = str(txt or "").strip()
    return t or None


def _saved_communities(first: Optional[str] = None) -> List[str]:
    """SNMP v2c communities to try: the device's own, then every saved one, then "public"."""
    from services.crypto import decrypt
    out: List[str] = [first] if first else []
    with SessionLocal() as db:
        for c in db.execute(select(Credential)).scalars().all():
            try:
                v = decrypt(c.snmp_community_enc) if c.snmp_community_enc else None
            except Exception:
                v = None
            if v and v not in out:
                out.append(v)
    if "public" not in out:
        out.append("public")
    return out


async def _fetch_asset_snmp(asset_id: int) -> Optional[dict]:
    """A switch that is only an asset (no router / switch record with a credential): read over SNMP with the saved communities."""
    from services import snmp_ports
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        ip = a.ip if a else None
    if not ip:
        return {"error": "the asset has no address"}
    snap = await snmp_ports.read(ip, _saved_communities())
    return snap or {"error": "no SNMP answer (tried the saved communities and public)"}


async def _fetch_snapshot(device_id: int) -> Optional[dict]:
    from services.device_client import build_client
    if device_id < 0:                                   # a negative key = an asset read over SNMP
        return await _fetch_asset_snmp(-device_id)
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        c = db.get(Credential, d.credential_id) if d and d.credential_id else None
        vendor = ((d.vendor if d else None) or "mikrotik").lower()
        if d and vendor != "mikrotik":                  # Cisco Small Business and other SNMP switches: the standard MIBs
            from services import snmp_ports
            from services.crypto import decrypt
            try:
                com = decrypt(c.snmp_community_enc) if c and c.snmp_community_enc else None
            except Exception:
                com = None
            ip, port = d.ip, d.snmp_port or 161
        elif not d or not c:
            return {"error": "no credential for this device"}
        else:
            try:
                client = build_client(d, c)
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}
    if vendor != "mikrotik":
        snap = await snmp_ports.read(ip, _saved_communities(com), port)
        return snap or {"error": "no SNMP answer (check the community in the device's credential)"}

    async def step(fn, default):
        try:
            return await asyncio.wait_for(fn(), 12) or default
        except Exception:
            return default

    ifaces = await step(client.get_interfaces, [])
    neighbors = await step(client.get_neighbors, [])
    bridge = await step(client.get_bridge_hosts, []) if hasattr(client, "get_bridge_hosts") and vendor == "mikrotik" else []
    ethernet = await step(client.get_ethernet, []) if hasattr(client, "get_ethernet") else []
    poe = await step(client.get_poe, {}) if hasattr(client, "get_poe") else {}
    if not ifaces:
        return {"error": "the device did not answer"}
    return {"ifaces": ifaces, "neighbors": neighbors, "bridge": bridge, "ethernet": ethernet, "poe": poe, "vendor": vendor}


async def _snapshot(device_id: int, fresh: bool = False) -> Optional[dict]:
    hit = _snapshots.get(device_id)
    ttl = SNAPSHOT_TTL if not hit or (hit[1] and "ifaces" in hit[1]) or device_id > 0 else 300.0    # a switch that did not answer SNMP is not asked again for 5 min
    if hit and not fresh and time.time() - hit[0] < ttl:
        return hit[1]
    data = await _fetch_snapshot(device_id)
    _snapshots[device_id] = (time.time(), data)
    return data


class _Resolver:
    """MAC -> what it is: an inventory asset, a DHCP / ARP host, or at least a vendor."""

    def __init__(self, db, directory: List[dict]):
        from services import oui
        self._oui = oui
        self.assets: Dict[str, dict] = {}
        for a in db.execute(select(Asset).where(Asset.mac.is_not(None))).scalars().all():
            m = _norm_mac(a.mac)
            if m and not a.key.startswith(("mon:", "prt:")):
                self.assets[m] = {"asset_id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "type": a.asset_type}
        for a in db.execute(select(Asset).where(Asset.details.is_not(None), Asset.asset_type.in_(("windows", "linux", "server", "virtual")))).scalars().all():
            for n in _jload(a.details, {}).get("network_adapters", []) or []:
                m = _norm_mac(n.get("mac"))
                if m and m not in self.assets:
                    self.assets[m] = {"asset_id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "type": a.asset_type}
        self.dir: Dict[str, dict] = {}
        for e in directory:
            m = _norm_mac(e.get("mac"))
            if m and m not in self.dir:
                self.dir[m] = e

    def resolve(self, mac: str) -> dict:
        m = _norm_mac(mac)
        if m in self.assets:
            return {"mac": m, **self.assets[m]}
        e = self.dir.get(m or "")
        if e:
            return {"mac": m, "name": e.get("name") or e.get("ip") or m, "ip": e.get("ip"), "asset_id": None, "type": None}
        c = self._oui.classify(m, None) if m else {}
        return {"mac": m, "name": c.get("vendor") or m, "ip": None, "asset_id": None, "type": c.get("type")}


def _ports_from_snapshot(snap: dict, stats: Dict[str, dict], resolver: _Resolver, ip_assets: Dict[str, dict]) -> List[dict]:
    eth = {str(e.get("name")): e for e in snap.get("ethernet") or []}
    by_port_macs: Dict[str, list] = {}
    for b in snap.get("bridge") or []:
        if _b(b.get("local")):
            continue
        by_port_macs.setdefault(str(b.get("on-interface") or ""), []).append(b)
    by_port_neigh: Dict[str, dict] = {}
    for n in snap.get("neighbors") or []:
        for p in str(n.get("interface") or n.get("interfaces") or "").split(","):
            p = p.strip()
            if p and p not in by_port_neigh and (n.get("identity") or n.get("address") or n.get("mac-address")):
                by_port_neigh[p] = n
    ports = []
    for f in snap["ifaces"]:
        if not _physical(f):
            continue
        name = str(f["name"])
        e = eth.get(name, {})
        st = (snap.get("stats") or {}).get(name) or stats.get(name, {})
        port = {"name": name, "up": _b(f.get("running")) and not _b(f.get("disabled")), "disabled": _b(f.get("disabled")),
                "speed": _speed(e.get("rate") or e.get("speed") or f.get("speed")), "rx_mbps": st.get("rx_mbps"), "tx_mbps": st.get("tx_mbps"),
                "comment": f.get("comment") or None, "remote": None}
        p = (snap.get("poe") or {}).get(name)
        if p:
            mode = str(p.get("mode") or "").lower()
            port["poe"] = {"mode": p.get("mode"), "on": p.get("on"), "status": p.get("status"), "watts": p.get("watts"), "off": mode in ("off", "disabled", "false")}
        macs = by_port_macs.get(name, [])
        port["mac_count"] = len(macs)
        port["_macs"] = [m for m in (_norm_mac(b.get("mac-address")) for b in macs[:2000]) if m]      # for locating hosts; never sent out
        vlans = sorted({str(b.get("vid")) for b in macs if b.get("vid")})
        if vlans:
            port["vlan"] = ",".join(vlans[:4])
        n = by_port_neigh.get(name)
        if n:
            ip = n.get("address") or n.get("address4")
            am = ip_assets.get(ip or "")
            port["remote"] = {"kind": "lldp", "name": n.get("identity") or ip or n.get("mac-address"), "ip": ip, "port": n.get("interface-name") or None,
                              "mac": _norm_mac(n.get("mac-address")), "asset_id": (am or {}).get("asset_id"), "platform": n.get("platform") or None}
        elif len(macs) == 1:
            r = resolver.resolve(macs[0].get("mac-address"))
            port["remote"] = {"kind": "mac", "name": r["name"], "ip": r["ip"], "mac": r["mac"], "asset_id": r["asset_id"], "port": None}
        elif len(macs) > 1:
            seen = [resolver.resolve(b.get("mac-address")) for b in macs[:8]]
            port["remote"] = {"kind": "multi", "count": len(macs), "name": f"{len(macs)} MAC", "asset_id": None,
                              "hosts": [{"name": r["name"], "ip": r["ip"], "mac": r["mac"], "asset_id": r["asset_id"]} for r in seen]}
        ports.append(port)
    ports.sort(key=lambda p: _port_key(p["name"]))
    return ports


def _port_key(name: str):
    import re
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", name)]


async def live(rack_id: int) -> Optional[dict]:
    """{items: {item_id: {online, ports | None, nics, error}}, links: [...]} - read from the devices, cached for SNAPSHOT_TTL seconds."""
    rack = get_rack(rack_id)
    if rack is None:
        return None
    from services import host_monitor
    try:
        directory = await host_monitor.directory(max_age=3600)
    except Exception:
        directory = []
    managed = {}                                   # item id -> device id (a router / switch with a credential), or -asset id (read over SNMP)
    for it in rack["items"]:
        a = it["asset"]
        if a and a["refs"].get("device_id") and a["managed"]:
            managed[it["id"]] = a["refs"]["device_id"]
        elif a and a["type"] == "network" and a["ip"]:
            managed[it["id"]] = -a["id"]
    snaps: Dict[int, Optional[dict]] = {}
    sem = asyncio.Semaphore(4)

    async def one(did):
        async with sem:
            snaps[did] = await _snapshot(did)

    await asyncio.gather(*(one(d) for d in set(managed.values())))
    with SessionLocal() as db:
        resolver = _Resolver(db, directory)
        ip_assets = {a.ip: {"asset_id": a.id} for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()}
        asset_item = {it["asset"]["id"]: it["id"] for it in rack["items"] if it["asset"]}
        stats_all: Dict[int, Dict[str, dict]] = {}
        from models.database import DeviceInterfaceStats
        for s in db.execute(select(DeviceInterfaceStats).where(DeviceInterfaceStats.device_id.in_([d for d in set(managed.values()) if d > 0] or [0]))).scalars().all():
            stats_all.setdefault(s.device_id, {})[s.iface_name] = {"rx_mbps": s.rx_mbps, "tx_mbps": s.tx_mbps}
        out_items: Dict[int, dict] = {}
        for it in rack["items"]:
            entry: dict = {"online": it["asset"]["online"] if it["asset"] else None, "ports": None, "nics": [], "error": None, "poe_total": None}
            did = managed.get(it["id"])
            if did:
                snap = snaps.get(did)
                if snap and "ifaces" in snap:
                    entry["ports"] = _ports_from_snapshot(snap, stats_all.get(did, {}), resolver, ip_assets)
                    entry["poe_total"] = snap.get("poe_total")
                else:
                    entry["error"] = (snap or {}).get("error") or "the device did not answer"
            elif it["asset"]:
                a = db.get(Asset, it["asset"]["id"])
                for n in (_jload(a.details, {}).get("network_adapters") or []) if a else []:
                    entry["nics"].append({"name": n.get("name"), "mac": _norm_mac(n.get("mac")), "ips": n.get("ips") or []})
                if a and not entry["nics"] and a.mac:
                    entry["nics"].append({"name": None, "mac": _norm_mac(a.mac), "ips": [a.ip] if a.ip else []})
            elif it["port_count"]:
                entry["ports"] = [{"name": str(n), "up": None, "remote": None} for n in range(1, it["port_count"] + 1)]
            out_items[it["id"]] = entry

    links: List[dict] = list(rack["links"])
    seen_pairs = set()
    # Where each MAC sits: in an all-switch network a host's MAC is learned on every switch up to the core, so the real port is the one that
    # has the fewest MACs behind it and no LLDP neighbour (an uplink has one). Taken out of the ports here - the full lists never leave.
    where: Dict[str, list] = {}
    for item_id, e in out_items.items():
        for p in e["ports"] or []:
            macs = p.pop("_macs", [])
            if (p.get("remote") or {}).get("kind") == "lldp":
                continue
            for m in macs:
                where.setdefault(m, []).append((len(macs), item_id, p["name"], p.get("vlan")))
    # switch <-> switch / router (LLDP)
    for item_id, e in out_items.items():
        for p in e["ports"] or []:
            r = p.get("remote") or {}
            tgt = asset_item.get(r.get("asset_id")) if r.get("asset_id") else None
            if r.get("kind") == "lldp" and tgt and tgt != item_id:
                key = tuple(sorted([(item_id, p["name"]), (tgt, r.get("port") or "")]))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                links.append({"id": None, "a": item_id, "a_port": p["name"], "b": tgt, "b_port": r.get("port"), "kind": "lldp", "remote": None, "label": None, "cable": None})
    # switch port -> computer / any other device of the rack, by its MACs
    for it in rack["items"]:
        e = out_items[it["id"]]
        macs = {n["mac"] for n in e["nics"] if n.get("mac")} | ({_norm_mac(it["asset"]["mac"])} - {None} if it["asset"] and it["asset"].get("mac") else set())
        found = set()
        for m in macs:
            cands = [c for c in where.get(m, []) if c[1] != it["id"]]
            if not cands:
                continue
            _n, sw_id, port, vlan = min(cands)
            for n in e["nics"]:
                if n.get("mac") == m:
                    n["connected"] = {"item_id": sw_id, "port": port, "vlan": vlan}
            if (sw_id, port) not in found:
                found.add((sw_id, port))
                links.append({"id": None, "a": sw_id, "a_port": port, "b": it["id"], "b_port": None, "kind": "mac", "remote": None, "label": None, "cable": None})
    for e in out_items.values():
        for p in e["ports"] or []:
            p.pop("_macs", None)
    return {"items": out_items, "links": links, "at": datetime.utcnow().isoformat() + "Z"}


# ── Operations asked for in Central ──────────────────────────────────────────

_ops_log: List[dict] = []                          # the last results, sent back with the racks so Central can show what happened


def _rack_ref(a: dict) -> int:
    """The rack an operation is about: its id, or - for a rack Central has just asked for and does not know the id of yet - its name."""
    with SessionLocal() as db:
        rid = a.get("rack_id") if a.get("rack_id") is not None else a.get("id")
        if rid is not None and int(rid) > 0 and db.get(Rack, int(rid)):
            return int(rid)
        name = _clean(a.get("rack_name"), 80)
        if name:
            r = db.execute(select(Rack).where(Rack.name == name).order_by(Rack.id.desc())).scalars().first()
            if r:
                return r.id
    raise RackError("rack not found")


def apply_op(op: dict) -> dict:
    """Carries out one rack operation queued in Central ({"op": name, ...args}); the same operations the agent's own page uses.
    Never raises: the outcome goes into the log that Central sees. Returns {"ok": bool, "error": str|None}."""
    name = str((op or {}).get("op") or "")
    err: Optional[str] = None
    try:
        a = op or {}
        if name == "rack_create":
            save_rack(None, a.get("name"), a.get("location"), a.get("units") or 42, a.get("notes"))
        elif name == "rack_update":
            save_rack(int(a["id"]), a.get("name"), a.get("location"), a.get("units") or 42, a.get("notes"))
        elif name == "rack_delete":
            if not delete_rack(int(a["id"])):
                raise RackError("rack not found")
        elif name == "rack_suggested":
            add_suggested(_rack_ref(a))
        elif name == "item_add":
            add_item(_rack_ref(a), int(a["u"]), a.get("height"), a.get("asset_id"), a.get("kind"), a.get("label"), a.get("port_count"))
        elif name == "item_update":
            fields = {k: a[k] for k in ("u", "height", "label", "notes", "port_count", "rack_id") if a.get(k) is not None}
            update_item(int(a["id"]), fields)
        elif name == "item_delete":
            if not delete_item(int(a["id"])):
                raise RackError("item not found")
        elif name == "link_add":
            add_link(_rack_ref(a), int(a["item_a_id"]), a.get("port_a"), a.get("item_b_id"), a.get("port_b"), a.get("remote_text"), a.get("label"), a.get("cable"))
        elif name == "link_delete":
            if not delete_link(int(a["id"])):
                raise RackError("link not found")
        else:
            raise RackError("unknown operation")
    except RackError as e:
        err = str(e)
    except (KeyError, TypeError, ValueError) as e:
        err = f"bad arguments ({type(e).__name__})"
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    _ops_log.append({"at": int(time.time()), "op": name, "ok": err is None, "error": err})
    _pub_cache["data"] = None                               # the next snapshot carries the new placement at once; the live part follows in the background
    del _ops_log[:-12]
    return {"ok": err is None, "error": err}


# ── Copy for the Central relay ───────────────────────────────────────────────

_pub_cache: dict = {"at": 0.0, "data": None}
_pub_task: Optional[asyncio.Task] = None
PUBLIC_TTL = 240.0


async def public_summary() -> dict:
    """What the snapshot carries to Central. It never waits for the devices: the live read (routers, switches - slow or unreachable ones can
    take minutes) happens in the background and the last result is returned; before the first one finishes, and right after Central changed
    something, the racks are sent with their placement only (database, instant)."""
    global _pub_task
    if (_pub_cache["data"] is None or time.time() - _pub_cache["at"] > PUBLIC_TTL) and (_pub_task is None or _pub_task.done()):
        _pub_task = asyncio.create_task(_refresh_public())
    if _pub_cache["data"] is None:
        return await _build_public_summary(with_live=False)
    return _pub_cache["data"]


async def _refresh_public() -> None:
    try:
        _pub_cache["data"] = await _build_public_summary(with_live=True)
        _pub_cache["at"] = time.time()
    except Exception as e:
        print(f"[racks] live refresh error: {e}")
        _pub_cache["at"] = time.time()                     # do not retry in a tight loop


async def _build_public_summary(with_live: bool) -> dict:
    """The racks as Central shows them: placement, ports with what is behind them, links. No credentials, no MAC tables, no addresses of
    hosts outside the inventory beyond what the port shows. A rack whose live read fails is still sent (placement only)."""
    out = []
    for r in list_racks():
        rack = get_rack(r["id"])
        if rack is None:
            continue
        try:
            lv = await live(r["id"]) if with_live else None
        except Exception:
            lv = None
        items = []
        for it in rack["items"]:
            a = it["asset"]
            e = (lv or {}).get("items", {}).get(it["id"], {})
            items.append({
                "id": it["id"], "k": it["kind"], "l": it["label"], "u": it["u"], "h": it["height"], "pc": it["port_count"],
                "a": ({"id": a["id"], "t": a["type"], "r": a["role"], "ip": a["ip"], "md": a["model"], "mf": a["manufacturer"], "on": a["online"]} if a else None),
                "p": [{"n": p["name"], "up": p.get("up"), "sp": p.get("speed"), "v": p.get("vlan"), "c": p.get("comment"),
                       "rx": p.get("rx_mbps"), "tx": p.get("tx_mbps"), "rm": _public_remote(p.get("remote")), "po": _public_poe(p.get("poe"))} for p in (e.get("ports") or [])],
                "pt": e.get("poe_total"),
                "nic": [{"n": n.get("name"), "ip": n.get("ips"), "c": n.get("connected")} for n in e.get("nics", [])],
            })
        out.append({"id": r["id"], "n": r["name"], "loc": r["location"], "u": r["units"], "nt": r["notes"], "items": items,
                    "links": [{"a": l["a"], "ap": l["a_port"], "b": l["b"], "bp": l["b_port"], "rm": l.get("remote"), "lb": l.get("label"), "cb": l.get("cable"), "k": l["kind"]}
                              for l in (lv or {}).get("links", rack["links"])]})
    return {"racks": out, "ops": list(_ops_log)}


def _public_poe(p: Optional[dict]) -> Optional[dict]:
    if not p:
        return None
    return {k: v for k, v in {"m": p.get("mode"), "on": p.get("on"), "st": p.get("status"), "w": p.get("watts"), "off": p.get("off") or None}.items() if v is not None}


def _public_remote(r: Optional[dict]) -> Optional[dict]:
    if not r:
        return None
    return {k: v for k, v in {"k": r.get("kind"), "n": r.get("name"), "ip": r.get("ip"), "p": r.get("port"), "aid": r.get("asset_id"), "c": r.get("count"),
                              "hs": [{"n": h.get("name"), "ip": h.get("ip")} for h in (r.get("hosts") or [])] or None}.items() if v not in (None, "")}
