"""
Topology discovery — builds device-to-device link graph from:

  1. /ip/neighbor — LLDP/CDP/MNDP discovered neighbors. Gives us:
       - neighbor IP (used to match to known Device row)
       - local interface (port on the querying device)
       - interface-name (port on the remote device, if LLDP/CDP)
  2. /interface/eoip|gre|vxlan|ipip — L2 tunnels with remote-address
     that we can resolve to a known device.

Links are stored canonically (device_a_id < device_b_id) so each edge
appears once even if both sides report each other.
"""
from typing import Optional
from datetime import datetime
from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from models.database import SessionLocal, Device, Credential, DeviceLink
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient


def _canon(a: int, b: int) -> tuple:
    """Return (smaller, larger, swapped_flag)."""
    if a < b:
        return a, b, False
    return b, a, True


def _build_ip_map() -> dict:
    """ip -> device_id, for fast lookup during discovery."""
    with SessionLocal() as db:
        return {ip: did for did, ip in db.execute(select(Device.id, Device.ip)).all()}


def _upsert_link(db: Session, dev_a: int, dev_b: int,
                 iface_a: Optional[str], iface_b: Optional[str],
                 link_type: str) -> None:
    """Insert or update a link. Pair is canonicalised. New per-side interface
    info overwrites only if it's not already set (so subsequent passes can
    fill in the other end)."""
    if dev_a == dev_b:
        return
    a, b, swapped = _canon(dev_a, dev_b)
    if swapped:
        iface_a, iface_b = iface_b, iface_a

    existing = db.execute(
        select(DeviceLink)
        .where(DeviceLink.device_a_id == a)
        .where(DeviceLink.device_b_id == b)
        .where(DeviceLink.link_type == link_type)
    ).scalar_one_or_none()

    if existing:
        if iface_a and not existing.interface_a:
            existing.interface_a = iface_a
        if iface_b and not existing.interface_b:
            existing.interface_b = iface_b
        # Overwrite if we have a definite value (helpful when port renamed)
        if iface_a:
            existing.interface_a = iface_a
        if iface_b:
            existing.interface_b = iface_b
        existing.last_seen = datetime.utcnow()
    else:
        db.add(DeviceLink(
            device_a_id=a,
            device_b_id=b,
            interface_a=iface_a,
            interface_b=iface_b,
            link_type=link_type,
            last_seen=datetime.utcnow(),
        ))


async def discover_for_device(device_id: int, ip_map: Optional[dict] = None) -> int:
    """Discover topology edges originating from one device.
    Returns count of links inserted/updated."""
    if ip_map is None:
        ip_map = _build_ip_map()

    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return 0
        device, cred = row
        password = decrypt(cred.password_enc)
        community = decrypt(cred.snmp_community_enc) if cred.snmp_community_enc else None

    client = MikrotikClient(
        device.ip, cred.username, password,
        api_port=device.api_port, web_port=device.web_port,
        snmp_community=community, snmp_port=device.snmp_port or 161,
    )

    inserts = 0

    # ── 1. LLDP/CDP/MNDP neighbors ────────────────────────────────────────
    try:
        neighbors = await client.get_neighbors()
    except Exception:
        neighbors = []

    with SessionLocal() as db:
        for n in neighbors:
            remote_ip = n.get("address") or n.get("address4") or n.get("ipv4-address")
            if not remote_ip or remote_ip not in ip_map:
                continue
            remote_id = ip_map[remote_ip]
            if remote_id == device_id:
                continue

            # Determine link type by available fields
            link_type = "mndp"
            if n.get("system-description") or n.get("system-caps"):
                link_type = "lldp"
            elif n.get("platform") and "cisco" in str(n.get("platform", "")).lower():
                link_type = "cdp"

            iface_local = n.get("interface") or n.get("interfaces")
            iface_remote = n.get("interface-name")  # LLDP/CDP only

            _upsert_link(db, device_id, remote_id,
                         iface_a=iface_local, iface_b=iface_remote,
                         link_type=link_type)
            inserts += 1
        db.commit()

    # ── 2. L2 tunnels (EOIP/GRE/VXLAN/IPIP) ───────────────────────────────
    try:
        tunnels = await client.get_vpn_tunnels()
    except Exception:
        tunnels = {}

    with SessionLocal() as db:
        for tun_type, entries in tunnels.items():
            for t in entries or []:
                remote_ip = t.get("remote-address") or t.get("remote-ip")
                local_name = t.get("name")
                if not remote_ip or remote_ip not in ip_map:
                    continue
                remote_id = ip_map[remote_ip]
                if remote_id == device_id:
                    continue
                _upsert_link(db, device_id, remote_id,
                             iface_a=local_name, iface_b=None,
                             link_type=tun_type)
                inserts += 1
        db.commit()

    return inserts


async def discover_all() -> dict:
    """Re-discover topology for every device with credentials.
    Returns summary {checked, links_total}."""
    ip_map = _build_ip_map()
    with SessionLocal() as db:
        ids = [d.id for d in db.execute(
            select(Device).where(Device.credential_id.is_not(None))
        ).scalars().all()]

    checked = 0
    for did in ids:
        try:
            await discover_for_device(did, ip_map)
            checked += 1
        except Exception:
            pass

    with SessionLocal() as db:
        total = db.execute(select(DeviceLink)).scalars().all()
        return {"devices_checked": checked, "links_total": len(total)}


def get_topology() -> dict:
    """Return {nodes:[...], links:[...]} for the frontend map.
    Nodes are all devices. Links include resolved port names."""
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        links = db.execute(select(DeviceLink)).scalars().all()

        nodes = [{
            "id": d.id,
            "ip": d.ip,
            "name": d.name,
            "identity": d.identity,
            "model": d.model,
            "online": d.online,
            "x_pos": d.x_pos,
            "y_pos": d.y_pos,
            "has_api": d.has_api,
            "has_web": d.has_web,
            "has_ssh": d.has_ssh,
            "has_snmp": d.has_snmp,
        } for d in devices]

        edges = [{
            "id": l.id,
            "a": l.device_a_id,
            "b": l.device_b_id,
            "iface_a": l.interface_a,
            "iface_b": l.interface_b,
            "type": l.link_type,
            "last_seen": l.last_seen.isoformat() if l.last_seen else None,
        } for l in links]

    return {"nodes": nodes, "links": edges}
