"""
Edge IP discovery — walks devices with credentials, pulls their /ip/address list,
returns entries with a public (non-RFC1918/CGNAT/loopback/link-local) address.

Result feeds unencrypted envelope metadata so the OVH central can ping them
directly without needing E2E key.

Handles multi-WAN — one device can produce multiple entries.
"""
import asyncio
import ipaddress
from typing import List
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.device_client import build_client


import re

# Interface names that are tunnels / VPN — their addresses are not real WAN
# and should not be pinged from the central server.
TUNNEL_IFACE_RE = re.compile(
    r"^("
    r"eoip|eoipv6|gre|gretap|ipip|ipipv6|"
    r"pptp-|l2tp-|ovpn-|sstp-|"
    r"wireguard|wg\d|"
    r"vxlan|vlan\d+"  # vlans are usually LAN, though some ISPs use them for WAN
    r")",
    re.IGNORECASE,
)


def _is_tunnel_iface(iface: str) -> bool:
    return bool(iface and TUNNEL_IFACE_RE.match(iface))


def _is_public(ip_str: str) -> bool:
    """True only for globally routable IPv4/IPv6 addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_private:
        return False  # 10/8, 172.16/12, 192.168/16, fc00::/7
    # CGNAT
    if isinstance(ip, ipaddress.IPv4Address) and ipaddress.IPv4Address("100.64.0.0") <= ip <= ipaddress.IPv4Address("100.127.255.255"):
        return False
    if ip.is_reserved:
        return False
    return True


def _strip_prefix(addr: str) -> str:
    """Turn '203.0.113.5/24' or '203.0.113.5' into '203.0.113.5'."""
    return addr.split("/", 1)[0].strip()


async def _scan_device(device_id: int) -> List[dict]:
    """Return one entry per public IP found on this device (multi-WAN safe)."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return []
        device, cred = row

    client = build_client(device, cred)
    try:
        addrs = await asyncio.wait_for(client.get_ip_addresses(), timeout=8)
    except Exception:
        return []

    out = []
    seen = set()
    for a in addrs or []:
        # Field names vary between REST/API-binary — try both
        raw = a.get("address") or a.get(".id") or ""
        iface = a.get("interface") or a.get("actual-interface") or ""
        ip = _strip_prefix(str(raw))
        if not ip or ip in seen:
            continue
        if not _is_public(ip):
            continue
        if _is_tunnel_iface(str(iface)):
            continue
        seen.add(ip)
        out.append({
            "ip": ip,
            "iface": str(iface),
            "device_id": device.id,
            "device_name": device.identity or device.name or device.ip,
        })
    return out


async def collect_public_ips() -> List[dict]:
    """Walk all devices with credentials, return flat list of public IPs."""
    with SessionLocal() as db:
        ids = [d.id for d in db.execute(
            select(Device).where(Device.credential_id.is_not(None))
        ).scalars().all()]

    sem = asyncio.Semaphore(5)

    async def _bounded(did):
        async with sem:
            try:
                return await _scan_device(did)
            except Exception:
                return []

    results = await asyncio.gather(*[_bounded(i) for i in ids])
    flat = []
    for r in results:
        flat.extend(r)
    return flat
