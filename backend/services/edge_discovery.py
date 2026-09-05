"""
Edge IP discovery — walks devices with credentials, pulls their /ip/address list,
returns entries with a public (non-RFC1918/CGNAT/loopback/link-local) address.

Result feeds unencrypted envelope metadata so the OVH central can ping them
directly without needing E2E key.

Handles multi-WAN — one device can produce multiple entries.
"""
import asyncio
import ipaddress
import json
import os
import time
from datetime import datetime
from typing import List
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.device_client import build_client
from services import activity


# Cache full scan for SCAN_TTL_SEC — same reason as alerts.py: uplink runs
# every 2 min but there's no reason to poll every device that often.
SCAN_TTL_SEC = int(os.environ.get("MIKROMANAGER_EDGE_SCAN_TTL", "3600"))
_scan_cache = {"data": [], "ts": 0.0}


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

    # "running" state straight from the router's own /interface list — same
    # field/normalization the tunnel-status code already relies on
    # (get_simple_tunnel_interfaces()). Read locally over the LAN, so this
    # needs no inbound WAN firewall rule and isn't affected by whether the
    # router allows any external management access at all (unlike OVH/any
    # external prober trying to reach the WAN IP from outside).
    iface_running = {}
    try:
        ifaces = await asyncio.wait_for(client.get_interfaces(), timeout=8)
        for i in ifaces or []:
            name = i.get("name") or i.get("actual-interface") or ""
            if not name:
                continue
            disabled = str(i.get("disabled", "false")).lower() in ("true", "yes")
            running = str(i.get("running", "false")).lower() in ("true", "yes")
            iface_running[str(name)] = running and not disabled
    except Exception:
        pass  # missing running-state just means "unknown" below, not fatal

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
            "running": iface_running.get(str(iface)),  # None = couldn't be determined
        })
    return out


async def collect_public_ips() -> List[dict]:
    """Walk all devices with credentials, return flat list of public IPs.
    Cached for SCAN_TTL_SEC to prevent flooding device logs."""
    now = time.time()
    if (now - _scan_cache["ts"]) < SCAN_TTL_SEC:
        return _scan_cache["data"]

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
    _scan_cache["data"] = flat
    _scan_cache["ts"] = now
    return flat


# ── WAN IP change detection ──────────────────────────────────────────────
# Last-known public IP per (device, interface), persisted to disk (not just
# in memory) so a routine agent restart never looks like a WAN change — an
# in-memory-only "last known" would reset to empty on every restart and
# falsely report every device's current IP as "changed" right after.
_WAN_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wan_state.json")


def _load_wan_state() -> dict:
    if not os.path.exists(_WAN_STATE_PATH):
        return {}
    try:
        with open(_WAN_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_wan_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_WAN_STATE_PATH), exist_ok=True)
    try:
        with open(_WAN_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[edge_discovery] wan state persist error: {e}")


async def collect_wan_change_events() -> List[dict]:
    """Compare each device's current public IP(s) — per (device, interface),
    multi-WAN safe — against the last value persisted to disk. Reuses
    collect_public_ips()'s own TTL cache/scan, so this adds no extra device
    polling. Self-dedupes: the new value is saved immediately after each
    comparison, so a change is only reported once (the run where it's first
    observed), not on every subsequent uplink cycle."""
    current = await collect_public_ips()
    state = _load_wan_state()
    events: List[dict] = []
    for entry in current:
        key = f"{entry['device_id']}:{entry['iface']}"
        prev_ip = state.get(key)
        if prev_ip is not None and prev_ip != entry["ip"]:
            events.append({
                "type": "wan_ip_changed",
                "device_id": entry["device_id"],
                "device_name": entry["device_name"],
                "iface": entry["iface"],
                "old_ip": prev_ip,
                "new_ip": entry["ip"],
                "count": 1,
                "detected_at": datetime.utcnow().isoformat(),
            })
            try:
                activity.record(
                    "wan_ip_changed", device_name=entry["device_name"],
                    old_ip=prev_ip, new_ip=entry["ip"], iface=entry["iface"],
                )
            except Exception as e:
                print(f"[edge_discovery] activity record error: {e}")
        state[key] = entry["ip"]
    # Deliberately not pruning keys whose device disappeared this run (e.g.
    # a transient scan failure) — keep the last known value so a later,
    # successful scan is compared against it, not treated as "first seen".
    _save_wan_state(state)
    return events


# ── WAN link up/down detection (local, no external probing needed) ──────
# Separate state/concern from the IP-change tracking above: this reads the
# WAN interface's own "running" flag straight from the router over the LAN
# (see _scan_device()) — the same signal RouterOS itself uses, and the same
# approach already used for tunnel status (get_simple_tunnel_interfaces()).
# Deliberately NOT inferring "down" just because an entry is momentarily
# absent from a scan (that's equally explained by a transient per-device
# scan failure, e.g. a timeout) — only an EXPLICIT running=false from a
# device that answered at all counts, to avoid false positives.
#
# This is the actual fix for sites whose router firewall correctly blocks
# all inbound WAN traffic by default (confirmed live: several WAN IPs kept
# timing out on every TCP port tried from OVH) — checking locally, over the
# LAN the agent is already on, needs no firewall hole punched on any router
# and isn't affected by NAT/CGNAT/ISP filtering at all.
_WAN_LINK_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wan_link_state.json")


def _load_wan_link_state() -> dict:
    if not os.path.exists(_WAN_LINK_STATE_PATH):
        return {}
    try:
        with open(_WAN_LINK_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_wan_link_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_WAN_LINK_STATE_PATH), exist_ok=True)
    try:
        with open(_WAN_LINK_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[edge_discovery] wan link state persist error: {e}")


async def collect_wan_link_events() -> List[dict]:
    """Compare each WAN interface's current running-state against the last
    persisted value, emitting wan_down/wan_up on an actual transition.
    Reuses collect_public_ips()'s own TTL cache, so this adds no extra
    device polling beyond what collect_wan_change_events() already does."""
    current = await collect_public_ips()
    state = _load_wan_link_state()
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()

    for entry in current:
        running = entry.get("running")
        if running is None:
            continue  # couldn't be determined this poll — leave prior state untouched
        key = f"{entry['device_id']}:{entry['iface']}"
        current_status = "up" if running else "down"
        prev_status = state.get(key)
        if prev_status is not None and prev_status != current_status:
            event_type = "wan_down" if current_status == "down" else "wan_up"
            events.append({
                "type": event_type,
                "device_id": entry["device_id"],
                "device_name": entry["device_name"],
                "iface": entry["iface"],
                "count": 1,
                "detected_at": now_iso,
            })
            try:
                activity.record(event_type, device_name=entry["device_name"], iface=entry["iface"])
            except Exception as e:
                print(f"[edge_discovery] activity record error: {e}")
        state[key] = current_status

    _save_wan_link_state(state)
    return events
