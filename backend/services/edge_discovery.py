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
from typing import List, Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.device_client import build_client
from services import activity


# Cache full scan for SCAN_TTL_SEC — same reason as alerts.py: uplink runs
# every 2 min but there's no reason to poll every device that often.
SCAN_TTL_SEC = int(os.environ.get("MIKROMANAGER_EDGE_SCAN_TTL", "3600"))
# "data" = flat public-IP list (collect_public_ips()'s own contract, used
# for OVH edge-device sync + wan_ip_changed — must stay public-only, OVH
# can't ping a private address). "wan_iface_data" = one entry per device
# for its WAN-facing interface's running-state, regardless of whether that
# interface's own address is public or private (see _find_wan_iface below)
# — used only by collect_wan_link_events()/get_wan_link_status().
_scan_cache = {"data": [], "wan_iface_data": [], "ts": 0.0}


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


def _find_wan_ifaces_from_routes(routes: list, addrs: list) -> List[str]:
    """Identify EVERY WAN-facing interface via each active default route's
    gateway, matched against which local interface's own subnet contains
    that gateway IP. Returns a deduplicated list, not just the first match
    — a router genuinely can have more than one active default route at
    once (failover/load-balancing/PCC setups, confirmed live: mcprojekt's
    R1 has two separate WAN links) — returning only one would arbitrarily
    pick whichever route happened to sort first, potentially the wrong
    one, and never check the other link at all.

    This is deliberately NOT based on which interface holds a public
    address — confirmed live (mcprojekt): a router can have NO public
    address anywhere at all (double-NAT / ISP CGNAT, e.g. ether1 holding
    only 192.168.0.2, an address assigned by the ISP's own upstream box)
    while still having a perfectly well-defined WAN-facing interface whose
    up/down state is exactly as meaningful to monitor as a directly-public
    one. Subnet-matching against the gateway works regardless of whether
    that subnet happens to be private, unlike public-IP-based discovery
    (still used, unchanged, for collect_public_ips()'s different purpose:
    finding an address OVH could actually ping from outside)."""
    gateways = []
    for r in routes or []:
        dst = str(r.get("dst-address") or "")
        active = str(r.get("active", "false")).lower() in ("true", "yes")
        if dst.startswith("0.0.0.0/0") and active:
            gw = r.get("gateway")
            if gw:
                gateways.append(str(gw).split("%")[0].strip())  # strip any %iface suffix

    gw_ips = []
    for gw in gateways:
        try:
            gw_ips.append(ipaddress.ip_address(gw))
        except ValueError:
            continue

    found = []
    seen = set()
    for a in addrs or []:
        raw = a.get("address") or ""
        iface = a.get("interface") or a.get("actual-interface") or ""
        if not raw or not iface or str(iface) in seen:
            continue
        try:
            net = ipaddress.ip_interface(str(raw)).network
        except ValueError:
            continue
        if any(gw_ip in net for gw_ip in gw_ips):
            seen.add(str(iface))
            found.append(str(iface))
    return found


async def _scan_device(device_id: int) -> dict:
    """Returns {"public_ips": [...], "wan_iface": {...}|None} for one
    device — public_ips is the existing contract (multi-WAN safe, one
    entry per public address, feeds collect_public_ips()); wan_ifaces is a
    list with one entry PER interface carrying an active default route
    (multi-WAN safe — a device can have more than one), each with its own
    running-state, regardless of whether its address is public or private
    (see _find_wan_ifaces_from_routes above)."""
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .join(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return {"public_ips": [], "wan_ifaces": []}
        device, cred = row

    client = build_client(device, cred)
    try:
        addrs = await asyncio.wait_for(client.get_ip_addresses(), timeout=8)
    except Exception:
        return {"public_ips": [], "wan_ifaces": []}

    device_name = device.identity or device.name or device.ip

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
            # Only trust an EXPLICIT "running" value — some API paths/
            # interface types may omit the field entirely rather than
            # returning an explicit false, and defaulting a missing field
            # to "not running" would silently misreport a healthy
            # interface as down. Reported live: WAN links showing "down"
            # that were confirmed actually up.
            if "running" not in i:
                continue
            disabled = str(i.get("disabled", "false")).lower() in ("true", "yes")
            running = str(i.get("running", "false")).lower() in ("true", "yes")
            iface_running[str(name)] = running and not disabled
    except Exception:
        pass  # missing running-state just means "unknown" below, not fatal

    public_ips = []
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
        public_ips.append({
            "ip": ip,
            "iface": str(iface),
            "device_id": device.id,
            "device_name": device_name,
            "running": iface_running.get(str(iface)),  # None = couldn't be determined
        })

    # Prefer RouterOS's own named "WAN" interface-list membership when the
    # router defines one — confirmed live (a real router's Winbox
    # Interfaces > Interface List view showing ether1+ether8 under "WAN")
    # that this is a direct, authoritative signal (the operator's own
    # stated intent) rather than an inference — more reliable than
    # route-matching for complex setups (PCC/mangle-based routing, VRFs)
    # where the "active default route" heuristic can be ambiguous or
    # simply wrong. Only fall back to route-based detection for routers
    # that don't define a WAN list at all (many minimal/CLI-only setups
    # won't).
    wan_iface_names = []
    try:
        members = await asyncio.wait_for(client.get_interface_list_members(), timeout=8)
        wan_iface_names = [
            str(m.get("interface"))
            for m in (members or [])
            if isinstance(m, dict) and str(m.get("list", "")).strip().lower() == "wan" and m.get("interface")
        ]
    except Exception:
        pass

    if not wan_iface_names:
        try:
            routes = await asyncio.wait_for(client.get_routes(), timeout=8)
            wan_iface_names = _find_wan_ifaces_from_routes(routes, addrs)
        except Exception:
            pass

    wan_ifaces = []
    seen_wan = set()
    for wan_iface_name in wan_iface_names:
        if wan_iface_name in seen_wan or _is_tunnel_iface(wan_iface_name):
            continue
        seen_wan.add(wan_iface_name)
        running = iface_running.get(wan_iface_name)
        if running is not None:
            wan_ifaces.append({
                "device_id": device.id,
                "device_name": device_name,
                "iface": wan_iface_name,
                "running": running,
            })

    return {"public_ips": public_ips, "wan_ifaces": wan_ifaces}


async def _run_full_scan() -> None:
    """Shared by collect_public_ips()/get_wan_link_status() — one pass over
    every device populates BOTH cache entries, so a device is never queried
    twice within the same SCAN_TTL_SEC window just because two different
    features each want a different slice of the same scan."""
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
                return {"public_ips": [], "wan_ifaces": []}

    results = await asyncio.gather(*[_bounded(i) for i in ids])
    public_flat = []
    wan_iface_flat = []
    for r in results:
        public_flat.extend(r.get("public_ips") or [])
        wan_iface_flat.extend(r.get("wan_ifaces") or [])
    _scan_cache["data"] = public_flat
    _scan_cache["wan_iface_data"] = wan_iface_flat
    _scan_cache["ts"] = time.time()


async def collect_public_ips() -> List[dict]:
    """Walk all devices with credentials, return flat list of public IPs.
    Cached for SCAN_TTL_SEC to prevent flooding device logs."""
    now = time.time()
    if (now - _scan_cache["ts"]) < SCAN_TTL_SEC:
        return _scan_cache["data"]
    await _run_full_scan()
    return _scan_cache["data"]


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


async def _get_wan_iface_data() -> List[dict]:
    """Ensures the shared scan is fresh (same TTL/cache as
    collect_public_ips(), see _run_full_scan()) then returns the
    WAN-interface slice — one entry per device's WAN-facing interface,
    public or private address alike (see _find_wan_iface_from_routes)."""
    now = time.time()
    if (now - _scan_cache["ts"]) >= SCAN_TTL_SEC:
        await _run_full_scan()
    return _scan_cache["wan_iface_data"]


async def collect_wan_link_events() -> List[dict]:
    """Compare each WAN interface's current running-state against the last
    persisted value, emitting wan_down/wan_up on an actual transition.
    Reuses the same shared scan as collect_public_ips() (_run_full_scan()),
    so this adds no extra device polling beyond what
    collect_wan_change_events() already does."""
    current = await _get_wan_iface_data()
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


def get_wan_link_status() -> dict:
    """Per-device latest known WAN link status, straight from the shared
    scan's WAN-interface slice (see _find_wan_iface_from_routes — works
    whether that interface's own address is public or private, e.g. behind
    an ISP's double-NAT) — used by devices.py to show a live up/down badge
    on the Devices page, separate from collect_wan_link_events()'s own
    transition-only alert_events. Reads whatever the background scan last
    found — does not itself trigger a fresh scan (this is called from a
    plain, synchronous API request handler).

    A device absent from the returned dict simply has no known WAN
    interface yet (never scanned, no active default route found, or
    running-state couldn't be determined) — distinct from "down", so
    callers must not treat a missing key as "down" and must know to render
    nothing rather than a false badge."""
    result: dict = {}
    for entry in _scan_cache["wan_iface_data"]:
        running = entry.get("running")
        if running is None:
            continue
        status = "up" if running else "down"
        did = entry["device_id"]
        prev = result.get(did)
        if prev is None or (prev["status"] == "up" and status == "down"):
            result[did] = {"status": status, "iface": entry["iface"]}
    return result
