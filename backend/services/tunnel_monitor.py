"""
VPN tunnel monitoring — WireGuard, IPsec, and EoIP/GRE/VXLAN/IPIP
site-to-site tunnels. The peer-based types (WireGuard/IPsec) get their
up/down status from their own negotiation state (handshake recency /
"established"); the plain-interface types get it from RouterOS's own
"running" flag on the interface entry (confirmed against help.mikrotik.com
and RouterOS's own "eoip-<name> link up/down" log lines).

Detects a tunnel's status change (up<->down) per device+tunnel and reports
it via alert_events — the SAME agent-detected-and-reported mechanism
already used for WAN IP changes (services/edge_discovery.py) and reboots/
failed logins (services/alerts.py), which rides the snapshot's existing
alert_events list into OVH's already-generic alerts_process() (ovh/
notifications.php) — no new event-type allow-list to extend there, only a
new selectable option in the Central UI's alert-rule event-type dropdown.

State persistence pattern (per-tunnel last-known status, self-dedup, never
pruned on a transient miss) copied 1:1 from edge_discovery.py's
_WAN_STATE_PATH/_load_wan_state/_save_wan_state/collect_wan_change_events
— see that module for the original reasoning, reproduced here verbatim.
"""
import asyncio
import json
import os
from datetime import datetime
from typing import List, Optional
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services.device_client import build_client
from services.mikrotik_client import MikrotikClient
from services import activity


_TUNNEL_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "tunnel_state.json")

# Current per-tunnel status from the most recent collect_tunnel_events() run
# — that function already SSHes every device to diff against persisted state,
# so public_summary() just reads this cache instead of re-querying routers a
# second time. Populated after the first successful snapshot cycle; empty
# list before that (mirrors linux_manage.public_summary()'s "nothing yet").
_last_status: List[dict] = []


def _load_state() -> dict:
    if not os.path.exists(_TUNNEL_STATE_PATH):
        return {}
    try:
        with open(_TUNNEL_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_TUNNEL_STATE_PATH), exist_ok=True)
    try:
        with open(_TUNNEL_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[tunnel_monitor] state persist error: {e}")


def _ros_major_version(ros_version) -> Optional[int]:
    """Parses the leading major version number out of a RouterOS version
    string like "7.23.2 (stable)" or "6.49.10 (long-term)" -> 7 / 6. Returns
    None if ros_version is empty or unparseable (device never enriched
    yet, or SNMP-only vendor string leaked through)."""
    if not ros_version:
        return None
    try:
        return int(str(ros_version).split(".")[0].strip())
    except (ValueError, IndexError):
        return None


async def _collect_device_tunnels(device_id: int) -> List[dict]:
    """Returns a flat list of {"tunnel_type","tunnel_name","status",
    "device_id","device_name"} for one device's WireGuard peers, IPsec
    active-peers, and EoIP/GRE/VXLAN/IPIP tunnel interfaces. Non-Mikrotik
    devices (Cisco SB, SNMP-only) have no tunnel concept here and return
    empty, same as firmware.py's handling of non-MikrotikClient devices."""
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
    if not isinstance(client, MikrotikClient):
        return []

    device_name = device.identity or device.name or device.ip
    out: List[dict] = []

    # Verify LIVE rather than trusting the cached Device.ros_version: that
    # field is only ever overwritten when a refresh cycle SUCCEEDS (see
    # refresher.py — a failed query just leaves the previous value in
    # place, by design, so a transient miss is never mistaken for "first
    # seen"). That's the right call for display purposes, but it means a
    # device that was ever misidentified once (e.g. a printer/switch whose
    # SNMP sysDescr got misread as a RouterOS version by a bug already
    # fixed in snmp_client.py) would keep that stale, wrong value forever —
    # nothing here would ever re-query and overwrite it back to empty. A
    # fresh /system/resource call is cheap and self-corrects immediately.
    try:
        resource = await asyncio.wait_for(client.get_resource(), timeout=8)
    except Exception:
        resource = {}
    ros_major = _ros_major_version(resource.get("version") if isinstance(resource, dict) else None)
    if ros_major is None:
        return []

    # WireGuard was only added to RouterOS in v7 — a v6 router (still the
    # majority of older client sites) has no such path at all, so querying
    # it always raises, not because anything is wrong but because the
    # feature structurally cannot exist there. That's "no WireGuard here",
    # the same as an empty peer list — not an error worth a row.
    if ros_major >= 7:
        try:
            wg = await asyncio.wait_for(client.get_wireguard_status(), timeout=8)
        except Exception as e:
            wg = {"peers": [], "error": f"{type(e).__name__}: {e}"}
        for p in wg.get("peers") or []:
            if not isinstance(p, dict):
                continue
            name = p.get("name") or p.get(".id") or p.get("interface") or "peer"
            out.append({"tunnel_type": "wireguard", "tunnel_name": str(name),
                        "status": p.get("status", "down")})
        # A genuine query failure on a device confirmed to support WireGuard
        # (bad creds, unreachable, unexpected RouterOS quirk) is still worth
        # surfacing — same silent-failure bug already fixed once for
        # mikrotik_client.py/DeviceDetail.tsx. Only synthesize this when
        # peers came back empty — if peers succeeded, any error string here
        # is about the (here-unused) interfaces query.
        if wg.get("error") and not wg.get("peers"):
            out.append({"tunnel_type": "wireguard", "tunnel_name": "_query_",
                        "status": "error", "detail": wg["error"]})

    try:
        ipsec = await asyncio.wait_for(client.get_ipsec_status(), timeout=8)
    except Exception as e:
        ipsec = {"peers": [], "error": f"{type(e).__name__}: {e}"}
    for p in ipsec.get("peers") or []:
        if not isinstance(p, dict):
            continue
        name = p.get("remote-address") or p.get(".id") or "peer"
        out.append({"tunnel_type": "ipsec", "tunnel_name": str(name),
                    "status": p.get("status", "down")})
    if ipsec.get("error") and not ipsec.get("peers"):
        out.append({"tunnel_type": "ipsec", "tunnel_name": "_query_",
                    "status": "error", "detail": ipsec["error"]})

    # EoIP/GRE/VXLAN/IPIP site-to-site tunnels (e.g. sanmed's R1<->R2/R3/R4)
    # — plain interface objects with RouterOS's own "running" flag as the
    # up/down signal (see MikrotikClient.get_simple_tunnel_interfaces).
    # Originally out of scope for this module (no peer-negotiation state
    # the way WireGuard/IPsec have), but explicitly requested once the
    # WireGuard/IPsec noise was cleaned up — the interface-level "running"
    # flag turned out to be a perfectly usable signal after all, confirmed
    # by RouterOS's own "eoip-R4 link up" log lines.
    try:
        simple = await asyncio.wait_for(client.get_simple_tunnel_interfaces(), timeout=8)
    except Exception as e:
        simple = {}
        simple_error = f"{type(e).__name__}: {e}"
    else:
        simple_error = None
    for tunnel_type in ("eoip", "gre", "vxlan", "ipip"):
        section = simple.get(tunnel_type) or {}
        interfaces = section.get("interfaces") or []
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name") or iface.get(".id") or "tunnel"
            out.append({"tunnel_type": tunnel_type, "tunnel_name": str(name),
                        "status": iface.get("status", "down")})
        err = section.get("error") or simple_error
        if err and not interfaces:
            out.append({"tunnel_type": tunnel_type, "tunnel_name": "_query_",
                        "status": "error", "detail": err})

    for t in out:
        t["device_id"] = device.id
        t["device_name"] = device_name
    return out


async def collect_tunnel_events() -> List[dict]:
    """Walk all devices with credentials, compare each tunnel's current
    status against the last value persisted to disk, and emit
    tunnel_down/tunnel_up events for any transition. Self-dedupes (new
    status saved immediately after comparison, so a change is reported
    only once) and deliberately never prunes a tunnel's entry just because
    this run's scan of that device failed or the device was offline —
    same reasoning as edge_discovery.collect_wan_change_events: a
    transient miss must not be treated as "first seen" next time it
    succeeds."""
    with SessionLocal() as db:
        devices = db.execute(
            select(Device).where(Device.credential_id.is_not(None))
        ).scalars().all()
        # Tunnels only make sense on an actual Mikrotik router. build_client()
        # in device_client.py defaults ANY vendor other than "cisco-sb" to
        # MikrotikClient — including "generic-snmp" (scanner.py's label for
        # printers/iDRACs/switches identified only via SNMP sysDescr), since
        # that client's SNMP fallback is genuinely useful for other features.
        # isinstance(client, MikrotikClient) below therefore does NOT mean
        # "is a real router" — without this vendor check, every credentialed
        # printer/iDRAC got queried for WireGuard/IPsec too, which used to
        # fail silently and, once query errors started being surfaced,
        # showed up as a wall of meaningless "_query_: error" rows.
        ids = [d.id for d in devices if (d.vendor or "mikrotik").lower() == "mikrotik"]

    sem = asyncio.Semaphore(5)

    async def _bounded(did):
        async with sem:
            try:
                return await _collect_device_tunnels(did)
            except Exception:
                return []

    results = await asyncio.gather(*[_bounded(i) for i in ids])
    current = [t for r in results for t in r]

    global _last_status
    _last_status = current

    state = _load_state()
    events: List[dict] = []
    for t in current:
        key = f"{t['device_id']}:{t['tunnel_type']}:{t['tunnel_name']}"
        prev_status = state.get(key)
        # Only alert on a real up<->down transition — an "error" (query
        # failed) is not a known tunnel state, so treating its appearance/
        # disappearance as if it were "up"/"down" would fire a misleading
        # tunnel_up/tunnel_down alert with no actual state change behind it.
        if prev_status in ("up", "down") and t["status"] in ("up", "down") and prev_status != t["status"]:
            event_type = "tunnel_down" if t["status"] == "down" else "tunnel_up"
            events.append({
                "type": event_type,
                "device_id": t["device_id"],
                "device_name": t["device_name"],
                "tunnel_type": t["tunnel_type"],
                "tunnel_name": t["tunnel_name"],
                "count": 1,
                "detected_at": datetime.utcnow().isoformat(),
            })
            try:
                activity.record(
                    event_type, device_name=t["device_name"],
                    tunnel_type=t["tunnel_type"], tunnel_name=t["tunnel_name"],
                )
            except Exception as e:
                print(f"[tunnel_monitor] activity record error: {e}")
        state[key] = t["status"]

    _save_state(state)
    return events


def public_summary() -> List[dict]:
    """Redacted view for the snapshot's plaintext envelope — same treatment
    as linux_manage.public_summary()/supply_chain.public_summary(): just the
    current up/down status per tunnel, nothing an attacker could use beyond
    what "Tunele" already shows locally on the agent itself."""
    return [{
        "device_name": t["device_name"],
        "tunnel_type": t["tunnel_type"],
        "tunnel_name": t["tunnel_name"],
        "status": t["status"],
        "detail": t.get("detail"),
    } for t in _last_status]
