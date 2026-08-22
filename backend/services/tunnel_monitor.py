"""
VPN tunnel monitoring — WireGuard + IPsec (v1 scope; other tunnel types
like EoIP/GRE/VXLAN/IPIP are already visible read-only in the "Tunele" tab
via MikrotikClient.get_vpn_tunnels() but have no up/down concept worth
alerting on the way a peer-based VPN does).

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
from typing import List
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


async def _collect_device_tunnels(device_id: int) -> List[dict]:
    """Returns a flat list of {"tunnel_type","tunnel_name","status",
    "device_id","device_name"} for one device's WireGuard peers + IPsec
    active-peers. Non-Mikrotik devices (Cisco SB, SNMP-only) have no
    tunnel concept here and return empty, same as firmware.py's handling
    of non-MikrotikClient devices."""
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

    try:
        wg = await asyncio.wait_for(client.get_wireguard_status(), timeout=8)
        for p in wg.get("peers") or []:
            if not isinstance(p, dict):
                continue
            name = p.get("name") or p.get(".id") or p.get("interface") or "peer"
            out.append({"tunnel_type": "wireguard", "tunnel_name": str(name),
                        "status": p.get("status", "down")})
    except Exception:
        pass

    try:
        ipsec = await asyncio.wait_for(client.get_ipsec_status(), timeout=8)
        for p in ipsec.get("peers") or []:
            if not isinstance(p, dict):
                continue
            name = p.get("remote-address") or p.get(".id") or "peer"
            out.append({"tunnel_type": "ipsec", "tunnel_name": str(name),
                        "status": p.get("status", "down")})
    except Exception:
        pass

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
        ids = [d.id for d in db.execute(
            select(Device).where(Device.credential_id.is_not(None))
        ).scalars().all()]

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
        if prev_status is not None and prev_status != t["status"]:
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
    } for t in _last_status]
