"""
Agent-side reachability self-check for "Monitoring urządzeń brzegowych"
(edge devices) — reported directly: OVH's shared hosting has no raw ICMP
socket capability (confirmed: "ping: socket: Address family not supported
by protocol") and its own routing quirks to some destination networks
(errno 101 "Network is unreachable"), so OVH's own active probe
(ovh/notifications.php's edge_check_ip()) can show a client's WAN address
as "offline" even when it's genuinely reachable — just not from OVH's
specific network path.

This module lets the AGENT do the check instead, using its own normal OS
network stack (no such restriction), and report the result to OVH in its
regular snapshot. OVH only ever tells an agent about its OWN tenant's
edge_devices rows for the *check_all()* path below (both 'auto' and
'manual' sources — see ovh/ingest.php's "edge_check_targets" command). For
a multi-site tenant (e.g. several branch routers connected via VPN tunnels
under one agent), this is a genuinely different, real network path than
wherever the agent process itself runs — for a single-site tenant it's a
weaker signal (checking your own WAN from behind the same router can hit
NAT hairpinning), but still catches "the whole internet connection is
down", and never worse than OVH's own broken-ICMP result.

OVH's own active probe (edge_check_due()) is NOT being replaced — this is
purely additive. Both write into the exact same debounce/state-machine
(edge_apply_check_result() in ovh/notifications.php), so the freshest
report (typically this one, arriving every ~2 min vs OVH's own 900s
default interval) naturally wins.

check_verify_targets() below is the one deliberately cross-tenant piece:
before OVH lets any source (its own probe OR this same tenant's own
check_all() above) declare a device offline, it asks 1-2 OTHER tenants'
agents to independently ping/TCP-check that SAME address first — this is
what catches the false-positive case from an OVH-side connectivity
incident, where the thing actually unreachable was OVH's network (or the
reporting agent itself), not the client's real WAN. This still does not
reintroduce agent-to-agent communication: the target IP/port travels
OVH → this agent via the same signed command channel as everything else,
tagged only with an opaque verification_id — this agent never learns
which tenant owns the address, and the result goes back to OVH only, never
to the other agent directly.
"""
import asyncio
import platform
import socket
import subprocess
from datetime import datetime
from typing import Optional

# The tenant's current (ip, check_port) list, as told by OVH via the
# "edge_check_targets" command — resent (and overwritten wholesale) every
# heartbeat, not drained/merged, so an operator's edit in Central (add/
# remove/disable a device, change its port) takes effect within one cycle.
_targets: list = []


def set_targets(targets: list) -> None:
    global _targets
    _targets = [t for t in (targets or []) if isinstance(t, dict) and t.get("ip")]


# Cross-tenant verification requests — addresses owned by OTHER tenants
# that OVH picked this agent (at random) to independently check, as told
# by the "edge_verify_targets" command. Kept in a separate list from
# _targets above: these must never be merged into this tenant's own
# edge-device checks/results, only reported back tagged with the opaque
# verification_id OVH gave them. Same "resent wholesale every heartbeat"
# shape as _targets.
_verify_targets: list = []


def set_verify_targets(targets: list) -> None:
    global _verify_targets
    _verify_targets = [
        t for t in (targets or [])
        if isinstance(t, dict) and t.get("ip") and t.get("verification_id")
    ]


def _ping_sync(ip: str, timeout: int = 3) -> tuple:
    """Real OS ping via subprocess — the exact same command-per-platform
    split as ovh/notifications.php's edge_check_ip() ICMP branch, just
    without that environment's broken raw-socket limitation (this is a
    normal OS process with normal network permissions)."""
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except Exception as e:
        return False, f"ping {ip} could not run: {type(e).__name__}: {e}"
    if result.returncode == 0:
        return True, "ping OK"
    return False, f"ping {ip} failed (exit code {result.returncode})"


def _tcp_check_sync(ip: str, port: int, timeout: int = 3) -> tuple:
    """socket connect — mirrors ovh/notifications.php's edge_tcp_check()."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, f"TCP {ip}:{port} connected"
    except Exception as e:
        return False, f"TCP {ip}:{port} failed: {type(e).__name__}: {e}"


async def _check_one(loop, ip: str, port: Optional[int]) -> tuple:
    """Shared by check_all()/check_verify_targets() — same check_port
    semantics as the existing Central UI/OVH check: a set check_port means
    TCP-only on that port; unset means ICMP. Blocking subprocess/socket
    calls run in the default executor so one slow/unreachable target never
    blocks the uplink snapshot cycle."""
    try:
        if port:
            ok, detail = await loop.run_in_executor(None, _tcp_check_sync, ip, port, 3)
            method = "tcp"
        else:
            ok, detail = await loop.run_in_executor(None, _ping_sync, ip, 3)
            method = "icmp"
    except Exception as e:
        ok, detail, method = False, f"check error: {type(e).__name__}: {e}", "error"
    return ok, method, detail


def _coerce_port(raw) -> Optional[int]:
    try:
        return int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


async def check_all() -> list:
    """Checks every target OVH told us about for our own tenant."""
    targets = list(_targets)
    if not targets:
        return []

    loop = asyncio.get_event_loop()
    results = []
    for t in targets:
        ip = str(t["ip"])
        port = _coerce_port(t.get("check_port"))
        ok, method, detail = await _check_one(loop, ip, port)
        results.append({
            "ip": ip, "ok": ok, "method": method, "detail": detail,
            "checked_at": datetime.utcnow().isoformat(),
        })
    return results


async def check_verify_targets() -> list:
    """Checks every cross-tenant verification target OVH asked this agent
    to look at (see module docstring) and reports back tagged with the
    opaque verification_id — never merged into this tenant's own
    edge-device state, this agent has no idea whose address it just
    checked beyond the bare IP/port."""
    targets = list(_verify_targets)
    if not targets:
        return []

    loop = asyncio.get_event_loop()
    results = []
    for t in targets:
        ip = str(t["ip"])
        port = _coerce_port(t.get("check_port"))
        ok, method, detail = await _check_one(loop, ip, port)
        results.append({
            "verification_id": t["verification_id"], "ip": ip,
            "ok": ok, "method": method, "detail": detail,
            "checked_at": datetime.utcnow().isoformat(),
        })
    return results
