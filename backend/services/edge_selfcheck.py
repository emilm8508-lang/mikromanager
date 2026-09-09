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
regular snapshot. Explicitly NOT cross-tenant: OVH only ever tells an
agent about its OWN tenant's edge_devices rows (both 'auto' and 'manual'
sources — see ovh/ingest.php's "edge_check_targets" command). For a
multi-site tenant (e.g. several branch routers connected via VPN tunnels
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


async def check_all() -> list:
    """Checks every target OVH told us about for our own tenant. Same
    check_port semantics as the existing Central UI/OVH check: a set
    check_port means TCP-only on that port; unset means ICMP — an operator
    who already configured ports for their devices sees no change in
    meaning, just a more reliable result. Blocking subprocess/socket calls
    run in the default executor so one slow/unreachable target never
    blocks the uplink snapshot cycle."""
    targets = list(_targets)
    if not targets:
        return []

    loop = asyncio.get_event_loop()
    results = []
    for t in targets:
        ip = str(t["ip"])
        port = t.get("check_port")
        try:
            port = int(port) if port not in (None, "") else None
        except (TypeError, ValueError):
            port = None

        try:
            if port:
                ok, detail = await loop.run_in_executor(None, _tcp_check_sync, ip, port, 3)
                method = "tcp"
            else:
                ok, detail = await loop.run_in_executor(None, _ping_sync, ip, 3)
                method = "icmp"
        except Exception as e:
            ok, detail, method = False, f"check error: {type(e).__name__}: {e}", "error"

        results.append({
            "ip": ip, "ok": ok, "method": method, "detail": detail,
            "checked_at": datetime.utcnow().isoformat(),
        })
    return results
