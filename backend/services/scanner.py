"""
Async network scanner — discovers Mikrotik devices in given CIDR ranges.

Strategy per host:
  1. PARALLEL TCP probe on common ports (8728, 80, 22, 443) — short timeout (0.4s).
     If ALL fail → host is dead, skip everything else immediately.
  2. If any TCP is open → do detailed probe (REST detection, SNMP, ports).

This means an empty /24 finishes in seconds instead of minutes.
"""
import asyncio
import ipaddress
import os
from typing import AsyncGenerator, Optional, Callable
import aiohttp
import ssl

LIVENESS_TIMEOUT = 0.4   # short — for empty-host detection
PORT_TIMEOUT = 0.8       # confirmation probe
SNMP_TIMEOUT = 1.2
HTTP_TIMEOUT = 2.0
# Concurrency cap. Each host probe can open up to ~8 sockets in parallel
# (4 liveness + 1 SSL TCP + 2 HTTP + 1 SNMP). On Windows select() has a 512
# FD limit, so default 30 * 8 = 240 keeps us well under. ProactorEventLoop
# (IOCP) is unlimited, but we keep this default to be polite to networks/devices.
MAX_CONCURRENT = int(os.environ.get("MIKROTIK_SCAN_CONCURRENCY", "30"))

# Ports used for fast liveness check.
# 8291 = Winbox (definitive Mikrotik signal — almost always enabled on RouterOS).
# 8728 = legacy API, 22 = SSH, 80/443 = WebFig / REST.
LIVENESS_PORTS = [8728, 8291, 22, 80, 443]


async def _tcp_open(ip: str, port: int, timeout: float = PORT_TIMEOUT) -> bool:
    """Open + immediately close a TCP socket. Uses raw socket via create_connection
    to ensure cleanup even on timeout/cancellation."""
    writer = None
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        return True
    except Exception:
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
                # Don't await wait_closed() — it can hang on broken connections
            except Exception:
                pass


async def _is_alive(ip: str) -> dict:
    """Fast parallel probe of common TCP ports. Returns dict of open ports."""
    results = await asyncio.gather(*[
        _tcp_open(ip, p, timeout=LIVENESS_TIMEOUT) for p in LIVENESS_PORTS
    ])
    return {port: ok for port, ok in zip(LIVENESS_PORTS, results)}


async def _snmp_alive(ip: str, port: int = 161) -> bool:
    try:
        from puresnmp import Client, V2C, PyWrapper
        client = PyWrapper(Client(ip, V2C("public"), port=port))
        await asyncio.wait_for(client.get("1.3.6.1.2.1.1.5.0"), timeout=SNMP_TIMEOUT)
        return True
    except Exception:
        return False


async def _is_mikrotik_web(ip: str, port: int) -> Optional[dict]:
    """Detect Mikrotik web interface — works for both RouterOS v7 (REST API)
    and v6 (WebFig HTML). Returns {web_port, has_web, web_kind} or None."""
    scheme = "https" if port == 443 else "http"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(force_close=True, limit=1, ssl=ssl_ctx)

    # 1. Try REST API (v7+). Mikrotik returns 401 Unauthorized without creds.
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(f"{scheme}://{ip}:{port}/rest/system/resource",
                                   timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT)) as resp:
                if resp.status in (401, 200):
                    return {"web_port": port, "has_web": True, "web_kind": "rest"}
    except Exception:
        pass

    # 2. Try root page (v6 WebFig has "RouterOS"/"Mikrotik" in HTML/headers).
    connector2 = aiohttp.TCPConnector(force_close=True, limit=1, ssl=ssl_ctx)
    try:
        async with aiohttp.ClientSession(connector=connector2) as session:
            async with session.get(f"{scheme}://{ip}:{port}/",
                                   timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                                   allow_redirects=True) as resp:
                # Header check — Mikrotik web server identifies itself
                server = resp.headers.get("Server", "").lower()
                if "mikrotik" in server or "webfig" in server:
                    return {"web_port": port, "has_web": True, "web_kind": "webfig"}
                # Body check — read up to 4 KB
                body = await resp.content.read(4096)
                text = body.decode("utf-8", errors="ignore").lower()
                if "mikrotik" in text or "routeros" in text or "webfig" in text:
                    return {"web_port": port, "has_web": True, "web_kind": "webfig"}
    except Exception:
        pass

    return None


# Backwards-compat alias
_is_mikrotik_rest = _is_mikrotik_web


async def _probe_host(ip: str, semaphore: asyncio.Semaphore,
                      on_progress: Optional[Callable] = None) -> Optional[dict]:
    async with semaphore:
        if on_progress:
            on_progress(ip, "checking")

        # ── Phase 1: parallel liveness — if all closed, abort fast ────────
        ports = await _is_alive(ip)
        any_alive = any(ports.values())

        if not any_alive:
            # No TCP port responded — could still be SNMP-only, but skip to keep
            # scan fast. (You can enable the line below to also probe SNMP on dead-TCP hosts.)
            # if not await _snmp_alive(ip): return None
            if on_progress:
                on_progress(ip, "dead")
            return None

        if on_progress:
            on_progress(ip, "probing")

        # ── Phase 2: detailed checks (in parallel) ────────────────────────
        has_api_ssl_task = _tcp_open(ip, 8729)
        web_80_task = _is_mikrotik_web(ip, 80) if ports.get(80) else asyncio.sleep(0, result=None)
        web_443_task = _is_mikrotik_web(ip, 443) if ports.get(443) else asyncio.sleep(0, result=None)
        snmp_task = _snmp_alive(ip)

        has_api_ssl, web_80, web_443, has_snmp = await asyncio.gather(
            has_api_ssl_task, web_80_task, web_443_task, snmp_task
        )

        web_result = web_80 or web_443
        has_api = ports.get(8728, False)
        has_ssh = ports.get(22, False)
        has_winbox = ports.get(8291, False)

        # Mikrotik signature: ANY of these is definitive:
        #   - 8291 (Winbox) — only Mikrotik runs this
        #   - 8728/8729 (RouterOS API) — only Mikrotik runs this
        #   - web responded with Mikrotik signature (REST or WebFig HTML)
        #   - SNMP responded (combined with port 80 open is strong signal)
        is_mikrotik = (
            has_winbox or has_api or has_api_ssl or
            bool(web_result) or
            (has_snmp and (ports.get(80) or ports.get(443)))
        )

        if not is_mikrotik:
            if on_progress:
                on_progress(ip, "dead")
            return None

        if on_progress:
            on_progress(ip, "found")

        # If web port is open but didn't match REST/WebFig signature, still mark
        # has_web=True if Winbox is open (probably old device with non-standard web)
        web_port = web_result["web_port"] if web_result else (80 if ports.get(80) else (443 if ports.get(443) else 80))
        has_web_flag = bool(web_result) or (has_winbox and (ports.get(80) or ports.get(443)))

        return {
            "ip": ip,
            "has_api": has_api or has_api_ssl,
            "api_port": 8729 if has_api_ssl else 8728,
            "has_ssh": has_ssh,
            "has_web": has_web_flag,
            "web_port": web_port,
            "has_snmp": has_snmp,
            "snmp_port": 161,
            "has_winbox": has_winbox,
        }


async def scan_range_with_progress(
    cidr: str,
    on_event: Callable,
    skip_ips: Optional[set] = None,
) -> int:
    """Scan a CIDR, calling on_event(dict) for every state change.
    Events: {type: 'total'|'progress'|'found'|'dead'|'cidr_done'|'skipped', ...}

    If skip_ips is provided, hosts whose IP is in this set are skipped
    entirely (not probed). Use this to focus only on UNKNOWN IPs — known
    devices are kept up to date by the periodic refresher instead.

    Returns number of found devices.
    """
    skip_ips = skip_ips or set()
    network = ipaddress.ip_network(cidr, strict=False)
    all_hosts = [str(h) for h in network.hosts()]
    hosts = [ip for ip in all_hosts if ip not in skip_ips]
    skipped_count = len(all_hosts) - len(hosts)
    total = len(hosts)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    found_count = 0
    completed = 0
    completed_lock = asyncio.Lock()

    on_event({
        "type": "total",
        "cidr": cidr,
        "total": total,
        "total_all": len(all_hosts),
        "skipped_known": skipped_count,
    })

    if total == 0:
        on_event({"type": "cidr_done", "cidr": cidr, "found": 0,
                  "skipped_known": skipped_count})
        return 0

    async def _run_one(ip):
        nonlocal completed, found_count
        result = await _probe_host(ip, semaphore)
        async with completed_lock:
            completed += 1
            if result:
                found_count += 1
                on_event({"type": "found", "ip": ip, "device": result,
                          "completed": completed, "total": total})
            else:
                on_event({"type": "progress", "ip": ip,
                          "completed": completed, "total": total})
        return result

    await asyncio.gather(*[_run_one(ip) for ip in hosts])
    on_event({"type": "cidr_done", "cidr": cidr, "found": found_count,
              "skipped_known": skipped_count})
    return found_count


# Legacy async generator kept for backward compat
async def scan_range(cidr: str) -> AsyncGenerator[dict, None]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = [asyncio.create_task(_probe_host(str(h), semaphore)) for h in hosts]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            yield result


async def enrich_device(ip: str, username: str, password: str,
                        web_port: int = 80,
                        snmp_community: Optional[str] = None,
                        snmp_port: int = 161) -> dict:
    from services.mikrotik_client import MikrotikClient
    client = MikrotikClient(ip, username, password,
                            web_port=web_port,
                            snmp_community=snmp_community,
                            snmp_port=snmp_port)
    info = {"ip": ip}
    try:
        identity = await client.get_identity()
        info["identity"] = identity.get("name", "")
    except Exception:
        pass
    try:
        resource = await client.get_resource()
        info["model"] = resource.get("board-name", "")
        info["ros_version"] = resource.get("version", "")
    except Exception:
        pass
    try:
        rb = await client.get_routerboard()
        info["board_name"] = rb.get("board", "")
    except Exception:
        pass
    return info
