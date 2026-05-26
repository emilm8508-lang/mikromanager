"""
Async network scanner — discovers Mikrotik devices in given CIDR ranges.
"""
import asyncio
import socket
import ipaddress
from typing import AsyncGenerator, Optional
import aiohttp
import ssl

MIKROTIK_PORTS = [8728, 8729, 80, 443, 22]
MIKROTIK_IDENTITY_PATHS = ["/rest/system/identity", "/rest/system/resource"]
PING_TIMEOUT = 0.8
PORT_TIMEOUT = 0.8
MAX_CONCURRENT = 50


async def _tcp_open(ip: str, port: int) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=PORT_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _is_mikrotik_rest(ip: str, port: int) -> Optional[dict]:
    """Try to hit /rest/system/resource without auth — Mikrotik returns 401, not 404."""
    url = f"http://{ip}:{port}/rest/system/resource"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/rest/system/resource"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=ssl_ctx,
                                   timeout=aiohttp.ClientTimeout(total=2)) as resp:
                if resp.status in (401, 200):
                    return {"web_port": port, "has_web": True}
    except Exception:
        pass
    return None


async def _probe_host(ip: str, semaphore: asyncio.Semaphore) -> Optional[dict]:
    async with semaphore:
        # Quick TCP probe on API port first
        has_api = await _tcp_open(ip, 8728)
        has_api_ssl = await _tcp_open(ip, 8729)
        has_ssh = await _tcp_open(ip, 22)

        # Check REST API on common web ports
        web_result = None
        for port in [80, 443]:
            web_result = await _is_mikrotik_rest(ip, port)
            if web_result:
                break

        if not (has_api or has_api_ssl or web_result):
            return None

        return {
            "ip": ip,
            "has_api": has_api or has_api_ssl,
            "api_port": 8729 if has_api_ssl else 8728,
            "has_ssh": has_ssh,
            "has_web": bool(web_result),
            "web_port": web_result["web_port"] if web_result else 80,
        }


async def scan_range(cidr: str) -> AsyncGenerator[dict, None]:
    """Yield discovered Mikrotik device info dicts for each host in cidr."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = [asyncio.create_task(_probe_host(str(h), semaphore)) for h in hosts]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            yield result


async def enrich_device(ip: str, username: str, password: str,
                        web_port: int = 80) -> dict:
    """Fetch device identity and resource info after discovery."""
    from services.mikrotik_client import MikrotikClient
    client = MikrotikClient(ip, username, password, web_port=web_port)
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
