"""
Async network scanner — discovers Mikrotik devices in given CIDR ranges.
Probes TCP for API/SSH/web and UDP for SNMP.
"""
import asyncio
import ipaddress
from typing import AsyncGenerator, Optional
import aiohttp
import ssl

PORT_TIMEOUT = 0.8
SNMP_TIMEOUT = 1.5
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


async def _snmp_alive(ip: str, port: int = 161) -> bool:
    """Quick SNMP v2c probe with 'public' community — just to see if SNMP is
    responding at all. Even if community is wrong, no-response = port closed
    or service disabled."""
    try:
        from puresnmp import Client, V2C, PyWrapper
        client = PyWrapper(Client(ip, V2C("public"), port=port))
        await asyncio.wait_for(client.get("1.3.6.1.2.1.1.5.0"), timeout=SNMP_TIMEOUT)
        return True
    except Exception:
        # Even with wrong community, an SNMP daemon usually times out silently.
        # We can't reliably detect SNMP without a valid community, so we report
        # 'no' here. Actual SNMP usability is verified during enrichment.
        return False


async def _is_mikrotik_rest(ip: str, port: int) -> Optional[dict]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/rest/system/resource"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
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
        has_api = await _tcp_open(ip, 8728)
        has_api_ssl = await _tcp_open(ip, 8729)
        has_ssh = await _tcp_open(ip, 22)
        has_snmp = await _snmp_alive(ip)  # uses 'public' — best-effort

        web_result = None
        for port in [80, 443]:
            web_result = await _is_mikrotik_rest(ip, port)
            if web_result:
                break

        if not (has_api or has_api_ssl or web_result or has_snmp):
            return None

        return {
            "ip": ip,
            "has_api": has_api or has_api_ssl,
            "api_port": 8729 if has_api_ssl else 8728,
            "has_ssh": has_ssh,
            "has_web": bool(web_result),
            "web_port": web_result["web_port"] if web_result else 80,
            "has_snmp": has_snmp,
            "snmp_port": 161,
        }


async def scan_range(cidr: str) -> AsyncGenerator[dict, None]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
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
    """Fetch device identity and resource info via REST → API → SNMP fallback."""
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
