"""
Mikrotik device client — uses RouterOS REST API (v7+) with librouteros fallback.
"""
import asyncio
import aiohttp
import ssl
from typing import Any, Optional
import librouteros
from librouteros.query import Key


class MikrotikClient:
    def __init__(self, ip: str, username: str, password: str,
                 api_port: int = 8728, web_port: int = 80):
        self.ip = ip
        self.username = username
        self.password = password
        self.api_port = api_port
        self.web_port = web_port
        self._rest_base = f"http://{ip}:{web_port}/rest"

    # ── REST API (RouterOS v7) ────────────────────────────────────────────────

    async def rest_get(self, path: str) -> Any:
        url = f"{self._rest_base}/{path.lstrip('/')}"
        auth = aiohttp.BasicAuth(self.username, self.password)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.get(url, auth=auth, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def rest_patch(self, path: str, data: dict) -> Any:
        url = f"{self._rest_base}/{path.lstrip('/')}"
        auth = aiohttp.BasicAuth(self.username, self.password)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.patch(url, json=data, auth=auth, ssl=ssl_ctx,
                                     timeout=aiohttp.ClientTimeout(total=8)) as resp:
                resp.raise_for_status()
                return await resp.json() if resp.content_length else {}

    async def rest_put(self, path: str, data: dict) -> Any:
        url = f"{self._rest_base}/{path.lstrip('/')}"
        auth = aiohttp.BasicAuth(self.username, self.password)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.put(url, json=data, auth=auth, ssl=ssl_ctx,
                                   timeout=aiohttp.ClientTimeout(total=8)) as resp:
                resp.raise_for_status()
                return await resp.json() if resp.content_length else {}

    async def rest_delete(self, path: str) -> None:
        url = f"{self._rest_base}/{path.lstrip('/')}"
        auth = aiohttp.BasicAuth(self.username, self.password)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, auth=auth, ssl=ssl_ctx,
                                      timeout=aiohttp.ClientTimeout(total=8)) as resp:
                resp.raise_for_status()

    # ── High-level helpers ────────────────────────────────────────────────────

    async def get_identity(self) -> dict:
        return await self.rest_get("system/identity")

    async def get_resource(self) -> dict:
        return await self.rest_get("system/resource")

    async def get_routerboard(self) -> dict:
        try:
            return await self.rest_get("system/routerboard")
        except Exception:
            return {}

    async def get_interfaces(self) -> list:
        return await self.rest_get("interface")

    async def get_ip_addresses(self) -> list:
        return await self.rest_get("ip/address")

    async def get_routes(self) -> list:
        return await self.rest_get("ip/route")

    async def get_neighbors(self) -> list:
        try:
            return await self.rest_get("ip/neighbor")
        except Exception:
            return []

    async def get_logs(self, limit: int = 100) -> list:
        """Fetch system log — no local storage, live only."""
        return await self.rest_get("log")

    async def get_firewall_rules(self) -> dict:
        filter_rules = await self.rest_get("ip/firewall/filter")
        nat_rules = await self.rest_get("ip/firewall/nat")
        return {"filter": filter_rules, "nat": nat_rules}

    async def get_wireless(self) -> list:
        try:
            return await self.rest_get("interface/wireless")
        except Exception:
            return []

    async def get_dhcp_leases(self) -> list:
        try:
            return await self.rest_get("ip/dhcp-server/lease")
        except Exception:
            return []

    async def get_vpn_tunnels(self) -> dict:
        result = {}
        for path, key in [
            ("interface/eoip", "eoip"),
            ("interface/vxlan", "vxlan"),
            ("interface/gre", "gre"),
            ("interface/ipip", "ipip"),
        ]:
            try:
                result[key] = await self.rest_get(path)
            except Exception:
                result[key] = []
        return result

    async def set_identity(self, name: str) -> None:
        await self.rest_patch("system/identity", {"name": name})

    # ── librouteros fallback (older devices / API port) ───────────────────────

    def _api_connect(self):
        return librouteros.connect(
            self.ip, username=self.username, password=self.password,
            port=self.api_port, timeout=8
        )

    async def api_command(self, command: str, **kwargs) -> list:
        loop = asyncio.get_event_loop()
        def _run():
            api = self._api_connect()
            try:
                return list(api(command, **kwargs))
            finally:
                api.close()
        return await loop.run_in_executor(None, _run)
