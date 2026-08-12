"""
OVH central login — the PRIMARY authentication source for this agent when
the uplink is configured and reachable (see backend/api/auth.py's /login).
The local emergency account (services/auth.py) remains the fallback, used
only when OVH is unreachable or has no accounts provisioned yet — never as
an automatic retry after a clean credential rejection from a reachable OVH.

This talks to ovh/api.php's `login` action — a completely separate
credential/endpoint space from the snapshot uplink's per-tenant api_key/HMAC
(services/uplink.py). Never send the uplink api_key here.
"""
import asyncio
from typing import Optional

import aiohttp

from services import uplink


class OvhUnreachable(Exception):
    """Network error, timeout, 5xx, or malformed response — the only cases
    where the caller should silently fall back to the local account."""


class OvhNotProvisioned(Exception):
    """OVH is reachable but no `users` rows exist yet for this deployment —
    a one-time bootstrap window, also fallback-eligible."""


class OvhLoginRejected(Exception):
    """Reachable OVH, credentials or tenant-scope explicitly rejected — must
    NOT trigger an automatic fallback attempt."""

    def __init__(self, status: int, error: str):
        self.status = status
        self.error = error
        super().__init__(f"OVH login rejected ({status}): {error}")


async def login(username: str, password: str, totp_code: str = "") -> dict:
    """Returns {token, username, role, allowed_tenants, expires_at} on success."""
    if not uplink.is_configured():
        raise OvhUnreachable("central not configured")
    url = uplink.api_url()
    if not url:
        raise OvhUnreachable("no api_url derivable from uplink config")

    body = {
        "username": username,
        "password": password,
        "totp_code": totp_code,
        "tenant": uplink._config.get("tenant", ""),
    }
    timeout = aiohttp.ClientTimeout(total=6)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, params={"action": "login"}, json=body) as resp:
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = None
                if not isinstance(data, dict):
                    raise OvhUnreachable(f"malformed response (HTTP {resp.status})")
                if resp.status == 404 and data.get("error") == "not_provisioned":
                    raise OvhNotProvisioned()
                if resp.status in (401, 403, 429):
                    raise OvhLoginRejected(resp.status, str(data.get("error", "invalid_credentials")))
                if resp.status != 200 or "token" not in data:
                    raise OvhUnreachable(f"unexpected response (HTTP {resp.status})")
                return data
    except (OvhLoginRejected, OvhNotProvisioned):
        raise
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
        raise OvhUnreachable(str(e))
