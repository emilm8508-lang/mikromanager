"""
Connecting the network devices to the agent: what works for each one, why not, and fixing it in bulk.

The scanner finds the MikroTik routers, the Cisco SB switches and anything else that answers SNMP, but a device is only useful once the agent can actually talk to it: a
login that is accepted (REST or the binary API for RouterOS, SSH for Cisco SB) gives everything - details, resources, firmware, configuration history - while SNMP alone gives
a read-only view (SwOS Lite, a few older switches and printers can never give more). This module answers, per device, with a live test:

  * channels: REST, API, SNMP (RouterOS); SSH, SNMP (Cisco SB); SNMP (anything else) - each ok, or why not (login refused, service off, no answer);
  * level: full / snmp (read only) / none, and a plain "what to do" for the usual causes;
  * the stored credentials are tried on a device that has none or does not work (concurrently, bounded), and the best one can be assigned to many devices at once - never over
    a credential that already works;
  * the networks the agent's own computer is in, as scan ranges to suggest when none is configured (the usual reason nothing is found).

Nothing is changed on a device: only logins and reads are attempted. Credentials never leave the agent.
"""
import asyncio
import ipaddress
import re
import subprocess
import sys
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, Credential, ScanRange
from services.crypto import decrypt

CHANNEL_TIMEOUT = 8.0
MAX_CRED_TRIES = 8
CONCURRENCY = 4
FULL_CHANNELS = ("rest", "api", "ssh")
_client_factory = None                      # tests put a fake here: (kind, device, cred) -> awaitable result of one channel


def classify_error(e: BaseException) -> dict:
    """{"code": auth | closed | timeout | other, "message"} from whatever a channel raised."""
    text = f"{type(e).__name__}: {e}"
    low = text.lower()
    status = getattr(e, "status", None)
    if status in (401, 403) or "authentication" in low or "invalid user name or password" in low or "cannot log in" in low or "bad credentials" in low or "not permitted" in low:
        return {"code": "auth", "message": text[:200]}
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)) or "timed out" in low or "timeout" in low or "10060" in low:
        return {"code": "timeout", "message": text[:200]}
    if isinstance(e, ConnectionRefusedError) or "refused" in low or "10061" in low or "cannot connect" in low or status in (404, 502, 503):
        return {"code": "closed", "message": text[:200]}
    return {"code": "other", "message": text[:200]}


async def _ok(coro, what: str) -> dict:
    try:
        r = await asyncio.wait_for(coro, timeout=CHANNEL_TIMEOUT)
        return {"ok": True, "detail": what if r is None else str(r)[:80]}
    except Exception as e:
        return {"ok": False, **classify_error(e)}


def _ssh_login(ip: str, port: int, user: str, password: str) -> str:
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, port=port, username=user, password=password, timeout=6, banner_timeout=6, auth_timeout=6, look_for_keys=False, allow_agent=False)
        return "login accepted"
    finally:
        c.close()


async def _channel(kind: str, dev: dict, cred: dict):
    """One channel test: returns when it worked, raises otherwise."""
    if kind == "snmp":
        from services.snmp_client import SnmpClient
        if not cred.get("community"):
            raise PermissionError("authentication: no SNMP community in this credential")
        if not await SnmpClient(dev["ip"], cred["community"], port=dev["snmp_port"], timeout=4.0).probe():
            raise asyncio.TimeoutError("no SNMP answer")
        return "answers"
    if kind == "ssh":
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _ssh_login, dev["ip"], dev["ssh_port"], cred["username"], cred["password"])
    from services.mikrotik_client import MikrotikClient
    c = MikrotikClient(dev["ip"], cred["username"], cred["password"], api_port=dev["api_port"], web_port=dev["web_port"])
    if kind == "rest":
        r = await c.rest_get("system/identity")
        return (r or {}).get("name")
    if kind == "api":
        r = await c.api_command("/system/identity")
        return (r[0] or {}).get("name") if r else "ok"
    raise ValueError(kind)


def channels_for(vendor: str) -> List[str]:
    v = (vendor or "mikrotik").lower()
    if v == "cisco-sb":
        return ["ssh", "snmp"]
    if v in ("generic-snmp", "cisco-generic", "unknown"):
        return ["snmp"]
    return ["rest", "api", "snmp"]


async def test_channels(dev: dict, cred: dict) -> dict:
    """{channel: {ok, detail | code, message}} for one device and one credential."""
    kinds = channels_for(dev["vendor"])
    run = _client_factory or _channel
    res = await asyncio.gather(*[_ok(run(k, dev, cred), "ok") for k in kinds])
    return dict(zip(kinds, res))


def level_of(channels: dict) -> str:
    if any(channels.get(k, {}).get("ok") for k in FULL_CHANNELS):
        return "full"
    if channels.get("snmp", {}).get("ok"):
        return "snmp"
    return "none"


ADVICE = {
    "auth": "login_refused", "closed": "service_off", "timeout": "no_answer", "other": "failed",
}


def advice(dev: dict, channels: dict, level: str, tried: int) -> List[str]:
    """Codes of what to do, most useful first (the page turns them into text)."""
    out: List[str] = []
    if level == "full":
        return out
    vendor = (dev["vendor"] or "mikrotik").lower()
    if tried == 0:
        out.append("no_credential")
    full_kinds = [k for k in channels_for(vendor) if k in FULL_CHANNELS]
    codes = {k: channels[k].get("code") for k in full_kinds if k in channels and not channels[k].get("ok")}
    if vendor in ("generic-snmp", "cisco-generic", "unknown") or not full_kinds:
        out.append("snmp_only_device" if level == "snmp" else "snmp_failed")
        return out
    if codes and all(c == "auth" for c in codes.values()):
        out.append("login_refused")
    elif codes and all(c in ("closed",) for c in codes.values()):
        out.append("service_off_" + vendor)
    elif codes and all(c in ("timeout", "closed") for c in codes.values()):
        out.append("no_answer")
    elif codes:
        out.append("login_refused" if "auth" in codes.values() else "no_answer")
    if level == "snmp":
        out.append("only_snmp")
    return out


def _snapshot(d: Device) -> dict:
    return {"id": d.id, "ip": d.ip, "name": d.name or d.identity or d.ip, "vendor": (d.vendor or "mikrotik").lower(), "api_port": d.api_port or 8728, "web_port": d.web_port or 80,
            "snmp_port": d.snmp_port or 161, "ssh_port": d.ssh_port or 22, "credential_id": d.credential_id}


def _cred_dict(c: Credential) -> dict:
    return {"id": c.id, "name": c.name, "username": c.username, "password": decrypt(c.password_enc) if c.password_enc else "",
            "community": decrypt(c.snmp_community_enc) if c.snmp_community_enc else None}


def _rank(level: str) -> int:
    return {"full": 2, "snmp": 1, "none": 0}[level]


async def diagnose(device_id: int, try_others: bool = True) -> Optional[dict]:
    """Live test of one device: its own credential first, then (when that does not give full access) the other stored ones. Returns None for an unknown device."""
    with SessionLocal() as db:
        d = db.get(Device, device_id)
        if d is None:
            return None
        dev = _snapshot(d)
        creds = [_cred_dict(c) for c in db.execute(select(Credential)).scalars().all()]
    own = next((c for c in creds if c["id"] == dev["credential_id"]), None)
    others = [c for c in creds if own is None or c["id"] != own["id"]][:MAX_CRED_TRIES]
    results: List[dict] = []
    tried = 0
    if own is not None:
        ch = await test_channels(dev, own)
        results.append({"credential_id": own["id"], "credential": own["name"], "own": True, "channels": ch, "level": level_of(ch)})
        tried += 1
    if try_others and (not results or results[0]["level"] != "full"):
        sem = asyncio.Semaphore(CONCURRENCY)

        async def one(c):
            async with sem:
                ch = await test_channels(dev, c)
            return {"credential_id": c["id"], "credential": c["name"], "own": False, "channels": ch, "level": level_of(ch)}
        results += await asyncio.gather(*[one(c) for c in others])
        tried += len(others)
    best = max(results, key=lambda r: (_rank(r["level"]), r["own"]), default=None)
    channels = best["channels"] if best else {k: {"ok": False, "code": "other", "message": "no credential stored"} for k in channels_for(dev["vendor"])}
    level = best["level"] if best else "none"
    return {"device_id": dev["id"], "name": dev["name"], "ip": dev["ip"], "vendor": dev["vendor"], "level": level, "channels": channels, "best_credential": best["credential"] if best else None,
            "best_credential_id": best["credential_id"] if best else None, "own_credential_id": dev["credential_id"], "tried": tried, "advice": advice(dev, channels, level, tried),
            "results": [{k: r[k] for k in ("credential_id", "credential", "own", "level")} for r in results]}


async def assign_best(device_ids: List[int]) -> List[dict]:
    """Tests the devices and assigns the best working credential to every one that has none or whose own gives less. A credential that already gives full access is never replaced."""
    out = []
    sem = asyncio.Semaphore(2)

    async def one(i: int):
        async with sem:
            return await diagnose(i, try_others=True)
    reports = await asyncio.gather(*[one(i) for i in dict.fromkeys(device_ids)])
    for r in reports:
        if r is None:
            continue
        changed = None
        own_level = next((x["level"] for x in r["results"] if x["own"]), None)
        bid = r["best_credential_id"]
        if bid is not None and bid != r["own_credential_id"] and _rank(r["level"]) > _rank(own_level or "none"):
            with SessionLocal() as db:
                d = db.get(Device, r["device_id"])
                if d is not None:
                    d.credential_id = bid
                    db.commit()
                    changed = r["best_credential"]
        out.append({"device_id": r["device_id"], "name": r["name"], "level": r["level"], "assigned": changed, "advice": r["advice"]})
    return out


def overview() -> dict:
    """What is known without touching the network: per device the stored flags, whether it has a credential and the last time its details were read; plus the scan ranges."""
    with SessionLocal() as db:
        creds = {c.id: c for c in db.execute(select(Credential)).scalars().all()}
        rows = []
        for d in db.execute(select(Device).order_by(Device.name, Device.ip)).scalars().all():
            c = creds.get(d.credential_id)
            has_login = bool(c and c.password_enc)
            has_comm = bool(c and c.snmp_community_enc)
            state = "no_credential" if c is None else ("ok" if d.last_resources_check_at else ("snmp" if (has_comm and not has_login) else "unverified"))
            rows.append({"id": d.id, "name": d.name or d.identity or d.ip, "ip": d.ip, "vendor": (d.vendor or "mikrotik"), "model": d.model, "online": bool(d.online), "mgmt_ok": d.mgmt_ok,
                         "credential": c.name if c else None, "has_login": has_login, "has_snmp_community": has_comm, "state": state,
                         "last_read": d.last_resources_check_at.isoformat() + "Z" if d.last_resources_check_at else None,
                         "ports": {"api": bool(d.has_api), "ssh": bool(d.has_ssh), "web": bool(d.has_web), "snmp": bool(d.has_snmp)}})
        ranges = [{"id": r.id, "cidr": r.cidr, "label": r.label, "active": bool(r.active)} for r in db.execute(select(ScanRange)).scalars().all()]
        ncreds = len(creds)
    return {"devices": rows, "ranges": ranges, "credentials": ncreds, "suggested_ranges": suggest_ranges([r["cidr"] for r in ranges])}


# ── The agent's own networks ─────────────────────────────────────────────────

def parse_local_networks(text: str, windows: bool) -> List[str]:
    """CIDRs from `ipconfig` (Windows) or `ip -o -4 addr` (Linux) output; loopback, link-local and /32 are skipped."""
    nets: List[str] = []
    if windows:
        ip = None
        for line in text.splitlines():
            m = re.search(r"IPv4[^:]*:\s*([\d.]+)", line)
            if m:
                ip = m.group(1)
                continue
            m = re.search(r"(?:Subnet Mask|Maska podsieci)[^:]*:\s*([\d.]+)", line)
            if m and ip:
                try:
                    nets.append(str(ipaddress.ip_network(f"{ip}/{m.group(1)}", strict=False)))
                except ValueError:
                    pass
                ip = None
    else:
        for m in re.finditer(r"inet\s+([\d.]+/\d+)", text):
            try:
                nets.append(str(ipaddress.ip_network(m.group(1), strict=False)))
            except ValueError:
                pass
    out = []
    for n in nets:
        net = ipaddress.ip_network(n)
        if net.is_loopback or net.is_link_local or net.prefixlen >= 32 or net.prefixlen < 16:
            continue
        if n not in out:
            out.append(n)
    return out


def local_networks() -> List[str]:
    try:
        if sys.platform == "win32":
            out = subprocess.run(["ipconfig"], capture_output=True, timeout=10).stdout.decode("oem", errors="replace")
            return parse_local_networks(out, True)
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "scope", "global"], capture_output=True, timeout=10, text=True).stdout
        return parse_local_networks(out, False)
    except Exception:
        return []


def suggest_ranges(configured: List[str], nets: Optional[List[str]] = None) -> List[dict]:
    """The agent's own networks that no configured scan range covers: [{"cidr", "hosts"}]."""
    have = []
    for c in configured:
        try:
            have.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    out = []
    for n in (nets if nets is not None else local_networks()):
        net = ipaddress.ip_network(n)
        if not any(net.subnet_of(h) for h in have if h.version == net.version):
            out.append({"cidr": n, "hosts": max(0, net.num_addresses - 2)})
    return out
