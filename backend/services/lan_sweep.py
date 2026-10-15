"""Finds the ordinary computers of the scan ranges for the asset inventory (services/assets.py).

The vulnerability scanner only learns about hosts that answer on an open port, and a Windows computer with its default firewall
answers on none - so workstations were invisible. This sweep reaches them differently: it pokes every address of each active
scan range with a few TCP connects (a firewall that drops the packets still has to resolve the address, which fills the agent's
own ARP table), reads the operating system's neighbour table (address + MAC), and asks every live host for its name over NetBIOS
(UDP 137) and reverse DNS. It sees what is on the agent's own network segment; other segments are covered by the routers'
DHCP/ARP tables that the inventory already reads. Nothing is sent that logs in or changes anything."""
import asyncio
import ipaddress
import os
import re
import socket
import sys
import time
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, ScanRange

PROBE_PORTS = (445, 139, 135, 3389, 5985, 22, 80, 443, 9100, 631)
PROBE_TIMEOUT = 0.5
CONCURRENCY = int(os.environ.get("MIKROTIK_LAN_SWEEP_CONCURRENCY", "120"))
MAX_RANGE_ADDRESSES = 1024                      # a /22; bigger ranges are skipped
MAX_KNOWN_PROBES = 1000                         # hosts of the routers' tables probed per sweep
SWEEP_HOURS = float(os.environ.get("MIKROTIK_LAN_SWEEP_HOURS", "6"))
_WINDOWS_PORTS = {445, 139, 135, 3389, 5985}

_state: dict = {"entries": [], "ranges": [], "at": 0.0, "running": False}
_task: Optional[asyncio.Task] = None


# ── Parsing (pure) ───────────────────────────────────────────────────────────

_ARP_WIN = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})\s", re.I | re.M)
_NEIGH_LINUX = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s.*?lladdr\s+([0-9a-f:]{17})\s+(?!FAILED|INCOMPLETE)", re.I | re.M)


def parse_neighbours(text: str) -> Dict[str, str]:
    """{ip: MAC} from `arp -a` (Windows), `arp -an` or `ip neigh` output. Multicast and broadcast entries are dropped."""
    out: Dict[str, str] = {}
    for rx in (_ARP_WIN, _NEIGH_LINUX):
        for ip, mac in rx.findall(text):
            m = mac.lower().replace("-", ":")
            if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or int(m[:2], 16) & 1:
                continue
            out[ip] = m
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{11,17}) ", text, re.I):   # BSD / macOS `arp -an`
        mac = ":".join(p.zfill(2) for p in m.group(2).lower().split(":"))
        if len(mac) == 17 and not int(mac[:2], 16) & 1 and mac != "ff:ff:ff:ff:ff:ff":
            out[m.group(1)] = mac
    return out


_NBSTAT_QUERY = b"\x81\x62\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01"


def parse_nbstat(data: bytes) -> Optional[str]:
    """The computer name out of a NetBIOS node-status reply (the unique name with suffix 0x00), or None."""
    try:
        if len(data) < 57 or data[3] & 0x0F:                  # RCODE
            return None
        n = data[56]
        for i in range(n):
            e = data[57 + i * 18: 57 + (i + 1) * 18]
            if len(e) < 18:
                break
            name, suffix, flags = e[:15].decode("ascii", errors="ignore").strip(), e[15], (e[16] << 8) | e[17]
            if suffix == 0x00 and not flags & 0x8000 and name:    # unique (not group) workstation name
                return name
    except Exception:
        pass
    return None


# ── Probing ──────────────────────────────────────────────────────────────────

async def _open(ip: str, port: int) -> bool:
    w = None
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=PROBE_TIMEOUT)
        return True
    except Exception:
        return False
    finally:
        if w is not None:
            try:
                w.close()
            except Exception:
                pass


def _nbstat_sync(ip: str) -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(_NBSTAT_QUERY, (ip, 137))
        return parse_nbstat(s.recvfrom(1024)[0])
    except Exception:
        return None
    finally:
        s.close()


def _rdns_sync(ip: str) -> Optional[str]:
    try:
        n = socket.gethostbyaddr(ip)[0]
        return n.split(".")[0] if n and n != ip else None
    except Exception:
        return None


async def _neighbours() -> Dict[str, str]:
    cmds = [["arp", "-a"]] if sys.platform == "win32" else [["ip", "neigh", "show"], ["arp", "-an"]]
    out = ""
    for cmd in cmds:
        try:
            p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            data, _ = await asyncio.wait_for(p.communicate(), timeout=10)
            out += data.decode("utf-8", errors="ignore") + "\n"
        except Exception:
            continue
    return parse_neighbours(out)


async def sweep_range(cidr: str, label: Optional[str] = None) -> dict:
    """{"cidr", "label", "probed", "alive", "entries": [...]} or {"cidr", "skipped": reason}."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {"cidr": cidr, "skipped": "invalid range"}
    if net.version != 4 or net.num_addresses > MAX_RANGE_ADDRESSES:
        return {"cidr": cidr, "skipped": "range too large (the sweep takes up to a /22)"}
    ips = [str(h) for h in net.hosts()]
    sem = asyncio.Semaphore(CONCURRENCY)
    ports: Dict[str, List[int]] = {}

    async def probe(ip: str, port: int):
        async with sem:
            if await _open(ip, port):
                ports.setdefault(ip, []).append(port)

    await asyncio.gather(*(probe(ip, p) for ip in ips for p in PROBE_PORTS))
    in_range = set(ips)
    arp = {ip: mac for ip, mac in (await _neighbours()).items() if ip in in_range}
    alive = sorted(set(ports) | set(arp), key=lambda i: [int(x) for x in i.split(".")])

    loop = asyncio.get_event_loop()
    nsem = asyncio.Semaphore(30)

    async def names(ip: str):
        async with nsem:
            nb = await loop.run_in_executor(None, _nbstat_sync, ip)
            dns = None if nb else await loop.run_in_executor(None, _rdns_sync, ip)
            return ip, nb, dns

    resolved = await asyncio.gather(*(names(ip) for ip in alive))
    entries = []
    for ip, nb, dns in resolved:
        p = sorted(ports.get(ip, []))
        entries.append({"name": nb or dns, "ip": ip, "mac": arp.get(ip), "sources": ["sweep"], "devices": [], "comment": None, "ports": p,
                        "hint": "windows" if (nb or set(p) & _WINDOWS_PORTS) else None})
    return {"cidr": cidr, "label": label, "probed": len(ips), "alive": len(entries), "entries": entries}


async def probe_known(ips: List[str]) -> List[dict]:
    """The hosts the routers' DHCP / ARP tables list but that are outside every swept segment (or hide behind a firewall): no ARP
    here - the agent is not on their segment - so only what answers: open ports, a NetBIOS name, a reverse-DNS name. A host that
    answers nothing is simply not reported (the router's own entry still puts it in the inventory)."""
    if not ips:
        return []
    sem = asyncio.Semaphore(CONCURRENCY)
    ports: Dict[str, List[int]] = {}

    async def probe(ip: str, port: int):
        async with sem:
            if await _open(ip, port):
                ports.setdefault(ip, []).append(port)

    await asyncio.gather(*(probe(ip, p) for ip in ips for p in PROBE_PORTS))
    loop = asyncio.get_event_loop()
    nsem = asyncio.Semaphore(30)

    async def names(ip: str):
        async with nsem:
            nb = await loop.run_in_executor(None, _nbstat_sync, ip)
            dns = None if nb else await loop.run_in_executor(None, _rdns_sync, ip)
            return ip, nb, dns

    entries = []
    for ip, nb, dns in await asyncio.gather(*(names(ip) for ip in ips)):
        p = sorted(ports.get(ip, []))
        if p or nb or dns:
            entries.append({"name": nb or dns, "ip": ip, "mac": None, "sources": ["sweep"], "devices": [], "comment": None, "ports": p,
                            "hint": "windows" if (nb or set(p) & _WINDOWS_PORTS) else None})
    return entries


async def sweep_all() -> dict:
    """Sweeps every active scan range, keeps the result for the inventory and returns {"ranges": [...], "alive": n}."""
    if _state["running"]:
        return {"running": True, "ranges": _state["ranges"], "alive": len(_state["entries"])}
    _state["running"] = True
    try:
        with SessionLocal() as db:
            ranges = [(r.cidr, r.label) for r in db.execute(select(ScanRange).where(ScanRange.active == True)).scalars().all()]  # noqa: E712
        results, entries, seen = [], [], set()
        for cidr, label in ranges:
            r = await sweep_range(cidr, label)
            for e in r.pop("entries", []):
                if e["ip"] not in seen:
                    seen.add(e["ip"])
                    entries.append(e)
            results.append(r)
        # the routers' own tables: hosts in other segments that no ARP of ours can reach
        try:
            from services import host_monitor
            known = [e["ip"] for e in await host_monitor.directory(max_age=86400) if e.get("ip") and e["ip"] not in seen and "sweep" not in (e.get("sources") or [])]
            extra = await probe_known(known[:MAX_KNOWN_PROBES])
            for e in extra:
                seen.add(e["ip"])
                entries.append(e)
            if known:
                results.append({"cidr": "routers' DHCP/ARP tables", "label": None, "probed": min(len(known), MAX_KNOWN_PROBES), "alive": len(extra)})
        except Exception as e:
            print(f"[lan_sweep] probing the routers' hosts failed: {e}")
        _state.update(entries=entries, ranges=results, at=time.time())
        return {"ranges": results, "alive": len(entries)}
    finally:
        _state["running"] = False


def entries() -> List[dict]:
    """The hosts of the last sweep, in the shape of the DHCP/ARP directory entries."""
    return list(_state["entries"])


def status() -> dict:
    return {"at": _state["at"] or None, "running": _state["running"], "ranges": _state["ranges"], "alive": len(_state["entries"])}


async def _loop():
    await asyncio.sleep(100)
    while True:
        try:
            if time.time() - _state["at"] > SWEEP_HOURS * 3600:
                await sweep_all()
                from services import assets
                await assets.refresh()
        except Exception as e:
            print(f"[lan_sweep] loop error: {e}")
        await asyncio.sleep(600)


def start():
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
    _task = None
