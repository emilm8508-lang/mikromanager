"""Ping, traceroute and a TCP port scan of one inventory device, started from its card, with the output arriving line by line.

Only for the address of an asset the inventory knows (the API checks), one job per request, at most MAX_RUNNING at a time, the output kept for
JOB_TTL seconds. The port scan is a plain TCP connect scan - the same kind of connection the vulnerability scan already makes - of the common
ports or of the ports given (at most MAX_PORTS); it sends nothing but the connection attempt."""
import asyncio
import ipaddress
import shutil
import socket
import sys
import time
import uuid
from typing import Dict, List, Optional

MAX_RUNNING = 3
JOB_TTL = 900
MAX_PORTS = 2048
MAX_LINES = 600
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 515, 548, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 3000,
                3306, 3389, 5000, 5060, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8081, 8443, 8728, 8729, 9000, 9090, 9100, 9200, 10000, 27017]
_jobs: Dict[str, dict] = {}


def parse_ports(spec: Optional[str]) -> List[int]:
    """"80,443,8000-8100" -> [80, 443, 8000, ...]; the common ports when empty. ValueError for nonsense or more than MAX_PORTS."""
    if not spec or not spec.strip():
        return list(COMMON_PORTS)
    out: List[int] = []
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        a, _, b = part.partition("-")
        lo, hi = int(a), int(b or a)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError("ports must be between 1 and 65535")
        out.extend(range(lo, hi + 1))
        if len(out) > MAX_PORTS:
            raise ValueError(f"at most {MAX_PORTS} ports at a time")
    return list(dict.fromkeys(out))


def _purge() -> None:
    now = time.time()
    for k in [k for k, j in _jobs.items() if now - j["started"] > JOB_TTL]:
        _jobs.pop(k, None)


def _add(job: dict, line: str) -> None:
    if len(job["lines"]) < MAX_LINES:
        job["lines"].append(line.rstrip("\r\n"))


async def _run_proc(job: dict, cmd: List[str]) -> None:
    enc = "oem" if sys.platform == "win32" else "utf-8"
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        assert p.stdout is not None
        while True:
            raw = await asyncio.wait_for(p.stdout.readline(), timeout=60)
            if not raw:
                break
            _add(job, raw.decode(enc, errors="replace"))
        await p.wait()
    except asyncio.TimeoutError:
        _add(job, "(timed out)")
    except Exception as e:
        _add(job, f"{type(e).__name__}: {e}")


async def _run_portscan(job: dict, ip: str, ports: List[int]) -> None:
    sem = asyncio.Semaphore(120)
    open_ports: List[int] = []

    async def one(port: int):
        async with sem:
            try:
                _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.7)
                w.close()
                open_ports.append(port)
                try:
                    svc = socket.getservbyport(port, "tcp")
                except OSError:
                    svc = "?"
                _add(job, f"{port}/tcp open  {svc}")
            except Exception:
                pass

    _add(job, f"Scanning {len(ports)} TCP port(s) of {ip} ...")
    await asyncio.gather(*(one(p) for p in ports))
    _add(job, f"Done: {len(open_ports)} open of {len(ports)}." if open_ports else f"Done: no open port among {len(ports)}.")


async def _run(job: dict, kind: str, ip: str, ports: Optional[List[int]]) -> None:
    try:
        if kind == "ping":
            await _run_proc(job, ["ping", "-n", "4", ip] if sys.platform == "win32" else ["ping", "-c", "4", ip])
        elif kind == "traceroute":
            if sys.platform == "win32":
                await _run_proc(job, ["tracert", "-d", "-h", "20", "-w", "700", ip])
            elif shutil.which("traceroute"):
                await _run_proc(job, ["traceroute", "-n", "-m", "20", "-w", "1", ip])
            elif shutil.which("tracepath"):
                await _run_proc(job, ["tracepath", "-n", ip])
            else:
                _add(job, "traceroute is not installed on this computer (apt install traceroute)")
        elif kind == "portscan":
            await _run_portscan(job, ip, ports or COMMON_PORTS)
    finally:
        job["done"] = True


def start(kind: str, ip: str, ports_spec: Optional[str] = None) -> dict:
    """{"job": id}. Raises ValueError (bad tool / address / ports) or RuntimeError (too many running)."""
    if kind not in ("ping", "traceroute", "portscan"):
        raise ValueError("unknown tool")
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        raise ValueError("the device has no valid IPv4 address")
    if addr.version != 4 or addr.is_multicast or addr.is_unspecified:
        raise ValueError("the device has no valid IPv4 address")
    ports = parse_ports(ports_spec) if kind == "portscan" else None
    _purge()
    if sum(1 for j in _jobs.values() if not j["done"]) >= MAX_RUNNING:
        raise RuntimeError("too many tools running at once - wait for one to finish")
    jid = uuid.uuid4().hex[:12]
    job = {"kind": kind, "ip": str(addr), "lines": [], "done": False, "started": time.time()}
    _jobs[jid] = job
    asyncio.get_event_loop().create_task(_run(job, kind, str(addr), ports))
    return {"job": jid}


def poll(jid: str, since: int = 0) -> Optional[dict]:
    j = _jobs.get(jid)
    if not j:
        return None
    return {"kind": j["kind"], "ip": j["ip"], "lines": j["lines"][since:], "next": len(j["lines"]), "done": j["done"]}
