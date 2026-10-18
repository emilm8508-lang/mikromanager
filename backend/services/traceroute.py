"""Traceroute to a host: the routers between the agent and it, hop by hop - how the hosts of routed ranges are grouped under their gateway.

An ARP scan and the routers' DHCP / ARP tables cover the segments the agent can reach at layer 2. A host in a routed range (another site, another
VLAN behind a router) can only be placed by the path to it: the last router before it is its gateway. One trace per subnet is enough, not one per host.
The system's own tool does the work (tracert on Windows, traceroute / tracepath elsewhere) and its output is parsed here; nothing else is sent."""
import asyncio
import re
import shutil
import sys
from typing import List, Optional

MAX_HOPS = 15
_WIN_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_MS = re.compile(r"(<?\d+(?:\.\d+)?)\s*ms")


def parse(text: str) -> List[dict]:
    """[{"n": 1, "ip": "192.168.1.1" | None, "ms": 0.5 | None}, ...] from tracert / traceroute / tracepath output (timeouts have ip None)."""
    hops: List[dict] = []
    for line in (text or "").splitlines():
        m = _WIN_HOP.match(line)
        if not m:
            continue
        n, rest = int(m.group(1)), m.group(2)
        if hops and n <= hops[-1]["n"]:
            continue
        if line.lstrip().startswith(("Trace", "over", "Tracing")):
            continue
        # tracepath prints "1?: [LOCALHOST]" lines and "1:  host  0.5ms"; only an IPv4 address (or a "*") makes a hop
        ips = _IP.findall(rest)
        ms = _MS.search(rest)
        if ips or re.search(r"\*", rest) or "timed out" in rest.lower():
            hops.append({"n": n, "ip": ips[-1] if ips else None, "ms": float(ms.group(1).lstrip("<")) if ms else None})
    return hops


def last_hop(hops: List[dict], target: str) -> Optional[str]:
    """The last router that answered before the target (the gateway of its subnet); None when the target is the first hop (on-link) or nothing answered."""
    seen = [h["ip"] for h in hops if h["ip"] and h["ip"] != target]
    return seen[-1] if seen else None


async def trace(ip: str, max_hops: int = MAX_HOPS, timeout: float = 45.0) -> dict:
    """{"target", "hops": [...], "reached": bool, "via": last router | None}; `error` instead of hops when the tool is missing / fails."""
    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "500", ip]
        enc = "oem"
    elif shutil.which("traceroute"):
        cmd, enc = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", ip], "utf-8"
    elif shutil.which("tracepath"):
        cmd, enc = ["tracepath", "-n", "-m", str(max_hops), ip], "utf-8"
    else:
        return {"target": ip, "hops": [], "reached": False, "via": None, "error": "no traceroute tool installed"}
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        data, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return {"target": ip, "hops": [], "reached": False, "via": None, "error": "timed out"}
    except Exception as e:
        return {"target": ip, "hops": [], "reached": False, "via": None, "error": f"{type(e).__name__}: {e}"}
    hops = parse(data.decode(enc, errors="replace"))
    return {"target": ip, "hops": hops, "reached": any(h["ip"] == ip for h in hops), "via": last_hop(hops, ip)}
