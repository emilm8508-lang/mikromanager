"""
The decisions of the NetFlow detectors that do not need the collector's state (stage 5 of docs/plan-jakosc-danych.md):

  initiator()          which side of a flow opened the connection: the TCP flags first (a SYN without an ACK opened it, a refusal - RST
                       without SYN - never did), the ports only when the flags do not say. Seen in production: "192.168.0.2 tried 263
                       ports on 172.234.162.56" - 192.168.0.2 is the WAN address of mcprojekt's MC-R1, and those were its RST answers
                       to an inbound scan, read as outgoing because the scanned port was higher than the scanner's
  scanner exceptions   per client: a source (address or network) allowed to scan, on which ports, in which hours, how many hosts at most.
                       Inside its scope the scan is not alerted; beyond it, it is - with what went beyond. Seen: mcprojekt's TECHSERVICE
                       (192.168.2.21), sanmed's RDP (192.168.1.38), aluplasti's check-mk (192.168.1.102) every ~6 h
  regular()            a source whose scans come at a steady rhythm: offered as an exception, never added by itself
  not_beacon_target()  broadcast / multicast and the discovery protocols of devices (Sentinel 1947, Ubiquiti 10001, MikroTik MNDP 5678,
                       WS-Discovery, SSDP, mDNS ...) are no "outside address" - seen: 255.255.255.255:1947 and :10001 as beacons
  cloud()              the owner of a destination names a big cloud / CDN (Google, Microsoft, Amazon, Akamai, Cloudflare, Tencent ...):
                       a beacon to it is low, unless the same host also scans

Pure: backend/tests/test_netflow_rules.py.
"""
import ipaddress
import re
import statistics
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

SYN, RST, ACK = 0x02, 0x04, 0x10
DISCOVERY_PORTS = {1947, 10001, 8002, 5678, 3702, 1900, 5353, 5355, 137, 138, 427, 6667, 48899, 9999, 20002, 32414}
_CLOUD = re.compile(r"google|microsoft|azure|amazon|aws|akamai|cloudflare|fastly|tencent|alibaba|apple|facebook|meta platforms|"
                    r"oracle cloud|digitalocean|ovh|hetzner|linode|edgecast|limelight|zscaler|cdn77|bunny", re.I)


def initiator(proto: int, flags: int, sport: int, dport: int) -> Optional[bool]:
    """True: the flow's source opened the connection; False: it answered; None: nothing to tell (not TCP / UDP with ports)."""
    if proto not in (6, 17) or not sport or not dport:
        return None
    if proto == 6 and flags:
        if flags & SYN and not flags & ACK:
            return True                                    # only the first packet: a connection attempt
        if flags & RST and not flags & SYN:
            return False                                   # a refusal (or the end of something it did not open)
    return sport >= dport                                  # the side with the higher (client) port opened it


def not_beacon_target(ip: str, dport: int) -> bool:
    if dport in DISCOVERY_PORTS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    # a directed broadcast of a local network is local anyway; a public x.x.x.255 can be a real host, so only the limited broadcast here
    return a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255"


def cloud(owner: Optional[str]) -> Optional[str]:
    m = _CLOUD.search(owner or "")
    return m.group(0) if m else None


# ── scanner exceptions ───────────────────────────────────────────────────────

def _ports(spec) -> List[Tuple[int, int]]:
    """"22,80,443,8000-8100" or [22, "1-1024"] -> [(lo, hi)]; empty = all ports."""
    items = spec if isinstance(spec, list) else str(spec or "").split(",")
    out = []
    for it in items:
        s = str(it).strip()
        if not s:
            continue
        lo, _, hi = s.partition("-")
        a, b = int(lo), int(hi or lo)
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"bad port range: {s}")
        out.append((a, b))
    return out


def _hours(spec: Optional[str]) -> Optional[Tuple[int, int]]:
    """"01:00-05:00" -> (60, 300) minutes of the day; None = any time."""
    if not spec:
        return None
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*", str(spec))
    if not m:
        raise ValueError(f"bad hours: {spec} (HH:MM-HH:MM)")
    a, b = int(m.group(1)) * 60 + int(m.group(2)), int(m.group(3)) * 60 + int(m.group(4))
    if a >= 1440 or b > 1440:
        raise ValueError(f"bad hours: {spec}")
    return a, b


def clean_exceptions(items) -> List[dict]:
    """Validated scanner exceptions: [{source, ports, hours, max_hosts, rules, note}]. Raises ValueError."""
    out = []
    for e in items or []:
        if not isinstance(e, dict):
            raise ValueError("an exception is an object")
        src = str(e.get("source") or "").strip()
        try:
            net = ipaddress.ip_network(src, strict=False)
        except ValueError:
            raise ValueError(f"source must be an address or a network: {src}")
        if net.num_addresses > 256:
            raise ValueError(f"a scanner exception covers at most a /24: {src}")
        ports = _ports(e.get("ports"))
        _hours(e.get("hours"))
        mh = e.get("max_hosts")
        if mh is not None and not (isinstance(mh, int) and 1 <= mh <= 65536):
            raise ValueError("max_hosts is 1-65536")
        rules = [r for r in (e.get("rules") or ["net.portscan"]) if r in ("net.portscan", "net.lateral")]
        out.append({"source": str(net) if net.num_addresses > 1 else src, "ports": ",".join(f"{a}-{b}" if a != b else str(a) for a, b in ports),
                    "hours": e.get("hours") or None, "max_hosts": mh, "rules": rules or ["net.portscan"], "note": str(e.get("note") or "")[:200]})
    if len(out) > 50:
        raise ValueError("at most 50 scanner exceptions")
    return out


def check_exception(exceptions: Iterable[dict], rule: str, src: str, ports: Iterable[int], hosts: int, when: datetime) -> Tuple[Optional[dict], List[str]]:
    """(the exception covering this scan, what of it is beyond the exception's scope). (None, []) when no exception names the source;
    (exc, []) inside the scope - not alerted; (exc, [reasons]) beyond it - alerted, saying why."""
    try:
        a = ipaddress.ip_address(src)
    except ValueError:
        return None, []
    for e in exceptions or []:
        if rule not in (e.get("rules") or ["net.portscan"]):
            continue
        if a not in ipaddress.ip_network(e["source"], strict=False):
            continue
        beyond = []
        allowed = _ports(e.get("ports"))
        if allowed:
            extra = sorted(p for p in set(ports) if not any(lo <= p <= hi for lo, hi in allowed))
            if extra:
                beyond.append(f"ports outside the exception: {', '.join(map(str, extra[:10]))}{' ...' if len(extra) > 10 else ''}")
        if e.get("max_hosts") and hosts > e["max_hosts"]:
            beyond.append(f"{hosts} hosts, the exception allows {e['max_hosts']}")
        hrs = _hours(e.get("hours"))
        if hrs:
            m = when.hour * 60 + when.minute
            inside = hrs[0] <= m < hrs[1] if hrs[0] <= hrs[1] else (m >= hrs[0] or m < hrs[1])
            if not inside:
                beyond.append(f"at {when.strftime('%H:%M')}, the exception allows {e['hours']}")
        return e, beyond
    return None, []


def regular(times: List[float], min_count: int = 4, max_cv: float = 0.2, min_span_h: float = 24.0, fit: float = 0.8) -> Optional[dict]:
    """{"every_h", "cv", "count", "span_h", "fit"} when the times come at a steady interval (a scheduled scanner), else None.
    3.66: the rhythm is the median gap and a gap of two or three rhythms counts (a run missed - restarts, a quiet NetFlow export - broke
    the plain spread before: no suggestion anywhere although check-mk scanned every 6 h for a week); a gap fits within 10 % of the rhythm
    (at least 10 minutes), `fit` of them have to; the times have to span `min_span_h` (one scan, or one afternoon, is no rhythm)."""
    ts = sorted(times)
    if len(ts) < min_count or ts[-1] - ts[0] < min_span_h * 3600:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    gaps = [g for g in gaps if g > 900]                    # two windows of one scan run are one run
    if len(gaps) < min_count - 1:
        return None
    m = statistics.median(gaps)
    if m < 3600:
        return None
    tol = max(600.0, 0.1 * m)
    ok, norm = 0, []
    for g in gaps:
        k = max(1, round(g / m))
        if k <= 3 and abs(g - k * m) <= tol * k:
            ok += 1
            norm.append(g / k)
    if not norm or ok / len(gaps) < fit:
        return None
    mean = statistics.mean(norm)
    cv = statistics.pstdev(norm) / mean if mean else 1.0
    if cv > max_cv:
        return None
    return {"every_h": round(mean / 3600, 1), "cv": round(cv, 2), "count": len(ts), "span_h": round((ts[-1] - ts[0]) / 3600, 1),
            "fit": round(ok / len(gaps), 2)}


def common_ports(port_lists: List[List[int]], min_share: float = 0.5, cap: int = 50) -> Tuple[List[int], float]:
    """The ports in at least `min_share` of the scans, and how alike the scans' port lists are (mean Jaccard of neighbours, 0..1)."""
    sets = [set(p) for p in port_lists if p]
    if not sets:
        return [], 0.0
    count: Dict[int, int] = {}
    for s in sets:
        for p in s:
            count[p] = count.get(p, 0) + 1
    ports = sorted(p for p, c in count.items() if c >= min_share * len(sets))[:cap]
    sims = [len(a & b) / len(a | b) for a, b in zip(sets, sets[1:]) if a | b]
    return ports, round(statistics.mean(sims), 2) if sims else 1.0
