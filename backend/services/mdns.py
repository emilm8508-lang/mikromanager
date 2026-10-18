"""Names and kinds of devices from mDNS / DNS-SD (Bonjour, Avahi) - what Apple devices, Chromecasts, printers, Linux hosts and many IoT things
announce about themselves, and what NetBIOS and reverse DNS never see.

One browse: a multicast query for the usual service types (the "unicast response" bit is set, so the answers come back to this socket), listened to
for a few seconds. Every answer is attributed to the address it came from: the host names in the SRV records (name.local), the service types seen
(_airplay._tcp, _ipp._tcp, _googlecast._tcp ...). Read-only and tiny - nothing is sent to a host but the standard multicast question. Pure
Python, no extra package."""
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

MDNS_ADDR = ("224.0.0.251", 5353)
SERVICES = ("_workstation._tcp", "_http._tcp", "_https._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_airplay._tcp", "_raop._tcp",
            "_googlecast._tcp", "_hap._tcp", "_homekit._tcp", "_smb._tcp", "_device-info._tcp", "_companion-link._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
            "_afpovertcp._tcp", "_spotify-connect._tcp", "_apple-mobdev2._tcp", "_airport._tcp", "_workstation._tcp", "_uscan._tcp", "_scanner._tcp")
# service types that say what the device is
APPLE_SERVICES = ("_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_apple-mobdev2._tcp", "_airport._tcp", "_afpovertcp._tcp")
PRINTER_SERVICES = ("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp")


def _name(labels: List[str]) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"


def build_query(names: Tuple[str, ...] = SERVICES) -> bytes:
    """One DNS message with a PTR question per service type (QU bit set: the answer may be unicast)."""
    qs = [("_services._dns-sd._udp.local",)] + [(f"{s}.local",) for s in dict.fromkeys(names)]
    body = b"".join(_name(q[0].split(".")) + struct.pack(">HH", 12, 0x8001) for q in qs)
    return struct.pack(">HHHHHH", 0, 0, len(qs), 0, 0, 0) + body


def _read_name(data: bytes, off: int) -> Tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(data) or hops > 40:
            return ".".join(labels), end
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped, hops = ptr, True, hops + 1
            continue
        labels.append(data[off + 1: off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def _service_of(name: str) -> Optional[str]:
    """"_ipp._tcp" out of "_ipp._tcp.local" or "Office Printer._ipp._tcp.local"; None for anything else (a host name, the meta name)."""
    labels = name.lower().split(".")
    if len(labels) >= 3 and labels[-1] == "local" and labels[-2] in ("_tcp", "_udp") and labels[-3].startswith("_") and labels[-3] != "_dns-sd":
        return f"{labels[-3]}.{labels[-2]}"
    return None


def parse_response(data: bytes) -> dict:
    """{"hosts": [name, ...], "services": [type, ...], "a": [ip, ...]} out of one mDNS message; {} when it is not an answer."""
    try:
        _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        if not flags & 0x8000:
            return {}
        off = 12
        for _ in range(qd):
            _n, off = _read_name(data, off)
            off += 4
        hosts, services, addrs = [], [], []
        for _ in range(an + ns + ar):
            name, off = _read_name(data, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off: off + 10])
            off += 10
            rdata = off
            off += rdlen
            if rtype == 12:                                    # PTR: a service type -> an instance, or the list of service types
                target, _ = _read_name(data, rdata)
                for n in (name, target):
                    sv = _service_of(n)
                    if sv:
                        services.append(sv)
            elif rtype == 33:                                   # SRV: the host that serves the instance
                host, _ = _read_name(data, rdata + 6)
                if host.lower().endswith(".local"):
                    hosts.append(host[:-len(".local")])
                sv = _service_of(name)
                if sv:
                    services.append(sv)
            elif rtype == 1 and rdlen == 4:                     # A: its own address
                addrs.append(socket.inet_ntoa(data[rdata: rdata + 4]))
                if name.lower().endswith(".local"):
                    hosts.append(name[:-len(".local")])
        return {"hosts": list(dict.fromkeys(hosts)), "services": list(dict.fromkeys(s for s in services if s.startswith("_"))), "a": addrs}
    except Exception:
        return {}


def browse(timeout: float = 3.0) -> Dict[str, dict]:
    """{ip: {"name": host name or None, "services": [...], "apple": bool, "printer": bool}} for every host that answered. Blocking."""
    out: Dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.bind(("", 0))
        s.settimeout(0.4)
        for _ in range(2):
            s.sendto(build_query(), MDNS_ADDR)
            time.sleep(0.05)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _port) = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            r = parse_response(data)
            if not r:
                continue
            e = out.setdefault(ip, {"name": None, "services": [], "apple": False, "printer": False})
            if r["hosts"] and not e["name"]:
                e["name"] = r["hosts"][0]
            for sv in r["services"]:
                if sv not in e["services"]:
                    e["services"].append(sv)
            e["apple"] = e["apple"] or any(x in APPLE_SERVICES for x in e["services"])
            e["printer"] = e["printer"] or any(x in PRINTER_SERVICES for x in e["services"])
    except OSError:
        pass
    finally:
        s.close()
    return out
