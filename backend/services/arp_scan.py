"""ARP scan of the networks the agent's computer is itself on: who answers an ARP request, whatever its firewall says.

A computer that drops every TCP probe still has to answer ARP - it cannot be on the network otherwise - so this finds the hosts the port probes
miss (a Windows workstation with its default firewall, a phone, an IoT thing) and reads their MAC address straight from the answer (-> maker from the
OUI table). Only for ranges that are on-link: ARP does not cross a router.

  Windows   SendARP of the IP Helper API (iphlpapi, via ctypes): a real ARP request and its answer - no driver, no administrator rights.
  Linux/macOS  an ARP request needs a raw socket (root); without it a datagram to every address makes the kernel resolve them by ARP and the
            neighbour table is read afterwards - the same result for the hosts that are there.

Nothing but ARP requests / one tiny datagram per address is sent."""
import asyncio
import ipaddress
import re
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

_WORKERS = 128


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw[:6])


def local_networks() -> List[ipaddress.IPv4Network]:
    """The IPv4 networks the computer has an address in (address + mask of every interface). Empty when it cannot tell."""
    out: List[ipaddress.IPv4Network] = []
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes
            size = wintypes.ULONG(0)
            ctypes.windll.iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
            buf = ctypes.create_string_buffer(size.value)
            if ctypes.windll.iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False) == 0:
                n = struct.unpack_from("<I", buf, 0)[0]
                for i in range(n):                       # MIB_IPADDRROW: addr, index, mask, bcast, reasm (DWORD x5), unused (WORD x2)
                    addr, _idx, mask = struct.unpack_from("<III", buf, 4 + i * 24)
                    ip, m = socket.inet_ntoa(struct.pack("<I", addr)), socket.inet_ntoa(struct.pack("<I", mask))
                    if not ip.startswith(("127.", "169.254.", "0.")) and m != "0.0.0.0":
                        out.append(ipaddress.ip_network(f"{ip}/{m}", strict=False))
        else:
            text = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
            for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", text):
                n = ipaddress.ip_interface(m.group(1)).network
                if not n.is_loopback and not n.is_link_local:
                    out.append(n)
    except Exception:
        return []
    return list(dict.fromkeys(out))


def on_link(net: ipaddress.IPv4Network, locals_: Optional[List[ipaddress.IPv4Network]] = None) -> bool:
    """True when the computer is itself in `net` (or `net` lies inside one of its networks): the range can be ARP-scanned."""
    for l in (local_networks() if locals_ is None else locals_):
        if net.overlaps(l):
            return True
    return False


def _send_arp_windows(ip: str) -> Optional[str]:
    import ctypes
    from ctypes import wintypes
    dest = struct.unpack("=I", socket.inet_aton(ip))[0]
    mac = ctypes.create_string_buffer(8)
    n = wintypes.ULONG(6)
    if ctypes.windll.iphlpapi.SendARP(dest, 0, mac, ctypes.byref(n)) == 0 and n.value == 6:
        m = _mac_str(mac.raw)
        return None if m in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") else m
    return None


def scan_sync(ips: List[str]) -> Dict[str, str]:
    """{ip: MAC} of the addresses that answered. Blocking: run it in an executor."""
    if sys.platform == "win32":
        with ThreadPoolExecutor(_WORKERS) as ex:
            return {ip: m for ip, m in zip(ips, ex.map(_send_arp_windows, ips)) if m}
    # without a raw socket: a datagram to each address makes the kernel resolve it by ARP; then the neighbour table is read
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        for ip in ips:
            try:
                s.sendto(b"\x00", (ip, 9))
            except OSError:
                pass
    finally:
        import time
        time.sleep(1.2)
        s.close()
    from services.lan_sweep import parse_neighbours
    try:
        text = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        text = ""
    want = set(ips)
    return {ip: m for ip, m in parse_neighbours(text).items() if ip in want}


async def scan(ips: List[str]) -> Dict[str, str]:
    """Async wrapper; never raises (a failure is an empty answer)."""
    try:
        return await asyncio.get_event_loop().run_in_executor(None, scan_sync, ips)
    except Exception as e:
        print(f"[arp_scan] failed: {type(e).__name__}: {e}")
        return {}
