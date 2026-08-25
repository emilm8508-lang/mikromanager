"""
Groups every host the scanner already knows about into simple categories
for the "Inwentarz" page — a lightweight classification pass over data
services/vuln_scan.py and the device scanner already collected. Runs no
new scanning of its own.

Rules (agreed with the user):
  - A host with a Device row whose vendor is confirmed Mikrotik or Cisco
    SB (switch/AP/router — the device scanner's own definitive signature,
    see services/scanner.py's is_mikrotik_def/is_cisco_sb) is a "network"
    device. Deliberately NOT "generic-snmp"/"unknown" vendor Device rows —
    those are printers, iDRACs, and other SNMP-answering peripherals that
    happened to get a Device row too (see services/scanner.py's vendor
    detection), not the network infrastructure this group is for.
  - Otherwise, classified by which "this looks like a server, not just an
    ordinary desktop" port is open — SSH (22) for Linux, SMB (445) or RDP
    (3389) for Windows. Chosen deliberately over trying to distinguish
    "server edition" from "desktop edition" purely from a passive banner
    grab (unreliable without logging in) — these are the network-exposed
    services an ordinary, non-server workstation wouldn't normally have
    open at all.
  - Anything else (no server-like port open) is only included if it has
    at least one active vulnerability finding tied to it — otherwise it's
    just noise for this view, per the user's explicit "don't bother
    listing an ordinary computer unless it's actually vulnerable" request.
"""
from typing import List
from sqlalchemy import select

from models.database import SessionLocal, Device, VulnHost, VulnService, VulnPackage, VulnFinding, LinuxHost, WindowsHost

_NETWORK_VENDORS = {"mikrotik", "cisco-sb"}
_LINUX_PORT = 22
_WINDOWS_PORTS = {445, 3389}


def _sort_key(entry: dict):
    try:
        return [int(p) for p in entry["ip"].split(".")]
    except ValueError:
        return [entry["ip"]]


def build_inventory() -> dict:
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        vuln_hosts = db.execute(select(VulnHost)).scalars().all()
        services = db.execute(select(VulnService)).scalars().all()
        packages = db.execute(select(VulnPackage)).scalars().all()
        findings = db.execute(select(VulnFinding)).scalars().all()
        linux_hosts = db.execute(select(LinuxHost)).scalars().all()
        windows_hosts = db.execute(select(WindowsHost)).scalars().all()

    finding_pvs = {(f.product, f.version) for f in findings}
    hosts_by_id = {h.id: h for h in vuln_hosts}
    linux_by_ip = {h.ip: h for h in linux_hosts}
    windows_by_ip = {h.ip: h for h in windows_hosts}

    # Same (product, version) -> "does a cached CVE finding exist for this"
    # matching services/vuln_scan.py's own findings pipeline relies on —
    # just tallying a count per IP here rather than building the full
    # finding objects api/vuln_scan.py's _build_findings does.
    findings_count_by_ip: dict = {}
    for s in services:
        if s.product and s.version and (s.product, s.version) in finding_pvs:
            host = hosts_by_id.get(s.host_id)
            if host:
                findings_count_by_ip[host.ip] = findings_count_by_ip.get(host.ip, 0) + 1
    for p in packages:
        if (p.name, p.version) in finding_pvs:
            host = hosts_by_id.get(p.host_id)
            if host:
                findings_count_by_ip[host.ip] = findings_count_by_ip.get(host.ip, 0) + 1
    for d in devices:
        if d.ros_version:
            product = "MikroTik RouterOS" if d.vendor == "mikrotik" else f"{d.vendor} {d.model or ''}".strip()
            if (product, d.ros_version) in finding_pvs:
                findings_count_by_ip[d.ip] = findings_count_by_ip.get(d.ip, 0) + 1

    services_by_host: dict = {}
    for s in services:
        services_by_host.setdefault(s.host_id, []).append(s)

    network: List[dict] = [{
        "ip": d.ip, "name": d.identity or d.name, "model": d.model,
        "vendor": d.vendor, "version": d.ros_version,
        "findings_count": findings_count_by_ip.get(d.ip, 0),
    } for d in devices if (d.vendor or "").lower() in _NETWORK_VENDORS]

    device_ips = {d.ip for d in devices}
    windows: List[dict] = []
    linux: List[dict] = []
    other: List[dict] = []
    for h in vuln_hosts:
        if h.ip in device_ips:
            continue  # already covered by the network group (or excluded from it deliberately)
        ports = sorted({s.port for s in services_by_host.get(h.id, [])})
        lh = linux_by_ip.get(h.ip)
        wh = windows_by_ip.get(h.ip)
        entry = {
            "ip": h.ip,
            "hostname": lh.hostname if lh else (wh.hostname if wh else None),
            "os": lh.distro_pretty if lh else (wh.os_name if wh else None),
            "ports": ports,
            "findings_count": findings_count_by_ip.get(h.ip, 0),
        }
        if _LINUX_PORT in ports:
            linux.append(entry)
        elif _WINDOWS_PORTS & set(ports):
            windows.append(entry)
        elif entry["findings_count"] > 0:
            other.append(entry)
        # else: an ordinary workstation with no server-like port open and
        # no known vulnerability — deliberately excluded from this view.

    return {
        "network": sorted(network, key=_sort_key),
        "windows": sorted(windows, key=_sort_key),
        "linux": sorted(linux, key=_sort_key),
        "other": sorted(other, key=_sort_key),
    }
