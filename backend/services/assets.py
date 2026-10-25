"""
The asset inventory — one list of every piece of equipment on the network, with a card per device.

Nothing here scans by itself. `refresh()` merges what the agent already knows into the `assets` table:

  Mikrotik / Cisco / SNMP devices (Device) · managed Linux and Windows hosts · Dell servers (iDRAC) · Hyper-V VMs ·
  the port scan (VulnHost / VulnService) · the DHCP leases and ARP tables of the routers (host_monitor.directory) — the
  last one is what shows devices no port scan reaches: printers, phones, anything with a lease.

Hosts are identified by address (key "ip:<ip>"; a VM without one by "vm:<guid>") and followed by MAC when the address
changes. What one source cannot tell, another fills in; a value found by a hardware scan (services/asset_scan.py, from
stage 2) is never overwritten by a weaker source. Where a credentialed scan is not possible the asset keeps whatever the
network told us (SNMP, DHCP/ARP, banners) and is marked scan level "passive" or "snmp".

Per asset the page also gets: the type, role (server / workstation), location (the label of the scan range its address
falls in, or one set by hand), OS lifecycle (services/asset_lifecycle.py), vulnerabilities (the same findings as the
Vulnerabilities page, per address) and the groups it belongs to (derived from type / role / scan level, plus tags added by
hand).
"""
import asyncio
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete

from models.database import (
    VulnDaily, SessionLocal, Asset, AssetPeripheral, Device, VulnHost, VulnService, VulnPackage, LinuxHost, WindowsHost, LinuxHostDisk,
    WindowsHostDisk, DellServer, HypervHost, HypervVM, ScanRange,
)
from services import asset_lifecycle, asset_scan

TYPES = ("windows", "linux", "network", "printer", "virtual", "server", "camera", "mobile", "monitor", "other")
# How old the routers' DHCP/ARP tables may be before an inventory rebuild logs in to every router again for them (each login is a
# line in the router's log); a button press always reads fresh ones.
DIRECTORY_MAX_AGE_SEC = int(os.environ.get("MIKROTIK_ASSET_DIRECTORY_SEC", "7200"))
REFRESH_SEC = max(120, int(os.environ.get("MIKROTIK_ASSET_REFRESH_SEC", "900")))
STALE_DAYS = 7                       # not seen for this long = inactive
VULN_HOST_MAX_AGE_DAYS = 30          # a scan result older than this no longer makes an asset on its own
PRUNE_AFTER_DAYS = 14                # a passive asset that no source lists any more and that holds nothing of the operator's goes after this
NEW_DAYS = 7
_PRINTER_PORTS = {9100, 631, 515}
_LOCAL_PRINTER_PORTS = ("USB", "LPT", "COM", "DOT4", "BTH")
_WINDOWS_PORTS = {445, 3389, 135, 5985, 5986}
_PRINTER_NAME = re.compile(r"printer|drukark|\bhp[0-9a-f]{4,}|brother|epson|canon|xerox|lexmark|kyocera|ricoh|konica|oki\b|samsung.?(?:m|c|x)\d|\bmfp\b", re.I)
_SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 1, "LOW": 0.5}
_SCAN_RANK = {"passive": 0, "snmp": 1, "credentialed": 2}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _jload(s: Optional[str], default):
    if not s:
        return default
    try:
        v = json.loads(s)
        return v if isinstance(v, type(default)) else default
    except Exception:
        return default


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _norm_mac(m: Optional[str]) -> Optional[str]:
    h = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def _ip_sort(ip: Optional[str]):
    try:
        return [int(p) for p in (ip or "").split(".")]
    except ValueError:
        return [999, 0, 0, 0]


def _locator(db):
    """ip -> the label of the most specific scan range containing it (or None)."""
    nets = []
    for r in db.execute(select(ScanRange)).scalars().all():
        try:
            nets.append((ipaddress.ip_network(r.cidr, strict=False), (r.label or r.cidr)))
        except ValueError:
            continue
    nets.sort(key=lambda x: -x[0].prefixlen)

    def locate(ip: Optional[str]) -> Optional[str]:
        try:
            a = ipaddress.ip_address(ip or "")
        except ValueError:
            return None
        return next((label for net, label in nets if a in net), None)
    return locate


def _guess_type(ports: set, name: Optional[str]) -> str:
    if name and _PRINTER_NAME.search(name):
        return "printer"
    if ports & _PRINTER_PORTS and not ports & (_WINDOWS_PORTS | {22}):
        return "printer"                           # 9100 is also node_exporter, 631 CUPS, 515 LPD of a PC: a computer with its own services is not a printer
    if ports & _WINDOWS_PORTS:
        return "windows"
    if 22 in ports:
        return "linux"
    return "other"


# ── Building the inventory from what the agent already knows ─────────────────

class _Rec(dict):
    """One asset as the sources describe it. Strong values (from a source that really knows) win over weak ones."""

    def put(self, strong: bool = False, **kw):
        for k, v in kw.items():
            if v in (None, "", [], {}):
                continue
            if k == "refs":
                self.setdefault("refs", {}).update(v)
            elif k == "seen":
                self["seen"] = max(self.get("seen") or v, v)
            elif k == "first":
                self["first"] = min(self.get("first") or v, v)
            elif k == "scan_level":
                if _SCAN_RANK[v] > _SCAN_RANK.get(self.get("scan_level", "passive"), 0):
                    self["scan_level"] = v
            elif strong or not self.get(k):
                self[k] = v


def _collect(directory: List[dict]) -> Dict[str, _Rec]:
    recs: Dict[str, _Rec] = {}

    def rec(ip: Optional[str], key: Optional[str] = None) -> _Rec:
        k = key or f"ip:{ip}"
        if k not in recs:
            recs[k] = _Rec(key=k, ip=ip)
        return recs[k]

    now = datetime.utcnow()
    with SessionLocal() as db:
        devices = db.execute(select(Device)).scalars().all()
        vuln_hosts = db.execute(select(VulnHost)).scalars().all()
        ports_by_host: Dict[int, set] = {}
        text_by_host: Dict[int, str] = {}
        for s in db.execute(select(VulnService)).scalars().all():
            ports_by_host.setdefault(s.host_id, set()).add(s.port)
            text_by_host[s.host_id] = f"{text_by_host.get(s.host_id, '')} {s.product or ''} {s.service_name or ''} {(s.banner_raw or '')[:200]}"
        linux = db.execute(select(LinuxHost)).scalars().all()
        windows = db.execute(select(WindowsHost)).scalars().all()
        dell = db.execute(select(DellServer)).scalars().all()
        vms = db.execute(select(HypervVM, HypervHost, WindowsHost).join(HypervHost, HypervVM.hyperv_host_id == HypervHost.id)
                         .join(WindowsHost, HypervHost.windows_host_id == WindowsHost.id)).all()
        windows_by_id = {w.id: w for w in windows}
        host_assets = {a.id: a for a in db.execute(select(Asset)).scalars().all()}
        monitors = db.execute(select(AssetPeripheral).where(AssetPeripheral.kind.in_(("monitor", "printer")))).scalars().all()

    # weakest first: DHCP/ARP, then the port scan
    for e in directory:
        if not e.get("ip"):
            continue
        r = rec(e["ip"])
        r.put(name=e.get("name") or e.get("comment"), mac=_norm_mac(e.get("mac")), seen=now, ttl=e.get("ttl"), apple=e.get("apple"), via=e.get("via"), hops=e.get("hops"))
    ports_by_ip: Dict[str, set] = {}
    text_by_ip: Dict[str, str] = {}
    stale_scan = now - timedelta(days=VULN_HOST_MAX_AGE_DAYS)
    for h in vuln_hosts:
        if h.last_scan_at is not None and h.last_scan_at < stale_scan and not h.device_id and not h.credential_id:
            continue                                    # left behind by a scan of a range that is gone: not a device on the network now
        ports = ports_by_host.get(h.id, set())
        ports_by_ip[h.ip] = ports
        text_by_ip[h.ip] = text_by_host.get(h.id, "")
        r = rec(h.ip)
        r.put(refs={"vuln_host_id": h.id}, seen=h.last_scan_at, scan_level="credentialed" if h.credential_id else "passive")
    for ip, ports in ports_by_ip.items():
        r = recs[f"ip:{ip}"]
        r.put(asset_type=_guess_type(ports, r.get("name")))
    sweep_ports = {e["ip"]: set(e.get("ports") or []) for e in directory if e.get("ip") and "sweep" in (e.get("sources") or [])}
    hints = {e["ip"]: e.get("hint") for e in directory if e.get("ip") and e.get("hint")}
    for r in recs.values():
        ip = r.get("ip")
        allp = (ports_by_ip.get(ip) or set()) | sweep_ports.get(ip, set())
        if not r.get("asset_type") or (r["asset_type"] == "other" and allp):
            kind = _guess_type(allp, r.get("name"))
            r["asset_type"] = "windows" if kind == "other" and hints.get(ip) == "windows" else "printer" if kind == "other" and hints.get(ip) == "printer" else kind
        if r["asset_type"] == "windows" and not r.get("role"):
            r["role"] = "workstation"                    # a Windows host nobody classified: most are workstations; the operator can change it
        # What the network card and the host name give away, for the devices nothing else could classify
        from services import oui
        c = oui.classify(r.get("mac"), r.get("name"))
        if c["vendor"]:
            r["oui_vendor"] = c["vendor"]
        if r["asset_type"] == "other" and c["type"] in ("printer", "camera", "mobile", "network", "virtual"):
            r["asset_type"] = c["type"]

    for d in devices:
        r = rec(d.ip)
        vendor = (d.vendor or "").lower()
        ports = ports_by_ip.get(d.ip, set())
        if vendor == "mikrotik":
            kind, maker = "network", "MikroTik"
        elif vendor.startswith("cisco"):
            kind, maker = "network", "Cisco"
        else:
            kind, maker = ("printer" if ports & _PRINTER_PORTS else "other"), None
        r.put(True, asset_type=kind, role=None)
        r.put(True, name=d.identity or d.name, model=d.model or d.board_name)
        r.put(manufacturer=maker, mac=_norm_mac(d.mac), refs={"device_id": d.id}, seen=d.last_seen)
        if d.ros_version and vendor == "mikrotik":
            r.put(True, os_name="RouterOS", os_version=d.ros_version)
        r.put(scan_level="credentialed" if d.credential_id else "snmp" if d.has_snmp else "passive")

    for h in linux:
        r = rec(h.ip)
        r.put(True, asset_type="linux", role="server", name=h.hostname, os_name=h.distro_pretty, os_version=h.distro_version)
        r.put(refs={"linux_host_id": h.id}, seen=h.last_seen_at, first=h.first_seen_at, scan_level="credentialed" if h.managed else "passive")
    for h in windows:
        r = rec(h.ip)
        r.put(True, asset_type="windows", role="workstation" if h.host_type == "workstation" else "server", name=h.hostname,
              os_name=h.os_name, os_version=h.os_version, manufacturer=None)
        r.put(refs={"windows_host_id": h.id}, seen=h.last_seen_at, first=h.first_seen_at, scan_level="credentialed" if h.managed else "passive")
        if h.system_model and "virtual" in h.system_model.lower():
            r.put(True, asset_type="virtual")
        elif h.system_model:
            r.put(model=h.system_model)

    for s in dell:
        linked = windows_by_id.get(s.windows_host_id) if s.windows_host_id else None
        if linked and f"ip:{linked.ip}" in recs:
            r = recs[f"ip:{linked.ip}"]            # same machine: its hardware facts go onto the OS host
        elif s.idrac_ip:
            r = rec(s.idrac_ip)
            r.put(True, asset_type="server", role="server", name=s.name)
        else:
            continue
        maker = {"dell": "Dell", "hp": "HP", "fujitsu": "Fujitsu", "lenovo": "Lenovo"}.get((s.vendor or "dell").lower(), (s.vendor or "").capitalize() or None)
        r.put(True, manufacturer=maker, model=s.model, serial=s.service_tag)
        r.put(refs={"dell_server_id": s.id}, seen=s.last_check_at)

    for vm, hv, host in vms:
        ips = _jload(vm.ips, [])
        ip = ips[0] if ips else None
        key = f"ip:{ip}" if ip else (f"vm:{vm.vm_guid}" if vm.vm_guid else f"vm:{hv.id}:{vm.name}")
        r = rec(ip, key)
        r.put(True, asset_type="virtual", name=vm.name)
        r.put(manufacturer="Microsoft Hyper-V", model=f"Generation {vm.generation}" if vm.generation else None,
              refs={"hyperv_vm_id": vm.id}, seen=vm.last_seen_at, first=vm.first_seen_at, scan_level="credentialed")
        r.setdefault("host_name", host.hostname or host.ip)
    _collect_attached(recs, monitors, host_assets)
    _classify(recs, text_by_ip)
    return recs


def _ipv4(x: Optional[str]) -> Optional[str]:
    import ipaddress
    try:
        a = ipaddress.IPv4Address((x or "").strip())
    except ValueError:
        return None
    return None if a.is_loopback or a.is_unspecified or a.is_multicast else str(a)


def _classify(recs: Dict[str, _Rec], text_by_ip: Optional[Dict[str, str]] = None) -> None:
    """The class of every device (gateway / router / switch / AP / Apple / Raspberry Pi / VM) - services/device_class.py - and the hints for
    embedded devices that are often left on a factory password - services/embedded_hints.py."""
    from services import device_class, embedded_hints
    try:
        from services import edge_discovery
        wan = set(edge_discovery.wan_capable_device_ids())
    except Exception:
        wan = set()
    for r in recs.values():
        refs = r.get("refs") or {}
        r["cls"] = device_class.classify(type=r.get("asset_type"), name=r.get("name"), manufacturer=r.get("manufacturer"), model=r.get("model"),
                                         os_name=r.get("os_name"), oui_vendor=r.get("oui_vendor"), wan_router=refs.get("device_id") in wan, apple_hint=bool(r.get("apple")))
        r["hints"] = embedded_hints.match(r.get("name"), r.get("model"), r.get("manufacturer"), r.get("os_name"), r.get("oui_vendor"), (text_by_ip or {}).get(r.get("ip") or ""))
        if r["cls"] == "raspberry" and "raspberry" not in r["hints"]:
            r["hints"].append("raspberry")


def _collect_attached(recs: Dict[str, _Rec], items: list, host_assets: Dict[int, Asset]) -> None:
    """The monitors and printers a credentialed scan found on a computer are assets of their own, tied to the computer.
    A monitor is identified by its serial number (maker + model + serial), so one moved to another computer stays one asset and
    follows its newest sighting; one without a readable serial is identified by the computer it was seen on. A printer that sits on a
    network address is the asset of that address (the same one the LAN discovery makes, so it is not doubled); a printer attached
    to the computer itself (USB / LPT) is an asset tied to the computer. Queues shared by a print server are only
    connections, not devices."""
    best: Dict[str, tuple] = {}
    seen_no_serial: Dict[tuple, int] = {}
    for p in sorted(items, key=lambda x: (x.asset_id, x.id)):
        host = host_assets.get(p.asset_id)
        if host is None:
            continue
        if p.kind == "printer":
            d = _jload(p.details, {})
            ip = _ipv4(d.get("address"))
            if ip:
                r = recs.setdefault(f"ip:{ip}", _Rec(key=f"ip:{ip}", ip=ip))
                if r.get("asset_type") in (None, "other"):
                    r["asset_type"] = "printer"
                r.put(name=p.name, model=p.model, first=host.first_seen_at, seen=p.last_seen_at)
                continue
            if d.get("network") or not (d.get("port") or "").upper().startswith(_LOCAL_PRINTER_PORTS):
                continue                              # a WSD / shared / unknown port is not a device attached to this computer
            key = f"prt:a{p.asset_id}|{(p.name or '').strip().casefold()}"
            best[key] = (p.last_seen_at or datetime.min, p, host)
            continue
        if p.serial:
            key = "mon:" + "|".join((x or "").strip().casefold() for x in (p.manufacturer, p.model, p.serial))
        else:
            n = seen_no_serial[(p.asset_id, p.model)] = seen_no_serial.get((p.asset_id, p.model), 0) + 1
            key = f"mon:a{p.asset_id}|{(p.model or '').strip().casefold()}|{n}"
        stamp = p.last_seen_at or datetime.min
        if key not in best or stamp >= best[key][0]:
            best[key] = (stamp, p, host)
    for key, (stamp, p, host) in best.items():
        r = recs.setdefault(key, _Rec(key=key, ip=None))
        d = _jload(p.details, {})
        if p.kind == "printer":
            r.put(True, asset_type="printer", name=p.name, model=p.model)
            r.put(refs={"printer_of": host.id}, scan_level="credentialed", seen=p.last_seen_at, first=host.first_seen_at,
                  host_name=host.name or host.ip, extra={"printer_port": d} if d else None)
            continue
        r.put(True, asset_type="monitor", name=p.name or p.model or "Monitor", manufacturer=p.manufacturer, model=p.model, serial=p.serial)
        r.put(refs={"monitor_of": host.id}, scan_level="credentialed", seen=p.last_seen_at, first=host.first_seen_at,
              host_name=host.name or host.ip, extra={"monitor": d} if d else None)


def _prune(db, recs: Dict[str, _Rec], now: datetime) -> int:
    """Drops the assets that nothing lists any more and that hold nothing of the operator's: only a port-scan result behind them (whose
    host is gone, or not scanned for PRUNE_AFTER_DAYS), no scan, no notes / tags / overrides. What somebody managed or edited stays."""
    live_hosts = {i for i, in db.execute(select(VulnHost.id)).all()}
    cutoff = now - timedelta(days=PRUNE_AFTER_DAYS)
    doomed = []
    for a in db.execute(select(Asset)).scalars().all():
        if a.key in recs or a.key.startswith("vm:"):
            continue
        refs = _jload(a.refs, {})
        if a.key.startswith(("mon:", "prt:")) and not (a.notes or _jload(a.manual_groups, []) or a.location_override):
            doomed.append(a.id)                   # the computer no longer reports this monitor (disconnected, or moved and rescanned)
            continue
        if any(k != "vuln_host_id" and v for k, v in refs.items()):
            continue
        d = _jload(a.details, {})
        if (a.notes or _jload(a.manual_groups, []) or a.location_override or d.get("_over") or a.scan_level != "passive" or a.last_scan_at):
            continue
        orphan = refs.get("vuln_host_id") is not None and refs["vuln_host_id"] not in live_hosts
        if orphan or (a.last_seen_at or a.first_seen_at) < cutoff:
            doomed.append(a.id)
    for i in range(0, len(doomed), 500):
        chunk = doomed[i:i + 500]
        db.execute(delete(AssetPeripheral).where(AssetPeripheral.asset_id.in_(chunk)).execution_options(synchronize_session=False))
        db.execute(delete(Asset).where(Asset.id.in_(chunk)).execution_options(synchronize_session=False))
    return len(doomed)


def _save(recs: Dict[str, _Rec], force_baseline: bool = False) -> dict:
    """Upserts the records. The very first population treats everything as already known, so "new assets" only counts
    what appears afterwards; so does the first LAN discovery (`force_baseline`), which finds every computer at once."""
    now = datetime.utcnow()
    created = updated = 0
    with SessionLocal() as db:
        baseline = force_baseline or db.execute(select(Asset.id).limit(1)).first() is None
        existing = db.execute(select(Asset)).scalars().all()
        by_key = {a.key: a for a in existing}
        by_mac = {a.mac: a for a in existing if a.mac}
        by_ref = {}
        for a in existing:                                    # the managed object behind an asset outlives its address
            for k, v in _jload(a.refs, {}).items():
                if k in ("linux_host_id", "windows_host_id", "device_id", "hyperv_vm_id") and isinstance(v, int):
                    by_ref.setdefault((k, v), a)
        used = set()
        for r in recs.values():
            a = by_key.get(r["key"])
            if a is None and r.get("mac") and r["mac"] in by_mac and by_mac[r["mac"]].id not in used and not by_mac[r["mac"]].key.startswith("vm:"):
                a = by_mac[r["mac"]]                  # the same device on a new address
                by_key.pop(a.key, None)
                a.key = r["key"]
                by_key[a.key] = a
            if a is None:
                for k, v in (r.get("refs") or {}).items():
                    cand = by_ref.get((k, v))
                    if cand is not None and cand.id not in used and cand.key != r["key"] and not cand.key.startswith("vm:"):
                        a = cand                              # same Linux / Windows host, router or VM, new address: re-key, no second asset
                        by_key.pop(a.key, None)
                        a.key = r["key"]
                        by_key[a.key] = a
                        break
            if a is None:
                if baseline:     # everything found by the very first population counts as already known
                    first = min(r.get("first") or (now - timedelta(days=365)), now - timedelta(days=NEW_DAYS + 1))
                else:
                    first = r.get("first") or now
                a = Asset(key=r["key"], first_seen_at=first)
                db.add(a)
                db.flush()
                created += 1
            else:
                updated += 1
            used.add(a.id)
            if r.get("ip"):
                a.ip = r["ip"]
            if r.get("oui_vendor") and not a.manufacturer:
                a.manufacturer = r["oui_vendor"]               # only fills a gap: a scan or a credential knows better than the MAC prefix
            for f in ("mac", "name", "manufacturer", "model", "serial", "os_name", "os_version", "role"):
                if r.get(f) and not (f == "role" and "role" in _jload(a.details, {}).get("_over", {})):
                    setattr(a, f, r[f])
            over = _jload(a.details, {}).get("_over", {})
            if r.get("asset_type") and "type" not in over and (r["asset_type"] != "other" or not a.asset_type or a.asset_type == "other"):
                a.asset_type = r["asset_type"]
            old = _jload(a.refs, {})
            old.update(r.get("refs", {}))
            a.refs = json.dumps(old)
            if r.get("host_name") or r.get("extra") or r.get("cls") or r.get("ttl") or r.get("hints") is not None or r.get("via"):
                d = _jload(a.details, {})
                if r.get("host_name"):
                    d["host"] = r["host_name"]
                d.update(r.get("extra") or {})
                if r.get("cls"):
                    d["_class"] = r["cls"]
                elif "_class" in d:
                    d.pop("_class")                              # what said so no longer does
                if r.get("ttl"):
                    d["_ttl"] = int(r["ttl"])
                if r.get("via"):
                    d["_via"], d["_hops"] = r["via"], r.get("hops")        # the gateway of a host in a routed range (traceroute)
                if r.get("hints"):
                    d["_hints"] = r["hints"]
                else:
                    d.pop("_hints", None)
                a.details = json.dumps(d)
            level = r.get("scan_level", "passive")
            if _SCAN_RANK[level] > _SCAN_RANK.get(a.scan_level or "passive", 0) or not a.last_scan_at:
                a.scan_level = level
            a.last_seen_at = max(filter(None, [a.last_seen_at, r.get("seen")]), default=now)
        gone = _prune(db, recs, now)
        db.commit()
    if gone:
        print(f"[assets] removed {gone} asset(s) that nothing lists any more")
    return {"created": created, "updated": updated, "total": len(recs), "baseline": baseline, "pruned": gone}


_state = {"last_refresh": None, "running": False}


async def refresh(directory: bool = True, fresh: bool = False) -> dict:
    """Rebuild the inventory from the sources. Cheap (database only), apart from re-reading the routers' DHCP/ARP tables
    when they are stale."""
    if _state["running"]:
        return {"skipped": True}
    _state["running"] = True
    try:
        entries: List[dict] = []
        if directory:
            try:
                from services import host_monitor
                entries = await host_monitor.directory(refresh=fresh, max_age=None if fresh else DIRECTORY_MAX_AGE_SEC)
            except Exception as e:
                print(f"[assets] DHCP/ARP directory unavailable: {e}")
        sweep_entries = []
        try:
            from services import lan_sweep
            sweep_entries = lan_sweep.entries()
        except Exception as e:
            print(f"[assets] LAN sweep results unavailable: {e}")
        first_sweep = False
        if sweep_entries:
            from models.database import AssetScanSettings
            with SessionLocal() as db:
                row = db.get(AssetScanSettings, 1)
                first_sweep = row is None or row.sweep_baseline_at is None
        result = _save(_collect(entries + sweep_entries), force_baseline=first_sweep)
        if first_sweep:
            from models.database import AssetScanSettings
            with SessionLocal() as db:
                row = db.get(AssetScanSettings, 1) or AssetScanSettings(id=1)
                row.sweep_baseline_at = datetime.utcnow()
                db.merge(row)
                db.commit()
        result["sources"] = {"routers": len(entries), "sweep": len(sweep_entries)}
        _state["last_refresh"] = datetime.utcnow()
        try:
            await record_vuln_day()
        except Exception as e:
            print(f"[assets] vulnerability history error: {e}")
        return result
    finally:
        _state["running"] = False


# ── Vulnerabilities per address (cached: the findings query is the expensive part) ──

_vuln_cache: dict = {"at": 0.0, "by_ip": {}}
_VULN_TTL = 120


async def _vulns_by_ip() -> Dict[str, List[dict]]:
    if time.time() - _vuln_cache["at"] > _VULN_TTL:
        try:
            from services import vuln_scan
            hosts = await vuln_scan.hosts_with_findings()
            _vuln_cache["by_ip"] = {h["ip"]: h["findings"] for h in hosts}
        except Exception as e:
            print(f"[assets] vulnerability lookup failed: {e}")
        _vuln_cache["at"] = time.time()
    return _vuln_cache["by_ip"]


async def record_vuln_day() -> None:
    """Keeps today's row of the vulnerability history up to date (called with every inventory rebuild; the last write of the day wins)."""
    by_ip = await _vulns_by_ip()
    tot = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assets = 0
    for findings in by_ip.values():
        c = _vuln_counts(findings)
        assets += 1 if c["total"] else 0
        for k in tot:
            tot[k] += c[k]
    day = datetime.utcnow().strftime("%Y-%m-%d")
    with SessionLocal() as db:
        row = db.get(VulnDaily, day) or VulnDaily(day=day)
        row.assets, row.critical, row.high, row.medium, row.low = assets, tot["critical"], tot["high"], tot["medium"], tot["low"]
        db.merge(row)
        db.commit()


def vuln_history(days: int = 90) -> List[dict]:
    since = (datetime.utcnow() - timedelta(days=max(1, min(days, 730)))).strftime("%Y-%m-%d")
    with SessionLocal() as db:
        rows = db.execute(select(VulnDaily).where(VulnDaily.day >= since).order_by(VulnDaily.day)).scalars().all()
        return [{"day": r.day, "assets": r.assets, "critical": r.critical, "high": r.high, "medium": r.medium, "low": r.low} for r in rows]


def _vuln_counts(findings: List[dict]) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if (f.get("status") or "open") in ("open", "in_progress"):
            sev = (f.get("severity") or "LOW").lower()
            c[sev if sev in c else "low"] += 1
    c["total"] = sum(c.values())
    return c


def _risk(findings: List[dict]) -> float:
    # a CVE that is being exploited in attacks (CISA KEV) counts for more than its CVSS says
    return sum(_SEV_WEIGHT.get(f.get("severity"), 0.5) + (3.0 if f.get("kev") else 0.0) for f in findings if (f.get("status") or "open") in ("open", "in_progress"))


# ── Reading ──────────────────────────────────────────────────────────────────

GROUP_LABELS = ("servers", "workstations", "virtual", "printers", "network", "credentialed")


def _groups(a: Asset) -> List[str]:
    g = []
    if a.role == "server" or a.asset_type == "server":
        g.append("servers")
    if a.role == "workstation":
        g.append("workstations")
    if a.asset_type == "virtual":
        g.append("virtual")
    if a.asset_type == "printer":
        g.append("printers")
    if a.asset_type == "network":
        g.append("network")
    if a.scan_level == "credentialed":
        g.append("credentialed")
    return g + [t for t in _jload(a.manual_groups, []) if t not in g]


def _attach(asset_id: int) -> Optional[dict]:
    """Where the asset is plugged in (switch + port), as the last map of the network says - see services/topology_map.py."""
    try:
        from services import topology_map
        return topology_map.attach_of(asset_id)
    except Exception:
        return None


def _row(a: Asset, locate, vulns: Dict[str, List[dict]], now: datetime) -> dict:
    fnd = vulns.get(a.ip or "", [])
    lc = asset_lifecycle.lifecycle(a.os_name, a.os_version)
    last = a.last_seen_at
    return {
        "id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "mac": a.mac, "type": a.asset_type, "role": a.role,
        "manufacturer": a.manufacturer, "model": a.model, "serial": a.serial, "os_name": a.os_name, "os_version": a.os_version,
        "location": a.location_override or locate(a.ip), "place": a.place, "attach": _attach(a.id), "groups": _groups(a), "scan_level": a.scan_level, "dclass": _jload(a.details, {}).get("_class"), "hints": _jload(a.details, {}).get("_hints") or [], "via": _jload(a.details, {}).get("_via"), "hops": _jload(a.details, {}).get("_hops"),
        "lifecycle": lc["status"], "lifecycle_product": lc["product"], "eol": lc["eol"],
        "vulns": _vuln_counts(fnd), "risk": round(_risk(fnd), 1),
        "first_seen_at": _iso(a.first_seen_at), "last_seen_at": _iso(last), "last_scan_at": _iso(a.last_scan_at),
        "active": bool(last and now - last < timedelta(days=STALE_DAYS)),
        "refs": {k: v for k, v in _jload(a.refs, {}).items() if isinstance(v, int)},       # which managed objects this asset is (host ids, device id, VM id)
    }


async def list_assets() -> List[dict]:
    try:
        from services import topology_map
        topology_map.kick()                      # the placement of the hosts comes from the map; it is refreshed in the background, never waited for
    except Exception:
        pass
    vulns = await _vulns_by_ip()
    now = datetime.utcnow()
    with SessionLocal() as db:
        locate = _locator(db)
        rows = [_row(a, locate, vulns, now) for a in db.execute(select(Asset)).scalars().all()]
    rows.sort(key=lambda r: (-r["risk"], _ip_sort(r["ip"])))
    return rows


async def summary() -> dict:
    rows = await list_assets()
    now = datetime.utcnow()
    count = lambda key_fn: sorted(_tally(rows, key_fn).items(), key=lambda kv: -kv[1])
    week_ago = now - timedelta(days=NEW_DAYS)
    days = [(now.date() - timedelta(days=d)) for d in range(NEW_DAYS - 1, -1, -1)]
    by_day = {d: 0 for d in days}
    new = 0
    for r in rows:
        fs = datetime.fromisoformat(r["first_seen_at"].rstrip("Z")) if r["first_seen_at"] else None
        if fs and fs >= week_ago:
            new += 1
            if fs.date() in by_day:
                by_day[fs.date()] += 1
    total_then = sum(1 for r in rows if not r["first_seen_at"] or datetime.fromisoformat(r["first_seen_at"].rstrip("Z")) < week_ago)
    vuln = {"assets": sum(1 for r in rows if r["vulns"]["total"]), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        for k in ("critical", "high", "medium", "low"):
            vuln[k] += r["vulns"][k]
    return {
        "total": len(rows), "total_7d_ago": total_then, "new_7d": new,
        "new_by_day": [{"day": d.isoformat(), "n": by_day[d]} for d in days],
        "by_type": [{"key": k, "n": n} for k, n in count(lambda r: r["type"])],
        "by_location": [{"name": k, "n": n} for k, n in count(lambda r: r["location"] or "")][:12],
        "by_lifecycle": {k: sum(1 for r in rows if r["lifecycle"] == k) for k in ("supported", "ending", "eol", "unknown")},
        "by_scan_level": {k: sum(1 for r in rows if r["scan_level"] == k) for k in ("credentialed", "snmp", "passive")},
        "inactive": sum(1 for r in rows if not r["active"]),
        "vulnerable": vuln,
        "top_risk": [r for r in rows if r["risk"] > 0][:8],
        "last_refresh": _iso(_state["last_refresh"]),
    }


MAX_PUBLIC_ROWS = 400


async def public_summary() -> dict:
    """What Central gets (as plaintext envelope metadata, no E2E key needed): the dashboard numbers and one compact row per active
    device, the most exposed first. Deliberately without serial numbers, MAC addresses, notes, tags and hardware details."""
    s = await summary()
    rows = [r for r in await list_assets() if r["active"]]
    shown = rows[:MAX_PUBLIC_ROWS]
    with SessionLocal() as db:
        lin = {h.id: h for h in db.execute(select(LinuxHost)).scalars().all()}
        win = {h.id: h for h in db.execute(select(WindowsHost)).scalars().all()}
        mik = {d.id for d in db.execute(select(Device)).scalars().all() if (d.vendor or "mikrotik").lower() == "mikrotik"}
        vmstate = {v.id: v.state for v in db.execute(select(HypervVM)).scalars().all()}
    out = []
    for r in shown:
        seen = datetime.fromisoformat(r["last_seen_at"].rstrip("Z")) if r["last_seen_at"] else None
        v = r["vulns"]
        row = {"id": r["id"], "n": r["name"], "ip": r["ip"], "t": r["type"], "r": r["role"], "mf": r["manufacturer"], "md": r["model"], "os": r["os_name"],
               "lc": r["lifecycle"], "v": [v["critical"], v["high"], v["medium"], v["low"]], "loc": r["location"], "sl": r["scan_level"],
               "seen": int((seen - datetime(1970, 1, 1)).total_seconds()) if seen else None}
        if r.get("place"):
            row["pl"] = r["place"]
        at = r.get("attach")
        if at:
            row["at"] = [at["to"], at.get("port"), at.get("vlan"), at.get("shared"), at["kind"]]        # switch, port, VLAN, other MACs on the port, how it is known
        # What Central may ask the agent to do with it (the same commands as on the server boards): only ids and flags, no details.
        refs = r["refs"]
        if refs.get("linux_host_id") in lin:
            h = lin[refs["linux_host_id"]]
            row["x"] = {"k": "linux", "id": h.id, "m": bool(h.managed), "u": h.upgradable_count, "rb": bool(h.reboot_required)}
        elif refs.get("windows_host_id") in win:
            h = win[refs["windows_host_id"]]
            row["x"] = {"k": "windows", "id": h.id, "m": bool(h.managed), "u": h.upgradable_count, "rb": bool(h.reboot_required), "ws": h.host_type == "workstation"}
        elif refs.get("device_id") in mik:
            row["x"] = {"k": "device", "id": refs["device_id"]}
        elif refs.get("hyperv_vm_id") in vmstate:
            row["x"] = {"k": "vm", "id": refs["hyperv_vm_id"], "st": vmstate[refs["hyperv_vm_id"]]}
        out.append(row)
    return {
        "summary": {k: s[k] for k in ("total", "total_7d_ago", "new_7d", "new_by_day", "by_type", "by_location", "by_lifecycle", "by_scan_level", "inactive", "vulnerable")},
        "rows": out, "truncated": len(rows) > MAX_PUBLIC_ROWS,
    }


def _tally(rows, key_fn) -> dict:
    out: dict = {}
    for r in rows:
        k = key_fn(r)
        out[k] = out.get(k, 0) + 1
    return out


def _hardware(db, a: Asset) -> dict:
    """Sections of the "Sprzęt" tab, assembled from what the source tables hold (plus anything a hardware scan stored)."""
    refs = _jload(a.refs, {})
    hw: dict = {}
    if refs.get("device_id"):
        d = db.get(Device, refs["device_id"])
        if d:
            hw["network_device"] = {k: v for k, v in {
                "vendor": d.vendor, "model": d.model, "board": d.board_name, "identity": d.identity, "architecture": d.architecture,
                "routeros": d.ros_version, "channel": d.ros_channel, "latest_routeros": d.latest_ros_version,
                "firmware": d.current_firmware, "firmware_available": d.upgrade_firmware, "uptime_sec": d.uptime_sec,
                "cpu_pct": d.cpu_load_pct, "mem_used_pct": d.mem_used_pct, "mem_total_bytes": d.mem_total_bytes,
                "disk_used_pct": d.disk_used_pct, "disk_total_bytes": d.disk_total_bytes, "temperature_c": d.temperature_c,
                "owner": d.owner, "criticality": d.criticality,
            }.items() if v is not None}
    if refs.get("linux_host_id"):
        h = db.get(LinuxHost, refs["linux_host_id"])
        if h:
            hw["host"] = {k: v for k, v in {"cpu_pct": h.cpu_used_pct, "mem_used_pct": h.mem_used_pct, "mem_total_bytes": h.mem_total_bytes,
                                            "package_manager": h.package_manager, "updates_pending": h.upgradable_count, "reboot_required": h.reboot_required}.items() if v is not None}
            hw["disks"] = [{"name": d.mount_point, "pct": d.pct, "total_bytes": d.total_bytes, "used_bytes": d.used_bytes}
                           for d in db.execute(select(LinuxHostDisk).where(LinuxHostDisk.host_id == h.id)).scalars().all()]
    if refs.get("windows_host_id"):
        h = db.get(WindowsHost, refs["windows_host_id"])
        if h:
            hw["host"] = {k: v for k, v in {"cpu_pct": h.cpu_used_pct, "mem_used_pct": h.mem_used_pct, "mem_total_bytes": h.mem_total_bytes,
                                            "domain": h.domain, "updates_pending": h.upgradable_count, "reboot_required": h.reboot_required,
                                            "system_model": h.system_model}.items() if v is not None}
            hw["disks"] = [{"name": d.drive_letter, "pct": d.pct, "total_bytes": d.total_bytes, "used_bytes": d.used_bytes}
                           for d in db.execute(select(WindowsHostDisk).where(WindowsHostDisk.host_id == h.id)).scalars().all()]
    if refs.get("dell_server_id"):
        s = db.get(DellServer, refs["dell_server_id"])
        if s:
            hw["server"] = {k: v for k, v in {"vendor": s.vendor, "model": s.model, "service_tag": s.service_tag, "bios": s.bios_version,
                                              "health": s.health_rollup, "power": s.power_state, "controller_ip": s.idrac_ip}.items() if v}
            hw["components"] = _jload(s.components_json, {}) if isinstance(_jload(s.components_json, {}), dict) else {}
    if refs.get("hyperv_vm_id"):
        v = db.get(HypervVM, refs["hyperv_vm_id"])
        if v:
            hw["vm"] = {k: x for k, x in {
                "state": v.state, "vcpu": v.vcpu_count, "generation": v.generation, "memory_assigned_bytes": v.memory_assigned_bytes,
                "dynamic_memory": v.dynamic_memory, "checkpoints": v.snapshot_count, "uptime_sec": v.uptime_sec, "heartbeat": v.heartbeat,
                "disks": _jload(v.disks, []), "switches": _jload(v.switches, []), "ips": _jload(v.ips, []),
            }.items() if x not in (None, [], "")}
    stored = _jload(a.details, {})
    for k, v in stored.items():
        if k in ("host", "_over") or (k == "disks" and hw.get("disks")):
            continue                                 # the live volume figures of the source tables stay fresher than the scan's
        hw[k] = v                                    # a hardware scan's own sections win
    return hw


async def get_asset(asset_id: int) -> Optional[dict]:
    vulns = await _vulns_by_ip()
    now = datetime.utcnow()
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return None
        locate = _locator(db)
        row = _row(a, locate, vulns, now)
        refs = _jload(a.refs, {})
        vh = db.get(VulnHost, refs["vuln_host_id"]) if refs.get("vuln_host_id") else None
        services = []
        software = 0
        if vh:
            services = [{"port": s.port, "proto": s.proto, "service": s.service_name, "product": s.product, "version": s.version}
                        for s in db.execute(select(VulnService).where(VulnService.host_id == vh.id).order_by(VulnService.port)).scalars().all()]
            software = len(db.execute(select(VulnPackage.id).where(VulnPackage.host_id == vh.id)).all())
        periph = [{"id": p.id, "kind": p.kind, "name": p.name, "manufacturer": p.manufacturer, "model": p.model, "serial": p.serial,
                   "details": _jload(p.details, {}), "last_seen_at": _iso(p.last_seen_at)}
                  for p in db.execute(select(AssetPeripheral).where(AssetPeripheral.asset_id == a.id)).scalars().all()]
        installed_on = []
        if a.asset_type == "printer" and a.ip:
            names = {x.id: x.name or x.ip for x in db.execute(select(Asset)).scalars().all()}
            for p in db.execute(select(AssetPeripheral).where(AssetPeripheral.kind == "printer")).scalars().all():
                if _jload(p.details, {}).get("address") == a.ip and p.asset_id in names and p.asset_id != a.id:
                    installed_on.append({"id": p.asset_id, "name": names[p.asset_id], "queue": p.name})
        if refs.get("monitor_of") or refs.get("printer_of"):
            host = db.get(Asset, refs.get("monitor_of") or refs.get("printer_of"))
            if host:
                installed_on.append({"id": host.id, "name": host.name or host.ip or host.key, "queue": None})
        for p in periph:
            addr = p["details"].get("address") if p["kind"] == "printer" else None
            if addr:
                tgt = db.execute(select(Asset).where(Asset.ip == addr)).scalars().first()
                if tgt and tgt.id != a.id:
                    p["details"] = {**p["details"], "asset_id": tgt.id, "asset_name": tgt.name or tgt.ip}
        row.update({
            "installed_on": installed_on, "override": _jload(a.details, {}).get("_over", {}), "notes": a.notes, "manual_groups": _jload(a.manual_groups, []), "location_override": a.location_override,
            "lifecycle_detail": asset_lifecycle.lifecycle(a.os_name, a.os_version), "refs": refs,
            "parent": _jload(a.details, {}).get("host"), "hardware": _hardware(db, a), "peripherals": periph, "services": services, "software_count": software,
            "scan": {"level": a.scan_level, "last_scan_at": _iso(a.last_scan_at), "status": a.last_scan_status, "error": a.last_scan_error,
                     "running": a.id in asset_scan.running_ids(), "available": bool(a.ip)},
        })
        return row


async def asset_vulnerabilities(asset_id: int) -> Optional[List[dict]]:
    vulns = await _vulns_by_ip()
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        ip = a.ip if a else None
    if a is None:
        return None
    return list(vulns.get(ip or "", []))


def asset_software(asset_id: int) -> Optional[List[dict]]:
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return None
        vh = db.get(VulnHost, _jload(a.refs, {}).get("vuln_host_id") or 0)
        if not vh:
            return []
        rows = db.execute(select(VulnPackage).where(VulnPackage.host_id == vh.id).order_by(VulnPackage.name)).scalars().all()
        return [{"name": p.name, "version": p.version, "last_seen": _iso(p.last_seen)} for p in rows][:5000]


def update_asset(asset_id: int, fields: dict) -> Optional[dict]:
    """Operator edits: name, location, notes and tags — kept across refreshes."""
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return None
        if "name" in fields:
            a.name = (fields["name"] or "").strip()[:128] or a.name
        if "location_override" in fields:
            a.location_override = (fields["location_override"] or "").strip()[:128] or None
        if "place" in fields:
            a.place = (fields["place"] or "").strip()[:128] or None
        if "notes" in fields:
            a.notes = (fields["notes"] or "").strip()[:2000] or None
        if "asset_type" in fields or "role" in fields:
            d = _jload(a.details, {})
            over = d.get("_over", {})
            if "asset_type" in fields:
                v = fields["asset_type"]
                if v in TYPES:
                    over["type"] = a.asset_type = v
                else:
                    over.pop("type", None)             # back to automatic: the next rebuild decides again
            if "role" in fields:
                v = fields["role"]
                if v in ("server", "workstation"):
                    over["role"] = a.role = v
                else:
                    over.pop("role", None)
            d["_over"] = over
            if not over:
                d.pop("_over")
            a.details = json.dumps(d)
        if "manual_groups" in fields:
            tags = []
            for t in fields["manual_groups"] or []:
                t = " ".join(str(t).split())[:40]
                if t and t not in tags and t not in GROUP_LABELS:
                    tags.append(t)
            a.manual_groups = json.dumps(tags[:20])
        db.commit()
    return {"ok": True}


_MANAGED_REFS = ("linux_host_id", "windows_host_id", "device_id", "hyperv_vm_id", "dell_server_id")


def delete_asset(asset_id: int) -> bool:
    """Forget an asset. The port-scan result behind it goes too (otherwise the next rebuild would bring the asset back at once); it
    comes back only if a source still reports the device - a router's DHCP / ARP entry, a managed host, a router."""
    return bool(delete_assets([asset_id])["deleted"])


def delete_assets(ids: List[int]) -> dict:
    """Deletes the assets; returns {"deleted": n, "managed": n} where `managed` counts the ones that a managed object (Linux / Windows
    host, router, Hyper-V VM, Dell server) stands behind - those are removed on their own pages and come back until then."""
    deleted = managed = 0
    ids = [i for i in dict.fromkeys(ids) if isinstance(i, int)]
    with SessionLocal() as db:
        for i in range(0, len(ids), 500):
            for a in db.execute(select(Asset).where(Asset.id.in_(ids[i:i + 500]))).scalars().all():
                refs = _jload(a.refs, {})
                if any(refs.get(k) for k in _MANAGED_REFS):
                    managed += 1
                vh = refs.get("vuln_host_id")
                if vh:
                    for m in (VulnService, VulnPackage):
                        db.execute(delete(m).where(m.host_id == vh).execution_options(synchronize_session=False))
                    db.execute(delete(VulnHost).where(VulnHost.id == vh).execution_options(synchronize_session=False))
                db.execute(delete(AssetPeripheral).where(AssetPeripheral.asset_id == a.id).execution_options(synchronize_session=False))
                db.delete(a)
                deleted += 1
        db.commit()
    return {"deleted": deleted, "managed": managed}


def set_types(ids: List[int], asset_type: str) -> int:
    """Gives the assets this type (an override: the automatic classification no longer changes it); "auto" removes the override."""
    n = 0
    for i in dict.fromkeys(ids):
        if isinstance(i, int) and update_asset(i, {"asset_type": asset_type}) is not None:
            n += 1
    return n


# ── Own loop ─────────────────────────────────────────────────────────────────

_task: Optional[asyncio.Task] = None


async def _loop():
    await asyncio.sleep(75)
    while True:
        try:
            await refresh()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[assets] refresh error: {e}")
        await asyncio.sleep(REFRESH_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None
