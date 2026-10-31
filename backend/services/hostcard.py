"""
The card of one host: everything the agent knows about it in one place (a configuration item, in ITIL terms).

The same machine is known to many parts of the application - the port scan, the inventory, the router / switch list, the Windows and Linux host lists, the BMC list, Hyper-V, the
vulnerability scan, the availability monitor, the SOC alerts, the TLS check, the configuration history, syslog, the network map, the maintenance windows, the response actions -
and until now each showed its own slice behind its own link. This module puts the slices together by the host's identity (its inventory asset, which the other tables are tied to by
address or by reference) and returns one structure the card page draws:

  * ci            what it is: class, type, vendor, model, serial, OS and its support status, owner, criticality, place, tags, first / last seen;
  * status        availability and 30-day uptime, maintenance, a health verdict with the reasons;
  * sources       where it is known (inventory, router list, Windows / Linux host, BMC, Hyper-V, vulnerability scan ...) with the link to each place;
  * alerts, vulnerabilities, tls, services, updates, resources, config, syslog, network, relationships (what it hangs on, what hangs on it, which business services it
    belongs to), response (blocks), access (credential and level), timeline (everything that happened to it, newest first).

Every section is built on its own: one that fails is reported in `errors` and the rest of the card still comes out. Read only; nothing is touched on the host.
"""
import json
import re
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import select, func

from models.database import (SessionLocal, Asset, Device, WindowsHost, LinuxHost, DellServer, HypervHost, HypervVM, VulnHost, VulnService, SocAlert, AvailState, AvailEvent,
                             BizService, ConfigCheck, ConfigSnapshot, SyslogEvent, TlsCheck, SoarAction, MaintenanceWindow, Credential, AssetPeripheral, MetricSeries, UpsTarget, DellServerSelEntry)

TIMELINE_MAX = 60
OPEN = ("new", "ack", "in_progress")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def _j(v, default):
    try:
        return json.loads(v) if v else default
    except Exception:
        return default


def resolve(ref: str) -> Optional[int]:
    """The inventory asset for a reference: an IPv4 address or `a<id>` (an asset without an address); None when the application does not know it."""
    ref = (ref or "").strip()
    with SessionLocal() as db:
        m = re.fullmatch(r"a(\d{1,9})", ref)
        if m:
            a = db.get(Asset, int(m.group(1)))
            return a.id if a else None
        a = db.execute(select(Asset).where(Asset.ip == ref).order_by(Asset.id).limit(1)).scalars().first()
        return a.id if a else None


class _Ctx:
    """What the sections share: the asset, its ids in the other tables and a place to collect the errors."""
    def __init__(self, asset: dict, row: Asset):
        self.asset = asset
        self.id = row.id
        self.ip = row.ip
        self.name = row.name or row.ip or f"#{row.id}"
        refs = _j(row.refs, {})
        self.device_id = refs.get("device_id")
        self.win_id = refs.get("windows_host_id")
        self.lin_id = refs.get("linux_host_id")
        self.vuln_id = refs.get("vuln_host_id")
        self.dell_id = refs.get("dell_server_id")
        self.vm_id = refs.get("hyperv_vm_id")
        self.bmc_ids: List[int] = []          # BMC (iDRAC / iLO ...) servers tied to this host: its own, or the one of the Windows host / address it is
        self.errors: List[str] = []


def _section(ctx: _Ctx, name: str, fn: Callable[[], Any], default=None):
    try:
        return fn()
    except Exception as e:
        ctx.errors.append(f"{name}: {type(e).__name__}: {e}"[:200])
        return default


# ── the sections ─────────────────────────────────────────────────────────────

def _ci(ctx: _Ctx) -> dict:
    a = ctx.asset
    typ = a.get("type") or "other"
    cls = {"network": "network_device", "printer": "printer", "virtual": "virtual_machine", "server": "server", "windows": "server" if a.get("role") == "server" else "workstation",
           "linux": "server" if a.get("role") == "server" else "workstation"}.get(typ, typ)
    last = a.get("last_seen_at")
    status = "unknown"
    if last:
        try:
            status = "operational" if datetime.utcnow() - datetime.fromisoformat(last.replace("Z", "")) < timedelta(days=7) else "inactive"
        except ValueError:
            pass
    owner, crit = a.get("owner"), a.get("criticality")        # the asset's own; a router's record fills what is empty
    if ctx.device_id and not (owner and crit):
        with SessionLocal() as db:
            d = db.get(Device, ctx.device_id)
            if d is not None:
                owner, crit = owner or d.owner, crit or d.criticality
    return {"class": cls, "type": typ, "role": a.get("role"), "manufacturer": a.get("manufacturer"), "model": a.get("model"), "serial": a.get("serial"), "os": a.get("os_name"),
            "os_version": a.get("os_version"), "lifecycle": a.get("lifecycle_detail"), "owner": owner, "criticality": crit, "place": a.get("place"), "location": a.get("location"),
            "tags": a.get("manual_groups") or [], "groups": a.get("groups") or [], "notes": a.get("notes"), "first_seen": a.get("first_seen_at"), "last_seen": last, "ci_status": status,
            "mac": a.get("mac"), "scan": a.get("scan")}


def _availability(ctx: _Ctx) -> Optional[dict]:
    from services import availability
    r = availability.outages(ctx.id, 30)
    if r.get("state") is None:
        return None
    return {"state": r["state"], "since": r.get("since"), "uptime": r.get("uptime"), "outages": r["outages"][:5], "affects": availability.affected_by(ctx.id)[:10]}


def _maintenance(ctx: _Ctx) -> List[dict]:
    now = datetime.utcnow()
    out = []
    with SessionLocal() as db:
        for w in db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled == True)).scalars().all():  # noqa: E712
            ids = _j(w.asset_ids, [])
            if not (w.scope_all or ctx.id in ids):
                continue
            if w.kind == "once" and w.starts_at and w.ends_at and w.starts_at <= now <= w.ends_at:
                out.append({"id": w.id, "name": w.name, "until": _iso(w.ends_at)})
            elif w.kind == "weekly":
                out.append({"id": w.id, "name": w.name, "until": None, "weekly": True})
    return out


def _alerts(ctx: _Ctx) -> dict:
    with SessionLocal() as db:
        cond = (SocAlert.asset_id == ctx.id) | (SocAlert.ip == ctx.ip) if ctx.ip else (SocAlert.asset_id == ctx.id)
        rows = db.execute(select(SocAlert).where(cond).order_by(SocAlert.rank.desc(), SocAlert.last_seen.desc()).limit(200)).scalars().all()
        opn = [r for r in rows if r.status in OPEN]
        closed = [r for r in rows if r.status not in OPEN]

        def row(r: SocAlert) -> dict:
            return {"id": r.id, "rule": r.rule, "title": r.title, "severity": r.severity, "status": r.status, "source": r.source, "category": r.category, "count": r.count,
                    "first_seen": _iso(r.first_seen), "last_seen": _iso(r.last_seen), "message": (_j(r.detail, {}).get("message") or "")[:200]}
        month = datetime.utcnow() - timedelta(days=30)
        return {"open": [row(r) for r in opn][:20], "open_count": len(opn), "closed_30d": sum(1 for r in closed if r.last_seen and r.last_seen >= month), "recent_closed": [row(r) for r in closed][:5]}


async def _vulns(ctx: _Ctx) -> dict:
    from services import assets
    fs = await assets.asset_vulnerabilities(ctx.id) or []
    opn = [f for f in fs if (f.get("status") or "open") in ("open", "in_progress")]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in opn:
        k = (f.get("severity") or "low").lower()
        counts[k if k in counts else "low"] += 1
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top = sorted(opn, key=lambda f: (0 if f.get("kev") else 1, order.get((f.get("severity") or "LOW").upper(), 4), -(f.get("cvss_score") or 0)))[:10]
    return {"counts": counts, "total": len(opn), "kev": sum(1 for f in opn if f.get("kev")), "accepted": len(fs) - len(opn),
            "top": [{"cve_id": f["cve_id"], "severity": f.get("severity"), "cvss": f.get("cvss_score"), "kev": bool(f.get("kev")), "epss": f.get("epss"), "product": f.get("product"),
                     "version": f.get("version"), "summary": (f.get("summary") or "")[:160], "url": f.get("ref_url")} for f in top]}


def _tls(ctx: _Ctx) -> List[dict]:
    if not ctx.ip:
        return []
    now = datetime.utcnow()
    with SessionLocal() as db:
        rows = db.execute(select(TlsCheck).where(TlsCheck.ip == ctx.ip).order_by(TlsCheck.port)).scalars().all()
        return [{"port": r.port, "subject": r.subject, "issuer": r.issuer, "days": round((r.not_after - now).total_seconds() / 86400, 1) if r.not_after else None, "protocol": r.protocol,
                 "findings": [f for f in _j(r.findings, []) if f.get("code") != "intercepted"], "error": r.error} for r in rows]


def _services(ctx: _Ctx) -> List[dict]:
    if not ctx.vuln_id and not ctx.ip:
        return []
    with SessionLocal() as db:
        hid = ctx.vuln_id
        if not hid and ctx.ip:
            h = db.execute(select(VulnHost).where(VulnHost.ip == ctx.ip)).scalars().first()
            hid = h.id if h else None
        if not hid:
            return []
        rows = db.execute(select(VulnService).where(VulnService.host_id == hid).order_by(VulnService.port)).scalars().all()
        return [{"port": r.port, "proto": r.proto, "service": r.service_name, "product": r.product, "version": r.version, "seen": _iso(r.last_seen)} for r in rows][:80]


def _updates(ctx: _Ctx) -> Optional[dict]:
    out: Dict[str, Any] = {}
    with SessionLocal() as db:
        if ctx.win_id:
            w = db.get(WindowsHost, ctx.win_id)
            if w is not None:
                out["windows"] = {"id": w.id, "upgradable": w.upgradable_count, "reboot_required": bool(w.reboot_required), "last_check": _iso(w.last_check_at), "last_upgrade": _iso(w.last_upgrade_at),
                                  "titles": _j(w.upgradable_titles, [])[:8], "status": w.last_status, "error": w.last_error, "managed": bool(w.managed)}
        if ctx.lin_id:
            l = db.get(LinuxHost, ctx.lin_id)
            if l is not None:
                out["linux"] = {"id": l.id, "upgradable": l.upgradable_count, "reboot_required": bool(l.reboot_required), "last_check": _iso(l.last_check_at), "last_upgrade": _iso(l.last_upgrade_at),
                                "packages": (_j(l.upgradable_packages, []) or [])[:8], "status": l.last_status, "error": l.last_error, "managed": bool(l.managed), "distro": l.distro_pretty}
        if ctx.device_id:
            d = db.get(Device, ctx.device_id)
            if d is not None:
                out["device"] = {"id": d.id, "version": d.ros_version, "latest": d.latest_ros_version, "update_status": d.ros_update_status, "firmware": getattr(d, "current_firmware", None),
                                 "upgrade_firmware": getattr(d, "upgrade_firmware", None)}
    return out or None


def _resources(ctx: _Ctx) -> Optional[dict]:
    with SessionLocal() as db:
        res: Dict[str, Any] = {}
        if ctx.device_id:
            d = db.get(Device, ctx.device_id)
            if d is not None and d.last_resources_check_at:
                res = {"cpu": d.cpu_load_pct, "mem": d.mem_used_pct, "disk": d.disk_used_pct, "temp": d.temperature_c, "at": _iso(d.last_resources_check_at), "source": "router"}
        for kind, hid, M in (("windows", ctx.win_id, WindowsHost), ("linux", ctx.lin_id, LinuxHost)):
            if hid and not res:
                h = db.get(M, hid)
                if h is not None and h.last_resources_check_at:
                    res = {"cpu": h.cpu_used_pct, "mem": h.mem_used_pct, "disk": None, "temp": None, "at": _iso(h.last_resources_check_at), "source": kind}
        series = [{"key": s.key, "name": s.name, "kind": s.kind, "unit": s.unit, "value": s.last_value, "at": _iso(s.last_at)} for s in db.execute(select(MetricSeries).where(MetricSeries.asset_id == ctx.id)).scalars().all()]
    if not res and not series:
        return None
    return {"now": res or None, "series": series[:12]}


def _last_boot(ctx: _Ctx) -> Optional[dict]:
    """When it was last restarted (the newest reading of the boot time or of the uptime, with its source and age) and the restarts the agent noticed - services/last_boot.py."""
    from services import last_boot
    return last_boot.for_asset(ctx.id)


def _config(ctx: _Ctx) -> Optional[dict]:
    if not ctx.device_id:
        return None
    with SessionLocal() as db:
        chk = db.get(ConfigCheck, ctx.device_id)
        snaps = db.execute(select(ConfigSnapshot).where(ConfigSnapshot.device_id == ctx.device_id).order_by(ConfigSnapshot.id.desc()).limit(6)).scalars().all()
        total = db.execute(select(func.count()).select_from(ConfigSnapshot).where(ConfigSnapshot.device_id == ctx.device_id)).scalar() or 0
    if chk is None and not snaps:
        return None
    return {"device_id": ctx.device_id, "last_check": _iso(chk.last_check_at) if chk else None, "last_change": _iso(chk.last_change_at) if chk else None, "error": chk.last_error if chk else None,
            "versions": total, "recent": [{"id": s.id, "at": _iso(s.at), "added": s.added, "removed": s.removed, "sections": _j(s.sections, [])[:6]} for s in snaps]}


def _syslog(ctx: _Ctx) -> Optional[dict]:
    if not ctx.ip:
        return None
    day = datetime.utcnow() - timedelta(hours=24)
    with SessionLocal() as db:
        cnt = db.execute(select(func.count()).select_from(SyslogEvent).where(SyslogEvent.source_ip == ctx.ip, SyslogEvent.at >= day)).scalar() or 0
        rows = db.execute(select(SyslogEvent).where(SyslogEvent.source_ip == ctx.ip).order_by(SyslogEvent.id.desc()).limit(8)).scalars().all()
        return {"count_24h": cnt, "recent": [{"at": _iso(r.at), "severity": r.severity, "kind": r.kind, "app": r.app, "message": (r.message or "")[:200]} for r in rows]} if (cnt or rows) else None


def _network(ctx: _Ctx) -> Optional[dict]:
    from services import topology_map
    at = topology_map.attachments().get(ctx.id)
    children = []
    with SessionLocal() as db:
        names = {a.id: (a.name or a.ip) for a in db.execute(select(Asset)).scalars().all()}
    for aid, a in topology_map.attachments().items():
        if a.get("to_id") == ctx.id:
            children.append({"id": aid, "name": names.get(aid), "port": a.get("port"), "vlan": a.get("vlan"), "kind": a.get("kind")})
    if not at and not children:
        return None
    return {"attached_to": {"id": at.get("to_id"), "name": at.get("to"), "ip": at.get("to_ip"), "port": at.get("port"), "vlan": at.get("vlan"), "kind": at.get("kind")} if at else None,
            "children": sorted(children, key=lambda c: (c.get("port") or "", c.get("name") or ""))[:60]}


def _relationships(ctx: _Ctx, net: Optional[dict]) -> dict:
    out: Dict[str, Any] = {"depends_on": [], "supports": [], "business_services": [], "hosted_on": None, "hosts": [], "peripherals": []}
    if net and net.get("attached_to"):
        a = net["attached_to"]
        out["depends_on"].append({"id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "via": f"{a.get('port') or ''}".strip() or a.get("kind")})
    if net:
        out["supports"] = [{"id": c["id"], "name": c["name"], "via": c.get("port")} for c in net["children"][:30]]
    with SessionLocal() as db:
        for s in db.execute(select(BizService)).scalars().all():
            if ctx.id in [int(x) for x in _j(s.members, [])]:
                out["business_services"].append({"id": s.id, "name": s.name, "mode": s.mode})
        parent = ctx.asset.get("parent")
        if parent:
            out["hosted_on"] = parent if isinstance(parent, dict) else {"name": str(parent)}
        out["peripherals"] = [{"kind": p.kind, "name": p.name} for p in db.execute(select(AssetPeripheral).where(AssetPeripheral.asset_id == ctx.id)).scalars().all()][:20]
        if ctx.win_id:
            hv = db.execute(select(HypervHost).where(HypervHost.windows_host_id == ctx.win_id)).scalars().first()
            if hv is not None:
                out["hosts"] = [{"name": v.name, "state": getattr(v, "state", None)} for v in db.execute(select(HypervVM).where(HypervVM.hyperv_host_id == hv.id)).scalars().all()][:40]
    try:
        from services import availability
        for x in availability.affected_by(ctx.id)[:20]:
            if not any(s["id"] == x["id"] for s in out["supports"]):
                out["supports"].append({"id": x["id"], "name": x["name"], "via": "unreachable"})
    except Exception:
        pass
    return out


def _bmc(ctx: _Ctx) -> Optional[List[dict]]:
    """The BMC (iDRAC / iLO / ...) of this host: the server record that is this asset (its address is the BMC's), or the one tied to the Windows host that is this asset."""
    with SessionLocal() as db:
        servers: List[DellServer] = []
        if ctx.dell_id:
            s = db.get(DellServer, ctx.dell_id)
            if s is not None:
                servers.append(s)
        if ctx.win_id:
            servers += list(db.execute(select(DellServer).where(DellServer.windows_host_id == ctx.win_id)).scalars().all())
        if ctx.ip and not servers:
            servers += list(db.execute(select(DellServer).where(DellServer.idrac_ip == ctx.ip)).scalars().all())
        servers = list({s.id: s for s in servers}.values())
        ctx.bmc_ids = [s.id for s in servers]
        out = []
        for s in servers:
            sel = db.execute(select(DellServerSelEntry).where(DellServerSelEntry.server_id == s.id).order_by(DellServerSelEntry.id.desc()).limit(6)).scalars().all()
            bmc_asset = db.execute(select(Asset).where(Asset.ip == s.idrac_ip).limit(1)).scalars().first() if s.idrac_ip else None
            out.append({"id": s.id, "name": s.name, "vendor": s.vendor, "idrac_ip": s.idrac_ip, "bmc_ref": (s.idrac_ip if bmc_asset is not None and bmc_asset.id != ctx.id else None), "model": s.model,
                        "service_tag": s.service_tag, "bios": s.bios_version, "power": s.power_state, "health": s.health_rollup, "access": s.access_method, "last_check": _iso(s.last_check_at),
                        "status": s.last_status, "error": s.last_error, "components": _j(s.components_json, {}),
                        "sel": [{"severity": e.severity, "message": (e.message or "")[:160], "at": _iso(e.logged_at or e.seen_at)} for e in sel]})
        return out or None


def _response(ctx: _Ctx) -> List[dict]:
    if not ctx.ip:
        return []
    with SessionLocal() as db:
        rows = db.execute(select(SoarAction).where(SoarAction.target == ctx.ip).order_by(SoarAction.id.desc()).limit(10)).scalars().all()
        return [{"id": r.id, "kind": r.kind, "status": r.status, "reason": r.reason, "at": _iso(r.proposed_at), "until": _iso(r.expires_at) if r.status == "executed" else None} for r in rows]


def _access(ctx: _Ctx) -> Optional[dict]:
    if not ctx.device_id:
        return None
    with SessionLocal() as db:
        d = db.get(Device, ctx.device_id)
        if d is None:
            return None
        c = db.get(Credential, d.credential_id) if d.credential_id else None
        return {"device_id": d.id, "vendor": d.vendor, "credential": c.name if c else None, "online": bool(d.online), "mgmt_ok": d.mgmt_ok, "last_seen": _iso(d.last_seen),
                "ports": {"api": bool(d.has_api), "ssh": bool(d.has_ssh), "web": bool(d.has_web), "snmp": bool(d.has_snmp)}, "ssh_port": d.ssh_port, "api_port": d.api_port, "web_port": d.web_port}


def _sources(ctx: _Ctx) -> List[dict]:
    out = [{"kind": "asset", "label": ctx.name, "id": ctx.id, "path": f"/inventory/{ctx.id}"}]
    if ctx.device_id:
        out.append({"kind": "device", "id": ctx.device_id, "path": f"/devices/{ctx.device_id}"})
    if ctx.win_id:
        out.append({"kind": "windows", "id": ctx.win_id, "path": "/windows"})
    if ctx.lin_id:
        out.append({"kind": "linux", "id": ctx.lin_id, "path": "/linux"})
    if ctx.dell_id or ctx.bmc_ids:
        out.append({"kind": "dell", "id": ctx.dell_id or (ctx.bmc_ids[0] if ctx.bmc_ids else None), "path": "/dell-servers"})
    if ctx.vm_id:
        out.append({"kind": "hyperv", "id": ctx.vm_id, "path": "/hyperv"})
    if ctx.vuln_id:
        out.append({"kind": "vuln", "id": ctx.vuln_id, "path": "/vulnerabilities"})
    with SessionLocal() as db:
        if ctx.ip and db.execute(select(UpsTarget.id).where(UpsTarget.ip == ctx.ip).limit(1)).first():
            out.append({"kind": "ups", "id": None, "path": "/ups"})
        if ctx.id and db.get(AvailState, ctx.id) is not None:
            out.append({"kind": "availability", "id": ctx.id, "path": "/availability"})
    return out


def _timeline(ctx: _Ctx) -> List[dict]:
    ev: List[dict] = []
    with SessionLocal() as db:
        for r in db.execute(select(SocAlert).where((SocAlert.asset_id == ctx.id) | (SocAlert.ip == ctx.ip) if ctx.ip else (SocAlert.asset_id == ctx.id)).order_by(SocAlert.last_seen.desc()).limit(30)).scalars().all():
            ev.append({"at": _iso(r.first_seen), "kind": "alert_opened", "severity": r.severity, "text": r.title or r.rule, "ref": r.id})
            if r.closed_at:
                ev.append({"at": _iso(r.closed_at), "kind": "alert_closed", "severity": "info", "text": r.title or r.rule, "ref": r.id})
        for e in db.execute(select(AvailEvent).where(AvailEvent.asset_id == ctx.id).order_by(AvailEvent.id.desc()).limit(20)).scalars().all():
            ev.append({"at": _iso(e.at), "kind": "availability", "severity": "high" if e.state != "up" else "info", "text": e.state + (f" ({e.root_name})" if e.root_name else ""), "ref": None})
        if ctx.device_id:
            for s in db.execute(select(ConfigSnapshot).where(ConfigSnapshot.device_id == ctx.device_id).order_by(ConfigSnapshot.id.desc()).limit(10)).scalars().all():
                ev.append({"at": _iso(s.at), "kind": "config", "severity": "info", "text": f"+{s.added or 0} / -{s.removed or 0}", "ref": s.id})
        if ctx.ip:
            for s in db.execute(select(SyslogEvent).where(SyslogEvent.source_ip == ctx.ip, SyslogEvent.raised.is_not(None)).order_by(SyslogEvent.id.desc()).limit(10)).scalars().all():
                ev.append({"at": _iso(s.at), "kind": "syslog", "severity": s.severity or "info", "text": (s.message or "")[:160], "ref": s.id})
            for a in db.execute(select(SoarAction).where(SoarAction.target == ctx.ip).order_by(SoarAction.id.desc()).limit(10)).scalars().all():
                ev.append({"at": _iso(a.executed_at or a.proposed_at), "kind": "response", "severity": "info", "text": f"{a.kind}: {a.status}", "ref": a.id})
        for sid in ctx.bmc_ids:
            for e in db.execute(select(DellServerSelEntry).where(DellServerSelEntry.server_id == sid).order_by(DellServerSelEntry.id.desc()).limit(8)).scalars().all():
                ev.append({"at": _iso(e.logged_at or e.seen_at), "kind": "bmc", "severity": "high" if (e.severity or "").lower() == "critical" else "info", "text": (e.message or "")[:160], "ref": e.id})
        a = db.get(Asset, ctx.id)
        if a is not None:
            ev.append({"at": _iso(a.first_seen_at), "kind": "first_seen", "severity": "info", "text": "", "ref": None})
            if a.last_scan_at:
                ev.append({"at": _iso(a.last_scan_at), "kind": "scan", "severity": "info", "text": a.last_scan_status or "", "ref": None})
    ev = [e for e in ev if e["at"]]
    ev.sort(key=lambda e: e["at"], reverse=True)
    return ev[:TIMELINE_MAX]


def _health(ctx: _Ctx, avail, alerts, vulns, tls, updates, ci, bmc=None) -> dict:
    """A verdict (ok / warn / crit) and the reasons it follows from, as codes the page turns into text."""
    crit: List[str] = []
    warn: List[str] = []
    if avail and avail["state"] != "up":
        crit.append("down" if avail["state"] == "down" else "unreachable")
    for a in (alerts or {}).get("open", []):
        if a["severity"] in ("critical", "high"):
            crit.append(f"alert:{a['rule']}")
        elif a["severity"] != "info":
            warn.append(f"alert:{a['rule']}")
    if vulns:
        if vulns["kev"]:
            crit.append("kev")
        if vulns["counts"]["critical"]:
            crit.append("vuln_critical")
        elif vulns["counts"]["high"]:
            warn.append("vuln_high")
    for t in tls or []:
        codes = {f["code"] for f in t["findings"]}
        if "expired" in codes:
            crit.append("tls_expired")
        elif codes & {"expiring", "weak_key", "weak_signature", "legacy_protocol"}:
            warn.append("tls_issue")
    for k in ("windows", "linux"):
        u = (updates or {}).get(k)
        if u and u.get("reboot_required"):
            warn.append("reboot_required")
        if u and (u.get("upgradable") or 0) > 0:
            warn.append("updates_pending")
    for b in bmc or []:
        h = (b.get("health") or "").lower()
        if h == "critical":
            crit.append("bmc_critical")
        elif h == "warning":
            warn.append("bmc_warning")
        if b.get("status") == "error":
            warn.append("bmc_unreachable")
    lc = (ci.get("lifecycle") or {}).get("status")
    if lc == "eol":
        warn.append("os_eol")
    elif lc == "ending":
        warn.append("os_ending")
    crit = list(dict.fromkeys(crit))
    warn = [w for w in dict.fromkeys(warn) if w not in crit]
    return {"level": "crit" if crit else ("warn" if warn else "ok"), "critical": crit[:8], "warnings": warn[:8]}


async def build(ref: str) -> Optional[dict]:
    from services import assets
    aid = resolve(ref)
    if aid is None:
        return None
    asset = await assets.get_asset(aid)
    if asset is None:
        return None
    with SessionLocal() as db:
        row = db.get(Asset, aid)
        if row is None:
            return None
        ctx = _Ctx(asset, row)
    ci = _section(ctx, "ci", lambda: _ci(ctx), {})
    avail = _section(ctx, "availability", lambda: _availability(ctx))
    alerts = _section(ctx, "alerts", lambda: _alerts(ctx), {"open": [], "open_count": 0, "closed_30d": 0, "recent_closed": []})
    try:
        vulns = await _vulns(ctx)
    except Exception as e:
        ctx.errors.append(f"vulnerabilities: {type(e).__name__}: {e}"[:200])
        vulns = None
    tls = _section(ctx, "tls", lambda: _tls(ctx), [])
    updates = _section(ctx, "updates", lambda: _updates(ctx))
    net = _section(ctx, "network", lambda: _network(ctx))
    bmc = _section(ctx, "bmc", lambda: _bmc(ctx))
    maint = _section(ctx, "maintenance", lambda: _maintenance(ctx), [])
    card = {
        "ref": ctx.ip or f"a{ctx.id}", "asset_id": ctx.id, "name": ctx.name, "ip": ctx.ip, "ci": ci,
        "status": {"availability": avail, "maintenance": maint, "health": _health(ctx, avail, alerts, vulns, tls, updates, ci, bmc)},
        "sources": _section(ctx, "sources", lambda: _sources(ctx), []), "alerts": alerts, "vulnerabilities": vulns, "tls": tls,
        "services": _section(ctx, "services", lambda: _services(ctx), []), "updates": updates, "bmc": bmc, "resources": _section(ctx, "resources", lambda: _resources(ctx)),
        "config": _section(ctx, "config", lambda: _config(ctx)), "syslog": _section(ctx, "syslog", lambda: _syslog(ctx)), "network": net,
        "relationships": _section(ctx, "relationships", lambda: _relationships(ctx, net), {}), "response": _section(ctx, "response", lambda: _response(ctx), []),
        "access": _section(ctx, "access", lambda: _access(ctx)), "last_boot": _section(ctx, "last_boot", lambda: _last_boot(ctx)), "hardware": asset.get("hardware"), "software_count": asset.get("software_count"),
        "timeline": _section(ctx, "timeline", lambda: _timeline(ctx), []), "errors": ctx.errors,
    }
    return card
