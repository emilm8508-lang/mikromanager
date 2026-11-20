"""
CMDB: configuration item classes and the relations between them (docs/plan-itam.md, stage B).

Every asset is a configuration item (CI). Its class says what it is in more detail than the inventory's seven types - a hypervisor, a domain
controller, an access point, a UPS. The class is suggested from what the agent already knows (type, role, the device class of the scan, the open
ports, the Hyper-V hosts, the model); the operator can set another one (Asset.ci_class), and the set one wins.

Relations (A <kind> B):
  runs_on        A runs on B (a VM on its Hyper-V host, an application on its server)
  depends_on     A needs B to work (an application needs its database server)
  connected_to   A is plugged into B (a switch port, an access point, the router of a segment)
  backs_up       A backs up B
  member_of      A is part of a business service (B is the service, not an asset)
  uses_license / covered_by_contract   (stages C and D)
Automatic relations come from what is already known and are computed, not stored: the map's attachments (services/topology_map.py: switch port,
Wi-Fi, router segment -> connected_to; VM -> runs_on) and the business services (services/business_services.py -> member_of). They cannot be
deleted (the next map would bring them back) but can be hidden. Manual relations are rows of ci_relation.

Impact - what stops working when X fails: everything that runs on, depends on or is connected to X, and so on, up to MAX_DEPTH steps, plus the
business services those belong to. Dependencies - what X needs: the other direction.
"""
import json
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import select

from models.database import SessionLocal, Asset, CiRelation

MAX_DEPTH = 4
KINDS = ("runs_on", "depends_on", "connected_to", "backs_up", "member_of", "uses_license", "covered_by_contract")
MANUAL_KINDS = ("runs_on", "depends_on", "connected_to", "backs_up")
# A <kind> B: when B fails, A is affected (backs_up is not: a backup failing does not stop what it backs up)
_IMPACT_KINDS = ("runs_on", "depends_on", "connected_to", "member_of")

# The classes, grouped. Order matters only for the UI.
CLASSES: Dict[str, Tuple[str, ...]] = {
    "hardware": ("server_physical", "server_virtual", "hypervisor", "workstation", "laptop", "thin_client", "tablet", "phone_mobile", "monitor",
                 "printer", "mfp", "scanner", "ups", "pdu", "nas", "storage_array", "tape_library", "bmc", "kvm", "camera_ip", "phone_ip",
                 "access_control", "iot_device"),
    "network": ("router", "switch", "access_point", "wlan_controller", "firewall", "load_balancer", "vpn_gateway", "modem"),
    "server_role": ("domain_controller", "database_server", "web_server", "mail_server", "file_server", "print_server", "backup_server",
                    "application_server", "dns_dhcp_server", "monitoring_server", "remote_desktop_server"),
    "logical": ("application", "business_service", "cluster", "other"),
}
ALL_CLASSES = tuple(c for g in CLASSES.values() for c in g)
GROUP_OF = {c: g for g, cs in CLASSES.items() for c in cs}

# open ports that name a server's role (the first match wins, in this order)
_ROLE_PORTS = (("domain_controller", {88, 389, 636, 3268}), ("database_server", {1433, 1521, 3306, 5432, 27017, 6379}),
               ("mail_server", {25, 465, 587, 993, 995}), ("remote_desktop_server", set()), ("backup_server", {10000, 9392, 902}),
               ("print_server", {631}), ("web_server", {80, 443, 8080, 8443}), ("file_server", {445, 2049}))


def suggest(asset_type: Optional[str], role: Optional[str], dclass: Optional[str], ports: Set[int], hyperv_host: bool, model: Optional[str],
            name: Optional[str], maker: Optional[str] = None) -> Tuple[str, str]:
    """(class, why) from what the inventory knows."""
    txt = " ".join(x for x in (model, name, maker) if x).lower()
    if hyperv_host:
        return "hypervisor", "Hyper-V host"
    if asset_type == "virtual":
        return "server_virtual", "virtual machine"
    if asset_type == "network":
        if dclass == "ap" or any(k in txt for k in ("wap", "cap ", "cap-", "hap", "access point", "unifi ap", "uap")):
            return "access_point", dclass or "model"
        if dclass == "switch" or any(k in txt for k in ("crs", "css", "switch", "sg2", "sg3", "cbs")):
            return "switch", dclass or "model"
        if any(k in txt for k in ("fortigate", "sophos", "pfsense", "opnsense", "firewall", "watchguard")):
            return "firewall", "model"
        return "router", dclass or "network device"
    if asset_type == "printer":
        return ("mfp" if any(k in txt for k in ("mfp", "mfc", "multifunction", "dcp")) else "printer"), "printer"
    if asset_type == "monitor":
        return "monitor", "monitor"
    if any(k in txt for k in ("smart-ups", "ups ", "apc ", "eaton")):
        return "ups", "model"
    if any(k in txt for k in ("idrac", "ilo ", "imm ", "ipmi")):
        return "bmc", "model"
    if any(k in txt for k in ("synology", "qnap", "diskstation", "nas")):
        return "nas", "model"
    if any(k in txt for k in ("camera", "hikvision", "dahua", "axis ")):
        return "camera_ip", "model"
    if any(k in txt for k in ("yealink", "grandstream", "polycom", "snom", "cisco ip phone")):
        return "phone_ip", "model"
    if role == "server" or asset_type == "server":
        if ports & {3389} and "rds" in txt:
            return "remote_desktop_server", "name"
        for cls, ps in _ROLE_PORTS:
            if ps and ports & ps:
                return cls, f"port {sorted(ports & ps)[0]}"
        return "server_physical", "server"
    if asset_type in ("windows", "linux"):
        if any(k in txt for k in ("latitude", "thinkpad", "elitebook", "probook", "laptop", "notebook", "macbook", "vivobook", "ideapad")):
            return "laptop", "model"
        return "workstation", "computer"
    if dclass == "apple":
        return "laptop" if "macbook" in txt else "phone_mobile", "Apple"
    return "other", "unknown"


def _ports(db) -> Dict[str, Set[int]]:
    from models.database import VulnHost, VulnService
    out: Dict[str, Set[int]] = {}
    for ip, port in db.execute(select(VulnHost.ip, VulnService.port).join(VulnService, VulnService.host_id == VulnHost.id)).all():
        out.setdefault(ip, set()).add(int(port))
    return out


def _hyperv_hosts(db) -> Set[int]:
    try:
        from models.database import HypervHost
        return {h.windows_host_id for h in db.execute(select(HypervHost)).scalars().all()}
    except Exception:
        return set()


def class_of(a: Asset, ports: Dict[str, Set[int]], hv: Set[int]) -> Dict:
    """{"class", "set" (by the operator), "suggested", "why", "group"}."""
    det = _jload(a.details)
    refs = _jload(a.refs)
    sug, why = suggest(a.asset_type, a.role, det.get("_class"), ports.get(a.ip or "", set()), refs.get("windows_host_id") in hv, a.model, a.name, a.manufacturer)
    cls = a.ci_class if a.ci_class in ALL_CLASSES else sug
    return {"class": cls, "set": a.ci_class in ALL_CLASSES, "suggested": sug, "why": why, "group": GROUP_OF.get(cls, "logical")}


def _jload(s) -> dict:
    try:
        v = json.loads(s or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def set_class(asset_id: int, ci_class: Optional[str], who: str = "operator") -> bool:
    from services import identity
    if ci_class and ci_class not in ALL_CLASSES:
        raise ValueError("unknown CI class")
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if not a:
            return False
        identity.history(db, a.id, "ci_class", a.ci_class, ci_class or None, f"cmdb: {who}"[:80])
        a.ci_class = ci_class or None
        db.commit()
    return True


# ── Relations ────────────────────────────────────────────────────────────────

def _auto_edges(db, names: Dict[int, str]) -> List[Dict]:
    """The relations known without anyone entering them."""
    from services import topology_map, business_services
    from models.database import BizService
    out = []
    for b, at in (topology_map.attachments() or {}).items():
        a = at.get("to_id")
        if not isinstance(a, int) or b not in names or a not in names or a == b:
            continue
        kind = "runs_on" if at.get("kind") == "vm" else "connected_to"
        how = {"client": f"port {at.get('port')}" if at.get("port") else "switch", "uplink": "uplink", "l3": "segment", "wifi": f"Wi-Fi {at.get('ssid') or ''}".strip(),
               "vm": "VM"}.get(at.get("kind"), at.get("kind"))
        out.append({"src": b, "dst": a, "kind": kind, "auto": True, "how": how})
    for s in db.execute(select(BizService)).scalars().all():
        for m in business_services._members(s):
            if m in names:
                out.append({"src": m, "dst": None, "service": s.name, "service_id": s.id, "kind": "member_of", "auto": True, "how": "business service"})
    return out


def edges(db=None) -> List[Dict]:
    """All relations: manual rows + automatic ones not hidden. Each {id?, src, dst, kind, auto, how, note, service?}."""
    own = db is None
    db = db or SessionLocal()
    try:
        names = {a.id: a.name or a.ip or a.key for a in db.execute(select(Asset)).scalars().all()}
        rows = db.execute(select(CiRelation)).scalars().all()
        hidden = {(r.src_id, r.dst_id, r.kind) for r in rows if r.hidden}
        out = [{"id": r.id, "src": r.src_id, "dst": r.dst_id, "kind": r.kind, "auto": False, "how": None, "note": r.note,
                "by": r.created_by, "at": r.created_at.isoformat() + "Z" if r.created_at else None}
               for r in rows if not r.hidden and r.src_id in names and (r.dst_id in names)]
        manual = {(e["src"], e["dst"], e["kind"]) for e in out}
        for e in _auto_edges(db, names):
            key = (e["src"], e["dst"] if e["dst"] is not None else -(e.get("service_id") or 0), e["kind"])
            if key in hidden or (e["src"], e["dst"], e["kind"]) in manual:
                continue
            out.append(e)
        for e in out:
            e["src_name"] = names.get(e["src"])
            e["dst_name"] = names.get(e["dst"]) if e["dst"] is not None else e.get("service")
        return out
    finally:
        if own:
            db.close()


def add_relation(src: int, dst: int, kind: str, note: Optional[str], who: str) -> int:
    if kind not in MANUAL_KINDS:
        raise ValueError(f"kind: one of {', '.join(MANUAL_KINDS)}")
    if src == dst:
        raise ValueError("an asset cannot relate to itself")
    with SessionLocal() as db:
        if not db.get(Asset, src) or not db.get(Asset, dst):
            raise ValueError("asset not found")
        dup = db.execute(select(CiRelation).where(CiRelation.src_id == src, CiRelation.dst_id == dst, CiRelation.kind == kind)).scalars().first()
        if dup:
            if dup.hidden:
                dup.hidden = False
                db.commit()
            return dup.id
        r = CiRelation(src_id=src, dst_id=dst, kind=kind, note=(note or "").strip()[:200] or None, created_by=(who or "")[:64], created_at=datetime.utcnow())
        db.add(r)
        db.commit()
        return r.id


def remove_relation(rel_id: int) -> bool:
    with SessionLocal() as db:
        r = db.get(CiRelation, rel_id)                  # a manual relation, or a hidden automatic one (removing it shows it again)
        if not r:
            return False
        db.delete(r)
        db.commit()
        return True


def hide_auto(src: int, dst: Optional[int], kind: str, service_id: Optional[int], who: str) -> None:
    """Hides an automatic relation (kept as a hidden row; a business service membership is keyed by the negative service id)."""
    if kind not in KINDS:
        raise ValueError("unknown relation kind")
    key_dst = dst if dst is not None else -(int(service_id or 0))
    with SessionLocal() as db:
        db.add(CiRelation(src_id=src, dst_id=key_dst, kind=kind, hidden=True, created_by=(who or "")[:64], created_at=datetime.utcnow()))
        db.commit()


def _graph(es: List[Dict]) -> Tuple[Dict[int, List[Dict]], Dict[int, List[Dict]]]:
    up: Dict[int, List[Dict]] = {}        # src -> edges it depends on
    down: Dict[int, List[Dict]] = {}      # dst -> edges of what depends on it
    for e in es:
        if e["kind"] not in _IMPACT_KINDS:
            continue
        up.setdefault(e["src"], []).append(e)
        if e["dst"] is not None:
            down.setdefault(e["dst"], []).append(e)
    return up, down


def impact(asset_id: int, es: Optional[List[Dict]] = None) -> Dict:
    """What is affected when `asset_id` fails: assets (with the depth and the path's last relation) and business services."""
    es = es if es is not None else edges()
    up, down = _graph(es)
    seen = {asset_id: 0}
    out, services = [], {}
    q = deque([asset_id])
    while q:
        cur = q.popleft()
        if seen[cur] >= MAX_DEPTH:
            continue
        for e in down.get(cur, []):
            s = e["src"]
            if s not in seen:
                seen[s] = seen[cur] + 1
                out.append({"id": s, "name": e["src_name"], "depth": seen[s], "kind": e["kind"], "via": e["dst_name"]})
                q.append(s)
    for aid in [asset_id] + [x["id"] for x in out]:
        for e in up.get(aid, []):
            if e["kind"] == "member_of" and e.get("service"):
                services[e["service"]] = e.get("service_id")
    return {"assets": out, "services": [{"name": n, "id": i} for n, i in sorted(services.items())]}


def dependencies(asset_id: int, es: Optional[List[Dict]] = None) -> List[Dict]:
    """What `asset_id` needs to work, transitively (the possible causes when it fails)."""
    es = es if es is not None else edges()
    up, _down = _graph(es)
    seen = {asset_id: 0}
    out = []
    q = deque([asset_id])
    while q:
        cur = q.popleft()
        if seen[cur] >= MAX_DEPTH:
            continue
        for e in up.get(cur, []):
            d = e["dst"]
            if d is None or d in seen:
                continue
            seen[d] = seen[cur] + 1
            out.append({"id": d, "name": e["dst_name"], "depth": seen[d], "kind": e["kind"], "from": e["src_name"]})
            q.append(d)
    return out


def for_asset(asset_id: int) -> Dict:
    es = edges()
    mine = [e for e in es if e["src"] == asset_id or e["dst"] == asset_id]
    return {"relations": mine, "impact": impact(asset_id, es), "dependencies": dependencies(asset_id, es)}


def overview() -> Dict:
    """Counts per class and per group, the number of relations (manual / automatic), and every CI with its class."""
    with SessionLocal() as db:
        ports, hv = _ports(db), _hyperv_hosts(db)
        items = []
        for a in db.execute(select(Asset)).scalars().all():
            if a.state in ("ignore",):
                continue
            c = class_of(a, ports, hv)
            items.append({"id": a.id, "name": a.name or a.ip or a.key, "ip": a.ip, "type": a.asset_type, **c, "state": a.state})
        es = edges(db)
    counts: Dict[str, int] = {}
    for x in items:
        counts[x["class"]] = counts.get(x["class"], 0) + 1
    rel_count: Dict[int, int] = {}
    for e in es:
        for k in (e["src"], e["dst"]):
            if k is not None:
                rel_count[k] = rel_count.get(k, 0) + 1
    for x in items:
        x["relations"] = rel_count.get(x["id"], 0)
    return {"classes": CLASSES, "counts": counts, "items": sorted(items, key=lambda x: (x["group"], x["class"], (x["name"] or "").lower())),
            "relations": {"manual": sum(1 for e in es if not e["auto"]), "auto": sum(1 for e in es if e["auto"])}}


def public_summary() -> Dict:
    """For Central / MCP: counts per class and the relations by name (asset names and business service names, no addresses)."""
    o = overview()
    es = edges()
    return {"counts": o["counts"], "relations": [[e["src_name"], e["kind"], e["dst_name"], 0 if e["auto"] else 1] for e in es][:800],
            "manual": o["relations"]["manual"], "auto": o["relations"]["auto"]}
