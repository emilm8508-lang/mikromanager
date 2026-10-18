"""The map of the whole network: gateway -> routers -> switches -> computers, built from what the devices themselves report.

Where L0p4Map-style tools guess the structure (traceroute, TTL), this one reads it: the routers' and switches' LLDP / MNDP neighbours and
their MAC tables (the same readings as the rack view, services/racks.py), the DHCP / ARP tables, the addresses of the routers' interfaces.

  nodes   every active asset (+ "Internet" above the routers that have a WAN link, + a small hub per subnet for what could not be placed)
  edges   backbone  switch/router <-> switch/router, seen by LLDP / MNDP
          uplink    an infrastructure device on the port of another one (its MAC was learned there), or its parent in the tree
          client    a computer / printer / camera ... on the access port of a switch (the MAC learned on the port with fewest MACs behind it,
                    no LLDP neighbour - an uplink is never taken for an access port)
          l3        no port is known: placed under the router that has an interface in the same subnet (dashed)
          vm        a virtual machine under its Hyper-V host
  levels  0 Internet, 1 routers, then one more per hop; clients one below what they hang on - the hierarchical layout of the page.

The readings of the devices can be slow (unreachable routers time out), so `get_map()` never waits for them: it returns the last map and refreshes
it in the background; until the first one is ready, a quick map from the database alone (assets + stored links) is returned (`partial`)."""
import asyncio
import ipaddress
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset, Device, DeviceLink
from services import racks

TTL = 300.0
MAX_ACCESS_MACS = 48                    # a port with more MACs than this is not taken for an access port
STALE_DAYS = 7
_SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_cache: dict = {"at": 0.0, "data": None}
_task: Optional[asyncio.Task] = None


def _jload(s, default):
    return racks._jload(s, default)


def _networks(addresses: list) -> List[ipaddress.IPv4Network]:
    out = []
    for a in addresses or []:
        v = a.get("address") if isinstance(a, dict) else a
        try:
            n = ipaddress.ip_interface(str(v)).network
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen < 32 and not n.is_loopback and not n.is_link_local:
            out.append(n)
    return out


def _vuln_marks(findings: List[dict]) -> tuple:
    """(worst severity 0-4, open count) of one host's findings."""
    worst, n = 0, 0
    for f in findings or []:
        if (f.get("status") or "open") in ("open", "in_progress"):
            n += 1
            worst = max(worst, _SEV.get(str(f.get("severity") or "").upper(), 0))
    return worst, n


async def _vulns() -> Dict[str, List[dict]]:
    try:
        from services import assets as assets_svc
        return await assets_svc._vulns_by_ip()
    except Exception:
        return {}


def _asset_nodes(db, vulns: Dict[str, List[dict]]) -> Dict[int, dict]:
    now = datetime.utcnow()
    nodes: Dict[int, dict] = {}
    for a in db.execute(select(Asset)).scalars().all():
        if a.key.startswith(("mon:", "prt:")) or a.asset_type == "monitor":
            continue
        if not a.last_seen_at or now - a.last_seen_at > timedelta(days=STALE_DAYS):
            continue
        refs = _jload(a.refs, {})
        worst, n = _vuln_marks(vulns.get(a.ip or "", []))
        nodes[a.id] = {"id": a.id, "name": a.name or a.ip or a.key, "type": a.asset_type, "role": a.role, "ip": a.ip, "mf": a.manufacturer, "md": a.model,
                       "v": worst, "vn": n, "sub": None, "lvl": None, "cls": _jload(a.details, {}).get("_class"), "_via": _jload(a.details, {}).get("_via"), "_refs": refs, "_mac": racks._norm_mac(a.mac),
                       "_macs": {m for m in [racks._norm_mac(a.mac)] + [racks._norm_mac(x.get("mac")) for x in (_jload(a.details, {}).get("network_adapters") or [])] if m},
                       "_host": (_jload(a.details, {}).get("host") or None) if a.asset_type == "virtual" else None}
    return nodes


def _stored_edges(nodes: Dict[int, dict], db) -> List[dict]:
    """The device-to-device links the topology discovery stored (LLDP / MNDP / tunnels), as backbone edges between the assets."""
    by_dev = {n["_refs"].get("device_id"): i for i, n in nodes.items() if n["_refs"].get("device_id")}
    edges = []
    for l in db.execute(select(DeviceLink)).scalars().all():
        a, b = by_dev.get(l.device_a_id), by_dev.get(l.device_b_id)
        if a and b:
            edges.append({"a": a, "b": b, "k": "backbone", "l": " ↔ ".join(x for x in (l.interface_a, l.interface_b) if x)})
    return edges


def _quick(nodes: Dict[int, dict], db) -> dict:
    """The map from the database alone: assets and the stored links, nothing read from a device."""
    return _finish(nodes, _stored_edges(nodes, db), partial=True)


def _subnet_of(ip: Optional[str], known: List[ipaddress.IPv4Network]) -> Optional[str]:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    if a.version != 4:
        return None
    best = None
    for n in known:
        if a in n and (best is None or n.prefixlen > best.prefixlen):
            best = n
    return str((best or ipaddress.ip_network(f"{a}/24", strict=False)))


def _finish(nodes: Dict[int, dict], edges: List[dict], partial: bool, routers: Optional[set] = None, nets_by_node: Optional[Dict[int, list]] = None,
            wan: Optional[dict] = None, adjacent: Optional[Dict[int, set]] = None, routed: Optional[Dict[int, int]] = None) -> dict:
    """Subnets, the hubs for what has no port, the levels. Pure: works on the nodes / edges it is given."""
    routers = routers or set()
    nets_by_node = nets_by_node or {}
    known = sorted({n for ns in nets_by_node.values() for n in ns}, key=lambda n: -n.prefixlen)
    for n in nodes.values():
        n["sub"] = _subnet_of(n["ip"], known)

    # who has a parent already (one edge into a client / infrastructure device); the rest are placed by subnet
    attached = {e["b"] for e in edges if e["k"] in ("client", "uplink", "vm")} | {e["a"] for e in edges if e["k"] in ("backbone",)} | {e["b"] for e in edges if e["k"] == "backbone"}
    adjacent = adjacent or {}
    routed = routed or {}
    claimants: Dict[str, set] = {}                       # subnet -> the routers that have an interface in it
    for rid in routers:
        for net in nets_by_node.get(rid, []):
            claimants.setdefault(str(net), set()).add(rid)
    hubs: Dict[str, dict] = {}
    for i, n in list(nodes.items()):
        if i in attached or i in routers:
            continue
        if n["type"] in ("network",) and not n["sub"]:
            continue
        sub = n["sub"]
        if not sub:
            continue
        # Which router is it under? A subnet alone is not evidence - two sites often use the same numbering (192.168.1.0/24 at both ends of a
        # tunnel) and a router's interface in "its" 192.168.1.0/24 says nothing about a host of the other site. The evidence is that the router's own
        # DHCP leases / ARP table list the host (it is on that router's segment); only when there is a single router at all is the subnet enough.
        rid, how = None, ""
        seen_by = {r for r in adjacent.get(i, set()) if r in routers and r != i}
        if len(seen_by) > 1:
            both = [r for r in seen_by if r in claimants.get(sub, set())]
            seen_by = set(both) if both else seen_by
        if len(seen_by) == 1:
            rid, how = next(iter(seen_by)), "ARP/DHCP"
        elif i in routed and routed[i] != i:
            rid, how = routed[i], "traceroute"                    # the last router on the path to it is its gateway
        elif len(routers) == 1:
            only = next(iter(routers))
            if only in claimants.get(sub, set()) and only != i:
                rid, how = only, "subnet"
        if rid is not None and rid != i:
            edges.append({"a": rid, "b": i, "k": "l3", "l": f"{how} · {sub}"})
        else:
            hub = hubs.setdefault(sub, {"id": f"sub:{sub}", "name": sub, "type": "subnet", "role": None, "ip": None, "mf": None, "md": None, "v": 0, "vn": 0, "sub": sub, "lvl": None})
            edges.append({"a": hub["id"], "b": i, "k": "l3", "l": ""})
    for sub, hub in hubs.items():
        nodes[hub["id"]] = hub

    # "Internet" above the routers that have a WAN link
    wan = wan or {}
    if wan:
        nodes["internet"] = {"id": "internet", "name": "Internet", "type": "internet", "role": None, "ip": None, "mf": None, "md": None, "v": 0, "vn": 0, "sub": None, "lvl": 0}
        for rid, st in wan.items():
            if rid in nodes:
                edges.append({"a": "internet", "b": rid, "k": "uplink", "l": ("WAN " + st) if st else "WAN"})

    # levels: BFS from Internet / the routers over the infrastructure links, clients one below their parent
    adj: Dict = {}
    for e in edges:
        adj.setdefault(e["a"], []).append(e["b"])
        adj.setdefault(e["b"], []).append(e["a"])
    level: Dict = {}
    roots = ["internet"] if "internet" in nodes else sorted(routers, key=lambda r: -len(adj.get(r, [])))[:1]
    queue = list(roots)
    for r in roots:
        level[r] = 0 if r == "internet" else 1
    if "internet" in nodes:
        for rid in wan:
            if rid in nodes:
                level.setdefault(rid, 1)
                queue.append(rid)
    infra_edge = {"backbone", "uplink"}
    while queue:
        cur = queue.pop(0)
        for e in edges:
            if e["k"] not in infra_edge:
                continue
            other = e["b"] if e["a"] == cur else e["a"] if e["b"] == cur else None
            if other is not None and other not in level and other in nodes:
                level[other] = level[cur] + 1
                queue.append(other)
    for _ in range(4):                       # clients and hubs hang one below their parent; repeated so that hub -> client works out
        for e in edges:
            if e["k"] in ("client", "l3", "vm") and e["a"] in level and e["b"] not in level:
                level[e["b"]] = level[e["a"]] + 1
    deepest = max(level.values(), default=1)
    for i, n in nodes.items():
        n["lvl"] = level.get(i, deepest + 1 if n["type"] != "subnet" else deepest)
    subnets: Dict[str, int] = {}
    for n in nodes.values():
        if n.get("sub") and n["type"] != "subnet":
            subnets[n["sub"]] = subnets.get(n["sub"], 0) + 1
    clean = [{k: v for k, v in n.items() if not k.startswith("_")} for n in nodes.values()]
    return {"nodes": clean, "edges": edges, "subnets": [{"cidr": c, "n": k} for c, k in sorted(subnets.items())],
            "at": datetime.utcnow().isoformat() + "Z", "partial": partial}


async def _full() -> dict:
    vulns = await _vulns()
    with SessionLocal() as db:
        nodes = _asset_nodes(db, vulns)
    infra = [i for i, n in nodes.items() if n["type"] == "network" and n["ip"]]
    keys: Dict[int, int] = {}
    for i in infra:
        refs = nodes[i]["_refs"]
        keys[i] = refs["device_id"] if refs.get("device_id") else -i
    from services import host_monitor
    try:
        directory = await host_monitor.directory(max_age=3600)
    except Exception:
        directory = []
    snaps: Dict[int, Optional[dict]] = {}
    sem = asyncio.Semaphore(4)

    async def one(i):
        async with sem:
            try:
                snaps[i] = await racks._snapshot(keys[i])
            except Exception:
                snaps[i] = None

    await asyncio.gather(*(one(i) for i in infra))
    edges: List[dict] = []
    nets_by_node: Dict[int, list] = {}
    routers: set = set()
    where: Dict[str, list] = {}
    seen_pairs = set()
    with SessionLocal() as db:
        resolver = racks._Resolver(db, directory)
        ip_assets = {a.ip: {"asset_id": a.id} for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()}
        quick_edges = _stored_edges(nodes, db)
        for i in infra:
            snap = snaps.get(i)
            if not snap or "ifaces" not in snap:
                continue
            nets = _networks(snap.get("addresses") or [])
            nets_by_node[i] = nets
            if len({str(n) for n in nets}) >= 2 or (nodes[i]["_refs"].get("device_id") and (nodes[i]["mf"] or "").lower() == "mikrotik" and nets):
                routers.add(i)
            for p in racks._ports_from_snapshot(snap, {}, resolver, ip_assets):
                macs = p.pop("_macs", [])
                r = p.get("remote") or {}
                if r.get("kind") == "lldp":
                    j = r.get("asset_id")
                    if j in nodes and j != i:
                        key = tuple(sorted([(i, p["name"]), (j, r.get("port") or "")], key=str))
                        if key not in seen_pairs:
                            seen_pairs.add(key)
                            edges.append({"a": i, "b": j, "k": "backbone", "l": " ↔ ".join(x for x in (p["name"], r.get("port")) if x)})
                    continue
                for m in macs:
                    where.setdefault(m, []).append((len(macs), i, p["name"], p.get("vlan")))
        linked = {frozenset((e["a"], e["b"])) for e in edges}
        for e in quick_edges:                                         # stored links for devices that did not answer now
            if frozenset((e["a"], e["b"])) not in linked:
                edges.append(e)
                linked.add(frozenset((e["a"], e["b"])))
    # computers (and infrastructure devices whose LLDP did not tell) on the access port of a switch
    for i, n in nodes.items():
        if i in infra and any(e["k"] == "backbone" and i in (e["a"], e["b"]) for e in edges):
            continue
        cands = [c for m in n["_macs"] for c in where.get(m, []) if c[1] != i]
        if not cands:
            continue
        _cnt, sw, port, vlan = min(cands)
        if _cnt > MAX_ACCESS_MACS:
            continue                                  # that many MACs behind a port is a trunk / a tunnel / another site, not where this host is plugged in
        edges.append({"a": sw, "b": i, "k": "uplink" if i in infra else "client", "l": f"{port}" + (f" · VLAN {vlan}" if vlan else "")})
    # virtual machines under their Hyper-V host
    by_name = {n["name"].casefold(): i for i, n in nodes.items() if n["type"] in ("windows", "server") and n["name"]}
    for i, n in nodes.items():
        if n["type"] == "virtual" and n["_host"] and by_name.get(str(n["_host"]).casefold()) not in (None, i):
            edges.append({"a": by_name[str(n["_host"]).casefold()], "b": i, "k": "vm", "l": ""})
    # the WAN link status of the routers (devices -> assets)
    wan: Dict[int, str] = {}
    try:
        from services import edge_discovery
        st = edge_discovery.get_wan_link_status()
        dev2asset = {n["_refs"].get("device_id"): i for i, n in nodes.items() if n["_refs"].get("device_id")}
        for did in edge_discovery.wan_capable_device_ids():              # a real gateway router: a "WAN" interface list
            if dev2asset.get(did):
                routers.add(dev2asset[did])
        for did, info in (st or {}).items():
            aid = dev2asset.get(did)
            if aid:
                wan[aid] = "up" if (info or {}).get("status") == "up" or (info or {}).get("running") else "down"
                routers.add(aid)
    except Exception:
        pass
    # which router's DHCP leases / ARP table lists which asset: the evidence that a host is on that router's segment
    adjacent: Dict[int, set] = {}
    try:
        by_ip = {n["ip"]: i for i, n in nodes.items() if n["ip"]}
        by_name = {n["name"].casefold(): i for i, n in nodes.items() if n["name"] and n["_refs"].get("device_id")}
        for e in directory:
            i = by_ip.get(e.get("ip"))
            if i is None:
                continue
            for dn in e.get("devices") or []:
                r = by_name.get(str(dn).casefold())
                if r is not None:
                    adjacent.setdefault(i, set()).add(r)
    except Exception:
        pass
    # the last hop of a traceroute is a router's own address: an asset with that address, or an interface address of a router we read
    owner = {n["ip"]: i for i, n in nodes.items() if n["ip"]}
    for rid, nets in {i: snaps[i].get("addresses") for i in infra if snaps.get(i) and "ifaces" in snaps[i]}.items():
        for a in nets or []:
            try:
                owner.setdefault(str(ipaddress.ip_interface(str(a.get("address") if isinstance(a, dict) else a)).ip), rid)
            except ValueError:
                pass
    routed = {i: owner[n["_via"]] for i, n in nodes.items() if n.get("_via") in owner and owner[n["_via"]] != i}
    for r in routed.values():
        routers.add(r)
    return _finish(nodes, edges, partial=False, routers=routers, nets_by_node=nets_by_node, wan=wan, adjacent=adjacent, routed=routed)


async def _refresh() -> None:
    try:
        _cache["data"] = await _full()
    except Exception as e:
        print(f"[topology_map] build error: {e}")
    _cache["at"] = time.time()


async def get_map(force: bool = False) -> dict:
    """The last map; a rebuild runs in the background when it is older than TTL (or `force`). Never waits for the devices."""
    global _task
    if (force or _cache["data"] is None or time.time() - _cache["at"] > TTL) and (_task is None or _task.done()):
        _task = asyncio.create_task(_refresh())
    if _cache["data"] is not None:
        return {**_cache["data"], "building": bool(_task and not _task.done())}
    vulns = await _vulns()
    with SessionLocal() as db:
        nodes = _asset_nodes(db, vulns)
        data = _quick(nodes, db)
    return {**data, "building": True}


def public_summary(data: Optional[dict] = None) -> Optional[dict]:
    """Compact copy for Central: nodes as arrays, no addresses of anything but the nodes themselves (the same IPs the inventory sends)."""
    d = data or _cache["data"]
    if not d:
        return None
    return {"n": [[n["id"], n["name"], n["type"], n.get("ip"), n.get("v", 0), n.get("sub"), n.get("lvl"), n.get("cls")] for n in d["nodes"]],
            "e": [[e["a"], e["b"], e["k"], e.get("l") or ""] for e in d["edges"]], "at": d["at"]}
