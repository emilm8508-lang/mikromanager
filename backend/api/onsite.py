"""The "on site" view: what is connected where, for the person who is standing next to the equipment.

A read-only slice of the inventory - the name, address, MAC, kind and place of every device, the switch and port it is plugged into, and the ports of a
chosen switch - without the rest of the application (no vulnerabilities, credentials, serial numbers, commands). It can be opened in two ways:

  - by a logged-in user (an administrator opens it from the menu);
  - by a link with a key, which the administrator creates and can switch off or replace at any time ("share"): the key travels in the X-Onsite-Key
    header (the page takes it from the link's # part, which is never sent to a server or written to a log). It works for these GET endpoints only.

The key is long and random; a wrong one is counted per address and after a few attempts the address is refused for a while."""
import hmac
import json
import os
import secrets
import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import require_login
from services import assets as assets_svc, auth as auth_svc, topology_map

router = APIRouter(prefix="/api/onsite", tags=["onsite"])

_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "onsite.json")
MAX_FAILS = 20
FAIL_WINDOW_SEC = 600
_fails: Dict[str, List[float]] = {}


def _load() -> dict:
    try:
        with open(_CFG_PATH, encoding="utf-8") as f:
            v = json.load(f)
            return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def _save(cfg: dict) -> None:
    os.makedirs(os.path.dirname(_CFG_PATH), exist_ok=True)
    tmp = _CFG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    os.replace(tmp, _CFG_PATH)


def require_onsite(request: Request) -> dict:
    """A valid session, or the shared key (when sharing is on). Never both required."""
    token = request.cookies.get(auth_svc.SESSION_COOKIE)
    if token:
        session = auth_svc.verify_session_token(token)
        if session is not None:
            return {"via": "session", "role": session.get("role"), "username": session.get("username")}
    key = request.headers.get("X-Onsite-Key", "")
    addr = request.client.host if request.client else "?"
    now = time.time()
    recent = [t for t in _fails.get(addr, []) if now - t < FAIL_WINDOW_SEC]
    if len(recent) >= MAX_FAILS:
        raise HTTPException(429, "too many attempts, try again later")
    cfg = _load()
    if key and cfg.get("enabled") and cfg.get("key") and hmac.compare_digest(key.encode(), str(cfg["key"]).encode()):
        return {"via": "key"}
    if key:
        _fails[addr] = recent + [now]
    raise HTTPException(401, "not authenticated")


def _place(r: dict) -> dict:
    """The fields of an asset the on-site view may show - nothing about vulnerabilities, credentials, serial numbers."""
    at = r.get("attach")
    return {"id": r["id"], "name": r["name"], "ip": r["ip"], "mac": r["mac"], "type": r["type"], "dclass": r.get("dclass"), "manufacturer": r["manufacturer"],
            "model": r["model"], "location": r["location"], "place": r.get("place"), "last_seen_at": r["last_seen_at"], "active": r["active"],
            "attach": ({"to": at["to"], "to_id": at["to_id"], "port": at["port"], "vlan": at["vlan"], "shared": at["shared"], "kind": at["kind"], "how": at["how"],
                        "iface": at.get("iface"), "ssid": at.get("ssid"), "signal": at.get("signal")} if at else None)}


@router.get("/hosts")
async def hosts(all: bool = False, _ctx: dict = Depends(require_onsite)):
    """Every device (the active ones, or all) with where it is plugged in and its physical place, and the state of the map this comes from."""
    rows = await assets_svc.list_assets()
    return {"items": [_place(r) for r in rows if all or r["active"]], "map": topology_map.map_state()}


@router.get("/switches")
async def switches(_ctx: dict = Depends(require_onsite)):
    """The switches / routers that have devices learned on their ports, with how many ports and devices."""
    att = topology_map.attachments()
    rows = {r["id"]: r for r in await assets_svc.list_assets()}
    by_sw: Dict[int, dict] = {}
    for aid, a in att.items():
        if a.get("to_id") in rows and aid in rows and (a.get("port") or a.get("kind") == "wifi"):
            s = by_sw.setdefault(a["to_id"], {"ports": set(), "hosts": 0, "wifi": 0})
            if a.get("kind") == "wifi":
                s["wifi"] += 1
            else:
                s["ports"].add(a["port"])
                s["hosts"] += 1
    out = [{"id": sid, "name": rows[sid]["name"], "ip": rows[sid]["ip"], "ports": len(s["ports"]), "hosts": s["hosts"], "wifi": s["wifi"], "place": rows[sid].get("place")}
           for sid, s in by_sw.items()]
    return {"items": sorted(out, key=lambda x: x["name"].lower()), "map": topology_map.map_state()}


@router.get("/switch/{switch_id}")
async def switch(switch_id: int, _ctx: dict = Depends(require_onsite)):
    """The ports of one switch that have something learned on them, in port order, with the devices on each."""
    rows = {r["id"]: r for r in await assets_svc.list_assets()}
    sw = rows.get(switch_id)
    if sw is None:
        raise HTTPException(404, "device not found")
    ports = []
    for p in topology_map.ports_of(switch_id):
        devs = [_place(rows[i]) for i in p["devices"] if i in rows]
        ports.append({"port": p["port"], "vlan": p["vlan"], "devices": sorted(devs, key=lambda d: d["name"].lower())})
    wifi = []
    for g in topology_map.wifi_of(switch_id):
        devs = []
        for i, signal in g["devices"]:
            if i in rows:
                devs.append({**_place(rows[i]), "signal": signal})
        wifi.append({"ssid": g["ssid"], "iface": g["iface"], "devices": devs})
    return {"switch": {"id": sw["id"], "name": sw["name"], "ip": sw["ip"], "place": sw.get("place")}, "ports": ports, "wifi": wifi, "map": topology_map.map_state()}


class ShareIn(BaseModel):
    enabled: Optional[bool] = None
    regenerate: bool = False


@router.get("/share")
def share_get(user: dict = Depends(require_login)):
    """The state of the shared link (the key is shown to administrators only)."""
    cfg = _load()
    admin = user.get("role") == "admin"
    return {"enabled": bool(cfg.get("enabled")), "key": cfg.get("key") if admin and cfg.get("enabled") else None, "admin": admin}


@router.post("/share")
def share_set(body: ShareIn, user: dict = Depends(require_login)):
    """Switches the shared link on / off and/or replaces its key (the old link stops working at once)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "administrators only")
    cfg = _load()
    if body.enabled is not None:
        cfg["enabled"] = body.enabled
    if body.regenerate or (cfg.get("enabled") and not cfg.get("key")):
        cfg["key"] = secrets.token_urlsafe(24)
    _save(cfg)
    return {"enabled": bool(cfg.get("enabled")), "key": cfg.get("key") if cfg.get("enabled") else None, "admin": True}
