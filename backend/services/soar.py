"""
Response actions with approval: from "I see it" to "I did something about it" - a human decides, the agent does it.

The SOC layer finds an address hammering a router with logins; until now the answer was to open the router and block it by hand. Here the first response action is built, with
the guard rails a security tool that touches firewalls needs:

  * an action is a PROPOSAL until a person approves it - from an alert ("block 203.0.113.9"), or typed in; nothing is ever executed on detection alone;
  * the only action is to put one address on the address list `mm-blocked` of the chosen MikroTik routers WITH A TIMEOUT (15 minutes to 7 days, 24 hours by default) - the router
    removes it by itself - and to take it off again; a drop rule for that list (firewall raw, prerouting, at the top) is installed only on a separate approval, because a list
    that nothing drops changes nothing, and a firewall rule is the operator's to allow;
  * what may not be blocked: private, loopback, link-local, multicast and reserved addresses (a compromised internal host is a different action, with a typed confirmation
    that says so), the agent's own address, the routers' own addresses and anything the inventory knows as network equipment; one address at a time, never a network; at most
    MAX_ACTIVE blocks at once;
  * the approval comes from the agent's page, or from Central by a signed command when `central_approval` is switched on here; who proposed, who approved, on which routers and
    with what result is kept in `soar_actions` and written to the alert's trail;
  * the whole feature is OFF until it is switched on.
"""
import asyncio
import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Device, Credential, Asset, SoarAction

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "soar.json")
DEFAULTS = {"enabled": False, "central_approval": False}
MIN_TTL, MAX_TTL, DEFAULT_TTL = 15, 7 * 24 * 60, 24 * 60
MAX_ACTIVE = 50
PROPOSAL_HOURS = 24
KINDS = ("block_ip", "install_rule")
_settings: Dict = dict(DEFAULTS)
_client_factory = None                  # tests put a fake here: (device, credential) -> client


# ── Settings ─────────────────────────────────────────────────────────────────

def load_settings() -> Dict:
    s = dict(DEFAULTS)
    try:
        with open(_PATH, encoding="utf-8") as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except Exception:
        pass
    _settings.clear()
    _settings.update(s)
    return _settings


def settings() -> Dict:
    return dict(_settings)


def update_settings(body: Dict) -> Dict:
    new = dict(_settings)
    for k in DEFAULTS:
        if body.get(k) is not None:
            new[k] = bool(body[k])
    _settings.clear()
    _settings.update(new)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f)
    os.replace(tmp, _PATH)
    return settings()


def _now() -> datetime:
    return datetime.utcnow()


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


# ── What may be blocked ──────────────────────────────────────────────────────

def _own_addresses() -> set:
    own = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            own.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))          # no packet is sent: it only picks the interface the OS would use
            own.add(s.getsockname()[0])
    except OSError:
        pass
    return own


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


def _is_internal(a) -> bool:
    return any(a in n for n in _INTERNAL)


def validate_target(ip: str, allow_internal: bool = False) -> str:
    """The normalised address, or ValueError saying why it must not be blocked."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError("a single IP address is required (a network or a name cannot be blocked here)")
    if a.version != 4:
        raise ValueError("only IPv4 addresses can be blocked")
    if a.is_unspecified or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local or str(a) == "255.255.255.255":
        raise ValueError("this address can never be blocked")
    if str(a) in _own_addresses():
        raise ValueError("this is the address of the agent itself")
    with SessionLocal() as db:
        if db.execute(select(Device.id).where(Device.ip == str(a)).limit(1)).first():
            raise ValueError("this is a managed router / device of this agent")
        asset = db.execute(select(Asset).where(Asset.ip == str(a)).limit(1)).scalars().first()
        if asset is not None and asset.asset_type == "network":
            raise ValueError("the inventory knows this address as network equipment")
    if _is_internal(a) and not allow_internal:
        raise ValueError("an internal address: blocking it cuts a host of this network off - confirm it explicitly")
    return str(a)


def candidates(alert: dict) -> List[str]:
    """The addresses an alert is about that may be blocked: the sources and the source address of its evidence, and any address in its message."""
    d = alert.get("detail") or {}
    found: List[str] = []
    for v in (d.get("sources") or []) + [d.get("src_ip")]:
        if v:
            found.append(str(v))
    found += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(d.get("message") or ""))
    out: List[str] = []
    for v in found:
        try:
            out.append(validate_target(v))
        except ValueError:
            continue
    return list(dict.fromkeys(out))


def routers() -> List[dict]:
    """The routers an address can be blocked on: MikroTik devices with a credential."""
    with SessionLocal() as db:
        return [{"id": d.id, "name": d.name or d.ip, "ip": d.ip, "online": bool(d.online), "mgmt_ok": d.mgmt_ok}
                for d in db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all() if (d.vendor or "mikrotik") == "mikrotik"]


# ── Proposals ────────────────────────────────────────────────────────────────

def _view(a: SoarAction, names: Dict[int, str]) -> dict:
    try:
        res = json.loads(a.result) if a.result else []
    except Exception:
        res = []
    ids = json.loads(a.device_ids or "[]")
    return {"id": a.id, "kind": a.kind, "target": a.target, "devices": [{"id": i, "name": names.get(i, str(i))} for i in ids], "ttl_min": a.ttl_min, "reason": a.reason, "alert_id": a.alert_id,
            "status": a.status, "proposed_by": a.proposed_by, "proposed_at": _iso(a.proposed_at), "decided_by": a.decided_by, "decided_at": _iso(a.decided_at), "executed_at": _iso(a.executed_at),
            "expires_at": _iso(a.expires_at), "result": res, "internal": bool(a.internal)}


def _alert_log(alert_id: Optional[int], who: str, action: str, value=None) -> None:
    if not alert_id:
        return
    try:
        from models.database import SocAlert
        from services import soc
        with SessionLocal() as db:
            row = db.get(SocAlert, alert_id)
            if row is not None:
                soc._log(row, who, action, value)
                db.commit()
    except Exception as e:
        print(f"[soar] alert trail: {e}")


def propose(kind: str, target: Optional[str], device_ids: List[int], *, ttl_min: int = DEFAULT_TTL, reason: str = "", alert_id: Optional[int] = None, user: str = "?",
            allow_internal: bool = False) -> int:
    """A proposal waiting for approval. Raises ValueError for anything the guard rails refuse."""
    if not _settings.get("enabled"):
        raise ValueError("response actions are switched off")
    if kind not in KINDS:
        raise ValueError("unknown action")
    ids = list(dict.fromkeys(int(i) for i in device_ids or []))
    valid = {r["id"] for r in routers()}
    if not ids or any(i not in valid for i in ids):
        raise ValueError("choose MikroTik routers that have a credential")
    now = _now()
    t = None
    if kind == "block_ip":
        t = validate_target(target or "", allow_internal)
        ttl_min = int(ttl_min)
        if not (MIN_TTL <= ttl_min <= MAX_TTL):
            raise ValueError("the block lasts between 15 minutes and 7 days")
        with SessionLocal() as db:
            active = db.execute(select(SoarAction).where(SoarAction.kind == "block_ip", SoarAction.status == "executed", SoarAction.expires_at > now)).scalars().all()
            if len(active) >= MAX_ACTIVE:
                raise ValueError(f"too many active blocks ({MAX_ACTIVE})")
            dup = db.execute(select(SoarAction).where(SoarAction.kind == "block_ip", SoarAction.target == t, SoarAction.status == "pending")).scalars().first()
            if dup is not None:
                raise ValueError("this address already has a proposal waiting")
    else:
        ttl_min = 0
    reason = (reason or "").strip()[:300]
    if not reason:
        raise ValueError("say why (the reason is kept with the action)")
    with SessionLocal() as db:
        a = SoarAction(kind=kind, target=t, device_ids=json.dumps(ids), ttl_min=ttl_min, reason=reason, alert_id=alert_id, status="pending", proposed_by=user, proposed_at=now,
                       expires_at=now + timedelta(hours=PROPOSAL_HOURS), internal=bool(t and _is_internal(ipaddress.ip_address(t))))
        db.add(a)
        db.commit()
        aid = a.id
    _alert_log(alert_id, user, "response_proposed", f"{kind} {t or ''}".strip())
    return aid


def _expire_old() -> None:
    now = _now()
    with SessionLocal() as db:
        for a in db.execute(select(SoarAction).where(SoarAction.status == "pending", SoarAction.expires_at < now)).scalars().all():
            a.status = "expired"
        db.commit()


async def decide(action_id: int, approve: bool, user: str, via: str = "agent") -> dict:
    """Approve (and execute) or reject a proposal. Returns the action view; raises ValueError / LookupError."""
    _expire_old()
    if not _settings.get("enabled"):
        raise ValueError("response actions are switched off")
    if via != "agent" and not _settings.get("central_approval"):
        raise ValueError("approval from Central is not allowed on this agent")
    with SessionLocal() as db:
        a = db.get(SoarAction, action_id)
        if a is None:
            raise LookupError("action not found")
        if a.status != "pending":
            raise ValueError(f"the action is already {a.status}")
        a.decided_by, a.decided_at = user, _now()
        a.status = "approved" if approve else "rejected"
        alert_id = a.alert_id
        db.commit()
    _alert_log(alert_id, user, "response_approved" if approve else "response_rejected", action_id)
    if approve:
        await execute(action_id)
    return get(action_id)


def _client(device: Device, cred: Credential):
    if _client_factory is not None:
        return _client_factory(device, cred)
    from services.device_client import build_client
    return build_client(device, cred)


def _ttl_text(minutes: int) -> str:
    d, rem = divmod(minutes, 1440)
    h, m = divmod(rem, 60)
    return (f"{d}d" if d else "") + (f"{h:02d}:{m:02d}:00" if (h or m or not d) else "")


async def execute(action_id: int) -> None:
    """Does an approved action on each chosen router and records what happened per router."""
    with SessionLocal() as db:
        a = db.get(SoarAction, action_id)
        if a is None or a.status != "approved":
            return
        kind, target, ids, ttl, alert_id, who = a.kind, a.target, json.loads(a.device_ids or "[]"), a.ttl_min, a.alert_id, a.decided_by
        pairs = []
        for i in ids:
            d = db.get(Device, i)
            c = db.get(Credential, d.credential_id) if d and d.credential_id else None
            pairs.append((d, c))
    results = []
    comment = f"MikroManager SOAR #{action_id} {who}"
    for d, c in pairs:
        name = (d.name or d.ip) if d else "?"
        if d is None or c is None:
            results.append({"device": name, "ok": False, "error": "no credential"})
            continue
        try:
            cl = _client(d, c)
            if kind == "block_ip":
                await cl.blocklist_add(target, _ttl_text(ttl), comment)
                present = await cl.block_rule_present()
                results.append({"device": name, "ok": True, "rule_present": present})
            else:
                where = await cl.block_rule_install()
                results.append({"device": name, "ok": True, "rule_present": True, "position": where})
        except Exception as e:
            results.append({"device": name, "ok": False, "error": f"{type(e).__name__}: {e}"[:200]})
    ok = [r for r in results if r["ok"]]
    now = _now()
    with SessionLocal() as db:
        a = db.get(SoarAction, action_id)
        a.result = json.dumps(results, ensure_ascii=False)
        a.status = "executed" if ok else "failed"
        a.executed_at = now
        a.expires_at = now + timedelta(minutes=ttl) if kind == "block_ip" else now
        db.commit()
    _alert_log(alert_id, "auto", "response_done", f"{len(ok)}/{len(results)}")
    try:
        from services import activity
        activity.record("soar_" + kind, target=target, devices=len(ok), approved_by=who)
    except Exception:
        pass


async def unblock(target: str, user: str) -> dict:
    """Takes an address off the list of every router that has it (no approval: it only restores the traffic)."""
    results = []
    with SessionLocal() as db:
        pairs = []
        for d in db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all():
            if (d.vendor or "mikrotik") == "mikrotik":
                pairs.append((d, db.get(Credential, d.credential_id)))
    for d, c in pairs:
        try:
            n = await _client(d, c).blocklist_remove(target)
            if n:
                results.append({"device": d.name or d.ip, "removed": n})
        except Exception as e:
            results.append({"device": d.name or d.ip, "error": f"{type(e).__name__}: {e}"[:200]})
    with SessionLocal() as db:
        for a in db.execute(select(SoarAction).where(SoarAction.kind == "block_ip", SoarAction.target == target, SoarAction.status == "executed")).scalars().all():
            a.status, a.expires_at = "lifted", _now()
            _alert_log(a.alert_id, user, "response_lifted", target)
        db.commit()
    return {"results": results}


def get(action_id: int) -> dict:
    with SessionLocal() as db:
        a = db.get(SoarAction, action_id)
        if a is None:
            raise LookupError("action not found")
        names = {d.id: d.name or d.ip for d in db.execute(select(Device)).scalars().all()}
        return _view(a, names)


def overview() -> dict:
    _expire_old()
    now = _now()
    with SessionLocal() as db:
        names = {d.id: d.name or d.ip for d in db.execute(select(Device)).scalars().all()}
        rows = db.execute(select(SoarAction).order_by(SoarAction.id.desc()).limit(200)).scalars().all()
        views = [_view(a, names) for a in rows]
    return {"settings": settings(), "pending": [v for v in views if v["status"] == "pending"],
            "active": [v for v in views if v["status"] == "executed" and v["kind"] == "block_ip" and v["expires_at"] and v["expires_at"] > _iso(now)],
            "history": [v for v in views if v["status"] not in ("pending",)][:60], "routers": routers()}


def public_summary() -> dict:
    """For Central: the proposals waiting for approval and the number of active blocks (addresses of attackers are public ones, nothing internal)."""
    ov = overview()
    return {"enabled": bool(_settings.get("enabled")), "central_approval": bool(_settings.get("central_approval")),
            "pending": [{"id": p["id"], "kind": p["kind"], "target": None if p["internal"] else p["target"], "devices": [d["name"] for d in p["devices"]][:6], "ttl_min": p["ttl_min"], "reason": p["reason"][:120],
                         "by": p["proposed_by"], "at": p["proposed_at"], "internal": p["internal"]} for p in ov["pending"]][:20],
            "active": len(ov["active"])}
