"""
The agent's own traffic and accounts (3.77, round 3 stage D of docs/plan-runda-3.md).

The agent polls every router and host of the client: its address and its accounts are everywhere in the data, and they are not a
person's or an attacker's. Seen at sanmed: the agent (192.168.1.38) trying ~30 ports of a dead address (192.168.2.94) - counted as that
address's traffic and anomaly; "user webshot logged in / out" many times a minute in the routers' logs.

  addresses()   the agent's own addresses: configured (data/agent_self.json "addresses") and the ones it reaches the devices from
  accounts()    the agent's accounts on the devices: configured ("accounts") and the user names of its credentials
  covers()      whether a scan of the agent stays inside its declared scope ("scan_ports", "scan_hours"; default: any port, any hour) -
                inside: not a scan alert; beyond it: alerted like any other source
  logins()      the agent's own API logins per router in the last hour (services/mikrotik_client.pooled_call notes them)
"""
import json
import os
import socket
import time
from collections import deque
from typing import Deque, Dict, Iterable, List, Optional, Set

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "agent_self.json")
_cache = {"at": 0.0, "addr": set()}
_logins: Dict[str, Deque[float]] = {}


def settings() -> dict:
    try:
        with open(_PATH, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def addresses() -> Set[str]:
    """The agent's addresses (cached 10 min)."""
    if time.time() - _cache["at"] < 600 and _cache["addr"]:
        return set(_cache["addr"])
    out: Set[str] = {str(a) for a in (settings().get("addresses") or []) if isinstance(a, str)}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                out.add(ip)
    except OSError:
        pass
    try:                                                  # the address the agent reaches each router from (one UDP "connect", nothing sent)
        from models.database import SessionLocal, Device
        from sqlalchemy import select
        with SessionLocal() as db:
            ips = [ip for (ip,) in db.execute(select(Device.ip)).all()][:200]
        nets = set()
        for ip in ips:
            net = ".".join(ip.split(".")[:3])
            if net in nets:
                continue
            nets.add(net)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((ip, 9))
                out.add(s.getsockname()[0])
                s.close()
            except OSError:
                pass
    except Exception:
        pass
    _cache.update(at=time.time(), addr=out)
    return set(out)


def accounts() -> Set[str]:
    out = {str(a).strip().lower() for a in (settings().get("accounts") or []) if str(a).strip()}
    try:
        from services import logons
        out |= logons._agent_users()
    except Exception:
        pass
    return out


def covers(ports: Iterable[int], hour: int) -> bool:
    """Whether a scan by the agent stays within its declared scope: scan_ports (a list, or null = any) and scan_hours ([from, to), or null)."""
    s = settings()
    allowed = s.get("scan_ports")
    if isinstance(allowed, list) and allowed and not set(int(p) for p in ports if isinstance(p, int)) <= {int(p) for p in allowed if isinstance(p, int)}:
        return False
    hrs = s.get("scan_hours")
    if isinstance(hrs, list) and len(hrs) == 2:
        a, b = int(hrs[0]), int(hrs[1])
        inside = a <= hour < b if a < b else (hour >= a or hour < b)
        if not inside:
            return False
    return True


def note_login(ip: str, now: Optional[float] = None) -> None:
    q = _logins.setdefault(ip, deque(maxlen=5000))
    q.append(now or time.time())


def logins(now: Optional[float] = None) -> dict:
    """{"routers": n, "per_hour_avg": x, "max": {"ip", "n"}} - the agent's own API logins in the last hour."""
    now = now or time.time()
    per = {}
    for ip, q in _logins.items():
        n = sum(1 for t in q if now - t <= 3600)
        if n:
            per[ip] = n
    if not per:
        return {"routers": 0, "per_hour_avg": 0, "max": None}
    top = max(per.items(), key=lambda kv: kv[1])
    return {"routers": len(per), "per_hour_avg": round(sum(per.values()) / len(per), 1), "max": {"ip": top[0], "n": top[1]}}


def full_rights(group: Optional[str], policy: Optional[str]) -> bool:
    """A RouterOS user group with full rights: "full", or a policy with write and policy (it can change users and the configuration)."""
    g = (group or "").strip().lower()
    pol = {p.strip().lower() for p in str(policy or "").split(",") if p.strip() and not p.strip().startswith("!")}
    return g == "full" or {"write", "policy"} <= pol


RECOMMENDATION = ('a read-only account for the agent: /user group add name=mikromanager policy=read,api,rest-api,!write,!policy,!sensitive; '
                  '/user add name=mikromanager group=mikromanager address=<agent IP>/32 password=<...>')
