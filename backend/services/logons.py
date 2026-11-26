"""
Who logged on to an asset, and when - from the asset's own sources, never guessed (3.70, round 2 stage E of docs/plan-runda-2.md).

Sources (each row says which):
  event_log      Windows Security log over WinRM (services/host_logs.py): 4624 (types 2 / 7 / 10 / 11), 4625, 4647, 4778 / 4779;
                 type 3 (network: shares, RPC) only counted per day (AssetLogonDaily) - thousands a day
  auth_log       Linux sshd "Accepted / Failed ..." (journald or auth.log / secure)
  routeros_log   RouterOS "user X logged in from Y via winbox / ssh / api / web" (syslog or the API read of the log)
  idrac          the BMC's Redfish sessions
  ad             a domain controller's lastLogonTimestamp (replicated about every 14 days: an "accuracy_days" of 14 goes with it)
Active sessions: quser on Windows, who on Linux, /user/active on RouterOS, the Redfish sessions - kept in data/logon_sessions.json.

Never stored: machine accounts (DC1$), SYSTEM, LOCAL / NETWORK SERVICE, ANONYMOUS LOGON, DWM-* / UMFD-*, the agent's own logons (the user
names of its credentials, from inside the network or with no address). 3.94.6: the same name from an internet address is stored -
the agent's credentials are often "admin", and "login failure for user admin from <internet address> via winbox" on an edge router
was thrown away as the agent's own. Privileged: Administrator / admin / root, a Windows logon with an elevated token, an AD account with adminCount=1,
RouterOS group full.

Personal data (GDPR): only the fields above; details are kept `retention_days` (90 by default, per client in data/logons.json), the daily
counts a year; read only by an admin role, every read written to the audit log (api/logons.py); user names are cut to 64 printable
characters and never interpreted.

Rules (each can be switched off per client in data/logons.json "rules"):
  logon.privileged_new_source  a privileged account from an address / workstation it has not used on this asset in 90 days
  logon.after_hours            a logon to a critical asset outside the working hours
  logon.first_on_server        the first logon of an account on a server or router (once the asset has a week of history)
  logon.builtin_admin          a logon with the built-in Administrator / admin account
  logon.unknown_account        failed logons for accounts that do not exist (admin, test ... - seen: mcprojekt SERWER)
"""
import json
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

from sqlalchemy import select, delete, func

from models.database import SessionLocal, AssetLogon, AssetLogonDaily, Asset

_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_SETTINGS_PATH = os.path.join(_DIR, "logons.json")
_SESSIONS_PATH = os.path.join(_DIR, "logon_sessions.json")
_AD_PATH = os.path.join(_DIR, "logons_ad.json")
DEFAULTS = {"retention_days": 90, "daily_days": 365, "work_hours": [7, 18], "workdays": [0, 1, 2, 3, 4], "send_to_central": True,
            "rules": {"privileged_new_source": True, "after_hours": True, "first_on_server": True, "builtin_admin": True, "unknown_account": True}}
INTERACTIVE = {"interactive", "rdp", "cached", "unlock", "ssh", "winbox", "web", "api", "console", "telnet", "ftp", "redfish", "remote"}
SESSION_MAX_AGE_SEC = 2 * 3600
AD_ACCURACY_DAYS = 14
_TECH = re.compile(r"^(system|local service|network service|anonymous logon|dwm-\d+|umfd-\d+|font driver host|window manager|"
                   r"iusr|defaultaccount|wdagutilityaccount|-)$", re.I)
_BUILTIN = {"administrator", "admin", "administrateur", "administrador", "администратор"}
_PRIV_NAMES = _BUILTIN | {"root"}
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_agent_users_cache = {"at": 0.0, "names": set()}


# ── settings ─────────────────────────────────────────────────────────────────

def settings() -> dict:
    s = json.loads(json.dumps(DEFAULTS))
    try:
        with open(_SETTINGS_PATH, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            for k in ("retention_days", "daily_days"):
                if isinstance(d.get(k), int) and 1 <= d[k] <= 3650:
                    s[k] = d[k]
            if isinstance(d.get("work_hours"), list) and len(d["work_hours"]) == 2 and all(isinstance(x, int) and 0 <= x <= 24 for x in d["work_hours"]):
                s["work_hours"] = d["work_hours"]
            if isinstance(d.get("workdays"), list) and all(isinstance(x, int) and 0 <= x <= 6 for x in d["workdays"]):
                s["workdays"] = d["workdays"]
            if isinstance(d.get("send_to_central"), bool):
                s["send_to_central"] = d["send_to_central"]
            for k, v in (d.get("rules") or {}).items():
                if k in s["rules"] and isinstance(v, bool):
                    s["rules"][k] = v
    except (OSError, ValueError):
        pass
    return s


def update_settings(body: dict) -> dict:
    cur = settings()
    for k in ("retention_days", "daily_days", "work_hours", "workdays", "send_to_central"):
        if k in body:
            cur[k] = body[k]
    if isinstance(body.get("rules"), dict):
        cur["rules"].update({k: bool(v) for k, v in body["rules"].items() if k in cur["rules"]})
    os.makedirs(_DIR, exist_ok=True)
    tmp = _SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cur, f)
    os.replace(tmp, _SETTINGS_PATH)
    return settings()


# ── accounts ─────────────────────────────────────────────────────────────────

def clean(v, n: int = 64) -> Optional[str]:
    """A value from a device, as text only: control characters out, cut."""
    if v is None:
        return None
    s = _CTRL.sub("", str(v)).strip()
    return s[:n] or None


def _agent_users() -> set:
    """The user names of the agent's own credentials: its logons are not anyone's."""
    if time.time() - _agent_users_cache["at"] > 600:
        names = set()
        try:
            from models.database import Credential
            with SessionLocal() as db:
                for (u,) in db.execute(select(Credential.username)).all():
                    if u:
                        names.add(u.split("\\")[-1].split("@")[0].strip().lower())
        except Exception:
            pass
        _agent_users_cache.update(at=time.time(), names=names)
    return _agent_users_cache["names"]


def _base(user: Optional[str]) -> str:
    return (user or "").strip().split("\\")[-1].split("@")[0].strip()


def is_system(user: Optional[str]) -> bool:
    """A machine or built-in system account (DC1$, SYSTEM, DWM-1 ...) or no name: never a person's logon."""
    base = _base(user)
    return not base or base.endswith("$") or bool(_TECH.match(base))


def is_technical(user: Optional[str]) -> bool:
    return is_system(user) or _base(user).lower() in _agent_users()


def is_agent_logon(user: Optional[str], source_ip: Optional[str]) -> bool:
    """The agent's own logon: one of its credentials' user names, unless it comes from a public (internet) address that is not one of the
    agent's - the agent reaches the devices from inside, so that is someone else using (or guessing) the account."""
    if _base(user).lower() not in _agent_users():
        return False
    src = (source_ip or "").strip()
    try:
        import ipaddress
        if not ipaddress.ip_address(src).is_global:
            return True
    except ValueError:
        return True                                        # no address (or a name): as before, the agent's
    try:
        from services import agent_self
        return src in agent_self.addresses()
    except Exception:
        return False


def _ad_privileged() -> set:
    return {u.lower() for u in (_load_json(_AD_PATH).get("privileged") or [])}


def is_privileged(user: Optional[str], hint: bool = False) -> bool:
    base = (user or "").split("\\")[-1].split("@")[0].strip().lower()
    return bool(hint) or base in _PRIV_NAMES or base in _ad_privileged()


def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_json(path: str, d: dict) -> None:
    os.makedirs(_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, default=str)
    os.replace(tmp, path)


# ── recording ────────────────────────────────────────────────────────────────

_purged = [0.0]


def maybe_purge(every_sec: float = 6 * 3600) -> None:
    if time.time() - _purged[0] > every_sec:
        _purged[0] = time.time()
        try:
            purge()
        except Exception as e:
            print(f"[logons] purge error: {type(e).__name__}: {e}")


def record(rows: Iterable[dict], now: Optional[datetime] = None) -> dict:
    """Stores the logons (the technical ones never, the network ones as daily counts) and runs the rules on the new ones.
    A row: {host_ip, host_name, user, domain, logon_type, source_ip, source_host, at, ended_at, result, source, privileged, no_such_user}."""
    now = now or datetime.utcnow()
    stored, counted, skipped, new = 0, 0, 0, []
    rows = list(rows)
    with SessionLocal() as db:
        asset_by_ip = {a.ip: a.id for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()}
        for r in rows:
            user = clean(r.get("user"))
            if is_system(user) or is_agent_logon(user, r.get("source_ip")):
                skipped += 1
                continue
            at = r.get("at") or now
            host_ip = clean(r.get("host_ip"), 45)
            result = "failure" if r.get("result") == "failure" else "success"
            ltype = clean(r.get("logon_type"), 24)
            if ltype == "network":
                day = at.strftime("%Y-%m-%d")
                row = db.execute(select(AssetLogonDaily).where(AssetLogonDaily.host_ip == (host_ip or ""), AssetLogonDaily.day == day)).scalars().first()
                if row is None:
                    row = AssetLogonDaily(host_ip=host_ip or "", day=day, network_success=0, network_failure=0)
                    db.add(row)
                if result == "success":
                    row.network_success += 1
                else:
                    row.network_failure += 1
                counted += 1
                db.flush()
                continue
            source = clean(r.get("source"), 24) or "?"
            dedup = f"{source}|{host_ip}|{user.lower()}|{at.strftime('%Y-%m-%dT%H:%M:%S')}|{result}|{ltype}"[:240]
            if db.execute(select(AssetLogon.id).where(AssetLogon.dedup == dedup)).first():
                continue
            row = AssetLogon(asset_id=r.get("asset_id") or asset_by_ip.get(host_ip), host_ip=host_ip, host_name=clean(r.get("host_name"), 128),
                             user=user, domain=clean(r.get("domain")), logon_type=ltype, source_ip=clean(r.get("source_ip"), 45),
                             source_host=clean(r.get("source_host"), 128), at=at, ended_at=r.get("ended_at"), result=result, source=source,
                             is_privileged=is_privileged(user, r.get("privileged")), dedup=dedup)
            db.add(row)
            db.flush()
            new.append({**r, "user": user, "result": result, "logon_type": ltype, "host_ip": host_ip, "asset_id": row.asset_id,
                        "privileged": row.is_privileged, "id": row.id, "at": at})
            stored += 1
        db.commit()
    alerts = _rules(new, now) if new else []
    maybe_purge()
    return {"stored": stored, "counted": counted, "skipped": skipped, "alerts": alerts}


def count_network(host_ip: str, at: datetime, success: int = 0, failure: int = 0) -> None:
    """Adds network (type 3) logons to the day's count of a host."""
    day = at.strftime("%Y-%m-%d")
    with SessionLocal() as db:
        row = db.execute(select(AssetLogonDaily).where(AssetLogonDaily.host_ip == host_ip, AssetLogonDaily.day == day)).scalars().first()
        if row is None:
            row = AssetLogonDaily(host_ip=host_ip, day=day, network_success=0, network_failure=0)
            db.add(row)
        row.network_success += max(0, int(success))
        row.network_failure += max(0, int(failure))
        db.commit()


def set_sessions(host_ip: str, sessions: List[dict], source: str, host_name: Optional[str] = None) -> None:
    """Who is logged on right now (quser / who / /user/active / Redfish sessions)."""
    d = _load_json(_SESSIONS_PATH)
    d[str(host_ip)] = {"at": time.time(), "source": source, "host": clean(host_name, 128),
                       "sessions": [{k: clean(v, 64) for k, v in s.items() if k in ("user", "since", "state", "from", "type")}
                                    for s in sessions if not is_technical(s.get("user"))][:50]}
    _save_json(_SESSIONS_PATH, d)


def active_sessions(host_ip: Optional[str]) -> Optional[List[dict]]:
    """The sessions seen in the last two hours, or None when no source read them."""
    if not host_ip:
        return None
    e = _load_json(_SESSIONS_PATH).get(host_ip)
    if not e or time.time() - float(e.get("at") or 0) > SESSION_MAX_AGE_SEC:
        return None
    return e.get("sessions") or []


def set_ad(users: List[dict], computers: List[dict], dc: Optional[str]) -> None:
    """A domain controller's view (once a day): the privileged accounts (adminCount=1) and each computer account's last logon."""
    d = {"at": time.time(), "dc": clean(dc, 128),
         "privileged": sorted({clean(u.get("user")) for u in users if u.get("admin") and clean(u.get("user"))})[:2000],
         "computers": {clean(c.get("name"), 64).upper(): c.get("last") for c in computers if clean(c.get("name"), 64) and c.get("last")}}
    _save_json(_AD_PATH, d)


def ad_computer_logon(name: Optional[str]) -> Optional[dict]:
    if not name:
        return None
    d = _load_json(_AD_PATH)
    t = (d.get("computers") or {}).get(name.split(".")[0].upper())
    return {"at": t, "accuracy_days": AD_ACCURACY_DAYS, "source": "ad", "dc": d.get("dc")} if t else None


def purge(now: Optional[datetime] = None) -> dict:
    now = now or datetime.utcnow()
    s = settings()
    with SessionLocal() as db:
        n = db.execute(delete(AssetLogon).where(AssetLogon.at < now - timedelta(days=s["retention_days"]))).rowcount
        m = db.execute(delete(AssetLogonDaily).where(AssetLogonDaily.day < (now - timedelta(days=s["daily_days"])).strftime("%Y-%m-%d"))).rowcount
        db.commit()
    return {"logons": n or 0, "daily": m or 0}


# ── what an asset shows ──────────────────────────────────────────────────────

def _brief(r: AssetLogon) -> dict:
    return {"user": r.user, "domain": r.domain, "type": r.logon_type, "from": r.source_ip or r.source_host, "at": r.at.isoformat() + "Z",
            "ended_at": r.ended_at.isoformat() + "Z" if r.ended_at else None, "result": r.result, "source": r.source, "privileged": bool(r.is_privileged)}


def summary(*, host_ip: Optional[str], asset_id: Optional[int] = None, asset_type: Optional[str] = None, refs: Optional[dict] = None,
            name: Optional[str] = None, now: Optional[datetime] = None, n: int = 10) -> dict:
    """{last_logon, last_logons, active_sessions, distinct_users_30d, last_failed_logon, network_logons_7d, domain_logon, reason}.
    No data is information too: last_logon None with reason no_source (nothing reads logons of this asset), source_silent (a source
    exists, nothing came in 30 days) or not_supported (a printer, a camera, a phone ...)."""
    now = now or datetime.utcnow()
    refs = refs or {}
    with SessionLocal() as db:
        cond = [AssetLogon.asset_id == asset_id] if asset_id else []
        if host_ip:
            cond.append(AssetLogon.host_ip == host_ip)
        rows = []
        if cond:
            from sqlalchemy import or_
            rows = db.execute(select(AssetLogon).where(or_(*cond)).order_by(AssetLogon.at.desc()).limit(500)).scalars().all()
        daily = db.execute(select(func.sum(AssetLogonDaily.network_success), func.sum(AssetLogonDaily.network_failure))
                           .where(AssetLogonDaily.host_ip == (host_ip or ""), AssetLogonDaily.day >= (now - timedelta(days=7)).strftime("%Y-%m-%d"))).first()
    ok = [r for r in rows if r.result == "success"]
    last = next((r for r in ok if (r.logon_type in INTERACTIVE) or r.is_privileged), None)
    failed = next((r for r in rows if r.result == "failure"), None)
    month = {r.user.lower() for r in ok if r.at >= now - timedelta(days=30)}
    out = {"last_logon": _brief(last) if last else None, "last_logons": [_brief(r) for r in rows[:n]],
           "active_sessions": active_sessions(host_ip), "distinct_users_30d": len(month),
           "last_failed_logon": _brief(failed) if failed else None,
           "network_logons_7d": {"success": int(daily[0] or 0), "failure": int(daily[1] or 0)} if daily and (daily[0] or daily[1]) else None,
           "domain_logon": ad_computer_logon(name), "reason": None}
    if not last:
        sourced = any(refs.get(k) for k in ("windows_host_id", "linux_host_id", "device_id", "dell_server_id"))
        if asset_type in ("printer", "camera", "mobile", "monitor") and not sourced:
            out["reason"] = "not_supported"
        elif not sourced:
            out["reason"] = "no_source"
        else:
            out["reason"] = "source_silent"
    return out


# ── rules ────────────────────────────────────────────────────────────────────

def _local(dt: datetime) -> datetime:
    return dt + (datetime.now() - datetime.utcnow())


def _rules(new: List[dict], now: datetime) -> List[str]:
    from services import soc
    s = settings()
    on = s["rules"]
    raised: List[str] = []
    with SessionLocal() as db:
        assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_({r["asset_id"] for r in new if r.get("asset_id")} or {0}))).scalars().all()}
        for r in new:
            if r["result"] != "success":
                continue
            host, user, src = r.get("host_ip"), r["user"], r.get("source_ip") or r.get("source_host")
            name = r.get("host_name") or host
            prev = db.execute(select(AssetLogon).where(AssetLogon.host_ip == host, AssetLogon.id != r["id"], AssetLogon.result == "success",
                                                       AssetLogon.at >= now - timedelta(days=90))).scalars().all()
            mine = [p for p in prev if p.user.lower() == user.lower()]
            a = assets.get(r.get("asset_id"))

            def alert(rule, title, sev, msg, key):
                soc.raise_alert(rule=f"logon.{rule}", device=name, ip=host, title=title, severity=sev, category="auth", fp_detail=key[:120],
                                detail={"users": [user], "sources": [src] if src else [], "message": msg, "description": title,
                                        "by": r.get("source")}, mitre="T1078", source="rules", asset_id=r.get("asset_id"), now=r.get("at"))
                raised.append(rule)

            # a RouterOS log line has its own rules (services/router_logs.py: login from a new source / from outside) - not raised twice
            routeros = r.get("source") == "routeros_log"
            if on["privileged_new_source"] and not routeros and r.get("privileged") and src and mine and not any((p.source_ip or p.source_host) == src for p in mine):
                alert("privileged_new_source", "Privileged logon from a new address", "high",
                      f"{user} ({r.get('logon_type') or 'logon'}) from {src} - not seen for this account on {name} in 90 days", f"{user}|{src}")
            if on["first_on_server"] and not mine and a is not None and _server_or_router(a) and prev and min(p.at for p in prev) <= now - timedelta(days=7):
                alert("first_on_server", "First logon of an account on a server", "medium",
                      f"{user} logged on to {name} for the first time ({r.get('logon_type') or 'logon'}{' from ' + src if src else ''})", user)
            if on["builtin_admin"] and not routeros and user.split("\\")[-1].lower() in _BUILTIN:
                alert("builtin_admin", "Logon with the built-in administrator account", "medium",
                      f"{user} on {name}{' from ' + src if src else ''} - a named personal account leaves a trail", user)
            if on["after_hours"] and a is not None and _critical(a) and (r.get("logon_type") in INTERACTIVE):
                t = _local(r["at"])
                h1, h2 = s["work_hours"]
                if t.weekday() not in s["workdays"] or not (h1 <= t.hour < h2):
                    alert("after_hours", "Logon to a critical asset outside working hours", "medium",
                          f"{user} on {name} at {t.strftime('%Y-%m-%d %H:%M')} (local){' from ' + src if src else ''}", user)
    # failed logons for accounts that do not exist: one alert per host, counted
    unknown: Dict[str, List[dict]] = {}
    for r in new:
        if r["result"] == "failure" and r.get("no_such_user"):
            unknown.setdefault(r.get("host_ip") or "?", []).append(r)
    if on["unknown_account"]:
        for host, rs in unknown.items():
            users = sorted({x["user"] for x in rs})[:10]
            srcs = sorted({x.get("source_ip") or x.get("source_host") for x in rs if x.get("source_ip") or x.get("source_host")})[:10]
            soc.raise_alert(rule="logon.unknown_account", device=rs[0].get("host_name") or host, ip=host if host != "?" else None,
                            title="Failed logons for accounts that do not exist", severity="medium", category="auth", fp_detail="unknown",
                            detail={"users": users, "sources": srcs, "count": len(rs), "message": f"{len(rs)} failed logons for {', '.join(users)}"},
                            count=len(rs), mitre="T1110.003", source="rules", asset_id=rs[0].get("asset_id"))
            raised.append("unknown_account")
    return raised


def _server_or_router(a: Asset) -> bool:
    return a.role == "server" or a.asset_type in ("server", "virtual", "network") or "server" in (a.os_name or "").lower()


def _critical(a: Asset) -> bool:
    from services import asset_type as at, assets
    lv = at.normalize_level(a.criticality)
    if not lv:
        sug = assets.suggested_level(a.id)
        lv = sug[0] if sug else None
    return lv == "critical"


# ── for Central and MCP ──────────────────────────────────────────────────────

def public_recent(limit: int = 300, days: int = 7) -> Optional[List[dict]]:
    """The recent logons for Central (MCP client_logons), or None when this client keeps them on the agent (send_to_central false)."""
    if not settings()["send_to_central"]:
        return None
    since = datetime.utcnow() - timedelta(days=days)
    with SessionLocal() as db:
        rows = db.execute(select(AssetLogon).where(AssetLogon.at >= since).order_by(AssetLogon.at.desc()).limit(limit)).scalars().all()
    return [{"aid": r.asset_id, "h": r.host_name or r.host_ip, "ip": r.host_ip, "u": r.user, "d": r.domain, "t": r.logon_type,
             "f": r.source_ip or r.source_host, "at": r.at.isoformat() + "Z", "r": r.result, "s": r.source, "p": 1 if r.is_privileged else 0}
            for r in rows]


def last_by_host(rows: List[dict]) -> Dict[int, dict]:
    """For the inventory rows ({id, ip, type, refs, name}): asset id -> {"u", "at", "t", "f", "p"} of the last interactive / RDP /
    administrative logon, or {"why": no_source | source_silent | not_supported}; "ses" = active sessions now. One query for all."""
    by_ip: Dict[str, dict] = {}
    by_aid: Dict[int, dict] = {}
    with SessionLocal() as db:
        for r in db.execute(select(AssetLogon).where(AssetLogon.result == "success").order_by(AssetLogon.at.desc()).limit(20000)).scalars().all():
            if not (r.logon_type in INTERACTIVE or r.is_privileged):
                continue
            b = {"u": r.user, "at": r.at.isoformat() + "Z", "t": r.logon_type, "f": r.source_ip or r.source_host, "p": 1 if r.is_privileged else 0,
                 "s": r.source}
            if r.host_ip and r.host_ip not in by_ip:
                by_ip[r.host_ip] = b
            if r.asset_id and r.asset_id not in by_aid:
                by_aid[r.asset_id] = b
    sessions = _load_json(_SESSIONS_PATH)
    out: Dict[int, dict] = {}
    for x in rows:
        b = by_aid.get(x["id"]) or (by_ip.get(x["ip"]) if x.get("ip") else None)
        if b:
            e = dict(b)
        else:
            refs = x.get("refs") or {}
            sourced = any(refs.get(k) for k in ("windows_host_id", "linux_host_id", "device_id", "dell_server_id"))
            e = {"why": "not_supported" if x.get("type") in ("printer", "camera", "mobile", "monitor") and not sourced
                 else ("source_silent" if sourced else "no_source")}
        s = sessions.get(x.get("ip") or "")
        if s and time.time() - float(s.get("at") or 0) <= SESSION_MAX_AGE_SEC:
            e["ses"] = len(s.get("sessions") or [])
        out[x["id"]] = e
    return out
