"""
History of the configuration of the MikroTik devices, with a diff of two versions and an alert when it changes.

The agent already keeps a backup of its own state and can make a binary backup on a router before an upgrade, but nothing answers the question an
incident starts with: "what was changed on this router, when, and what was it before?". Here a plain-text `/export` of every managed MikroTik is taken on
a schedule (every few hours; SSH, the same call as the DRP document uses), and a new version is stored only when the configuration really changed:

  * the header comment of the export (date, software id) is dropped before the comparison, so a re-export is not a change; the values of passwords,
    secrets, keys and pre-shared keys are replaced by *** before anything is compared or stored (RouterOS 7 hides them itself; older versions do not);
  * a change is described by the sections of the export it touches (/ip firewall filter, /user, /ip service ...) with the number of lines added and
    removed, and the diff of any two versions is shown line by line under the section of each line;
  * a change after the first version is an alert of the router in the SOC queue (medium; high when it touches the firewall, users, services,
    scheduler/scripts, VPN or the SSH/Winbox access), merged while changes keep coming; the first export is only the baseline.

Versions are kept per device (the newest MAX_VERSIONS), plain text; what is stored is what the export says, nothing is ever written to a router.
"""
import asyncio
import difflib
import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select, delete, func

from models.database import SessionLocal, Device, Credential, ConfigSnapshot, ConfigCheck
from services.crypto import decrypt as decrypt_secret

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "config_history.json")
DEFAULTS = {"enabled": True, "interval_hours": 6}
MAX_VERSIONS = 40
MAX_BYTES = 2_000_000
SENSITIVE_SECTIONS = ("/ip firewall", "/user", "/ip service", "/system scheduler", "/system script", "/interface wireguard", "/interface ovpn", "/interface l2tp",
                      "/interface sstp", "/ip ipsec", "/ppp secret", "/ip ssh", "/certificate", "/snmp", "/radius", "/ip proxy", "/ip socks", "/system ntp", "/tool",
                      # Cisco: the access lists, accounts, authentication, management access, VPN and routing
                      "ip access-list", "access-list", "username", "aaa", "line vty", "line console", "snmp-server", "crypto", "enable", "ip ssh", "ip http", "interface Tunnel",
                      "router ", "tacacs", "radius-server", "management access", "ip route", "ntp ")
SUPPORTED = ("mikrotik", "cisco-sb")             # the vendors whose configuration can be read

_settings: Dict = dict(DEFAULTS)
_task: Optional[asyncio.Task] = None
_running: Dict[int, bool] = {}


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
    if body.get("enabled") is not None:
        new["enabled"] = bool(body["enabled"])
    if body.get("interval_hours") is not None:
        h = float(body["interval_hours"])
        if not (0.25 <= h <= 168):
            raise ValueError("the interval is between 15 minutes and a week")
        new["interval_hours"] = h
    _settings.clear()
    _settings.update(new)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f)
    os.replace(tmp, _PATH)
    return settings()


# ── Normalising ──────────────────────────────────────────────────────────────

_SECRET = re.compile(r'((?:^|[\s;])(?:password|secret|private-key|passphrase|pre-shared-key|preshared-key|authentication-password|encryption-password|'
                     r'wpa-pre-shared-key|wpa2-pre-shared-key|psk|auth-key|key-string|community-string)=)("(?:[^"\\]|\\.)*"|\S+)', re.I)
_HEADER = re.compile(r"^#\s*(?:\d{4}-\d\d-\d\d|[a-z]{3}/\d\d/\d{4}|software id|model|serial number|by RouterOS)", re.I)


_CISCO_VOLATILE = re.compile(r"^(?:Building configuration|Current configuration\s*:|Using \d+ out of|!\s*(?:Last configuration change|NVRAM config last updated|Time:)|ntp clock-period)", re.I)
_CISCO_SECRET_A = re.compile(r"\b(secret|password|passwd)(\s+(?:\d|encrypted))?\s+(\S+)", re.I)
_CISCO_SECRET_B = re.compile(r"\b(key|key-string|community|pre-shared-key|psk|md5)(\s+\d)?\s+(\S+)", re.I)


def _mask_cisco(line: str) -> str:
    line = _CISCO_SECRET_A.sub(lambda m: f"{m.group(1)}{m.group(2) or ''} ***", line)
    return _CISCO_SECRET_B.sub(lambda m: f"{m.group(1)}{m.group(2) or ''} ***", line)


def normalize(text: str, vendor: str = "mikrotik") -> str:
    """The export without what changes by itself (the header comments with the date) and without secrets; line endings unified, `\\` line joins kept
    as the device wrote them. For Cisco: the banner lines and the "last changed" comments are dropped and the secrets, keys and communities masked."""
    out: List[str] = []
    cisco = vendor == "cisco-sb"
    for line in (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if cisco:
            if _CISCO_VOLATILE.match(line):
                continue
            out.append(_mask_cisco(line.rstrip()))
            continue
        if _HEADER.match(line):
            continue
        out.append(_SECRET.sub(lambda m: m.group(1) + "***", line.rstrip()))
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


def _join_continuations(lines: List[str]) -> List[str]:
    """RouterOS wraps long commands with a trailing backslash; the diff is easier to read - and a re-wrapping is not a change - on joined lines."""
    out, cur = [], ""
    for ln in lines:
        if ln.endswith("\\"):
            cur += ln[:-1].strip() + " "
            continue
        out.append((cur + ln.strip()) if cur else ln)
        cur = ""
    if cur:
        out.append(cur.strip())
    return out


def _is_header(line: str) -> bool:
    return line.startswith("/") and "=" not in line


def _cisco_items(text: str) -> List[tuple]:
    """[(section, line)] of a Cisco configuration: the indented lines belong to the block above them ("interface gi1"), a top-level line is its own section;
    "!" and "exit" at the top level end a block and are not commands."""
    head, out = "", []
    for raw in text.split(chr(10)):
        ln = raw.rstrip()
        s = ln.strip()
        if not s:
            continue
        if raw[:1].isspace():
            out.append((head[:60], s))
            continue
        if s.startswith("!") or s in ("exit", "end"):
            head = ""
            continue
        head = s
        out.append((s[:60], s))
    return out


def _joined_with_sections(text: str, vendor: str = "mikrotik") -> List[tuple]:
    """[(section, command)] of an export, wrapped lines joined, comments left out. A section header is a line like "/ip firewall filter"."""
    if vendor == "cisco-sb":
        return _cisco_items(text)
    sec, out = "", []
    for line in _join_continuations(text.split(chr(10))):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _is_header(line):
            sec = line
            continue
        out.append((sec, line))
    return out


def diff(old: str, new: str, vendor: str = "mikrotik") -> dict:
    """What changed between two normalised exports: {added, removed, sections: {section: {added, removed}}, hunks: [{section, lines: [(+|-|' ', text)]}]}."""
    a, b = _joined_with_sections(old, vendor), _joined_with_sections(new, vendor)
    sm = difflib.SequenceMatcher(None, [f"{s}\u0000{l}" for s, l in a], [f"{s}\u0000{l}" for s, l in b], autojunk=False)
    added = removed = 0
    secs: Dict[str, Dict[str, int]] = {}
    hunks: List[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        lines = []
        section = (b[j1][0] if j1 < len(b) else a[i1][0] if i1 < len(a) else "")
        for s, l in a[i1:i2]:
            lines.append(("-", l))
            removed += 1
            secs.setdefault(s, {"added": 0, "removed": 0})["removed"] += 1
        for s, l in b[j1:j2]:
            lines.append(("+", l))
            added += 1
            secs.setdefault(s, {"added": 0, "removed": 0})["added"] += 1
        hunks.append({"section": section, "lines": lines})
    return {"added": added, "removed": removed, "sections": secs, "hunks": hunks}


def _sensitive(sections) -> bool:
    return any(s.startswith(SENSITIVE_SECTIONS) for s in sections)


# ── Taking a version ─────────────────────────────────────────────────────────

async def _export(device: Device, cred: Credential) -> str:
    from services.device_client import build_client
    client = build_client(device, cred)                  # MikroTik: /export; Cisco: show running-config - both over SSH, read-only
    return await client.get_config_export(ssh_port=device.ssh_port or 22, timeout_sec=30)


def record(device_id: int, device_name: str, exported: str, now: Optional[datetime] = None, vendor: str = "mikrotik") -> dict:
    """Stores the export as a new version when it differs from the last one; raises an alert for a change after the first version.
    Returns {"changed": bool, "first": bool, "id": snapshot id, "added", "removed", "sections"}."""
    now = now or datetime.utcnow()
    text = normalize(exported, vendor)[:MAX_BYTES]
    if len(text) < 20:
        raise ValueError("the export is empty")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with SessionLocal() as db:
        last = db.execute(select(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id).order_by(ConfigSnapshot.id.desc()).limit(1)).scalars().first()
        chk = db.get(ConfigCheck, device_id) or ConfigCheck(device_id=device_id)
        db.add(chk)
        chk.last_check_at, chk.last_error = now, None
        if last is not None and last.sha == sha:
            db.commit()
            return {"changed": False, "first": False, "id": last.id}
        d = diff(last.text, text, vendor) if last is not None else None
        sections = sorted(d["sections"]) if d else []
        snap = ConfigSnapshot(device_id=device_id, at=now, sha=sha, text=text, size=len(text), lines=text.count("\n") + 1,
                              added=d["added"] if d else None, removed=d["removed"] if d else None,
                              sections=json.dumps(sections[:40]) if d else None)
        db.add(snap)
        db.flush()
        chk.last_change_at = now if d else chk.last_change_at
        ids = [r for (r,) in db.execute(select(ConfigSnapshot.id).where(ConfigSnapshot.device_id == device_id).order_by(ConfigSnapshot.id.desc())).all()]
        if len(ids) > MAX_VERSIONS:
            db.execute(delete(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id, ConfigSnapshot.id.in_(ids[MAX_VERSIONS:])))
        db.commit()
        sid = snap.id
    if d is not None and (d["added"] or d["removed"]):
        _alert(device_id, device_name, sid, d, sections, now)
    return {"changed": d is not None, "first": d is None, "id": sid, "added": d["added"] if d else None, "removed": d["removed"] if d else None, "sections": sections}


def _alert(device_id: int, name: str, sid: int, d: dict, sections: List[str], now: datetime) -> None:
    try:
        from services import soc
        sev = "high" if _sensitive(sections) else "medium"
        soc.raise_alert(rule="config_changed", device=name, title="Router configuration changed", severity=sev, category="system", fp_detail="",
                        detail={"sections": ", ".join(sections[:8]), "message": f"+{d['added']} / -{d['removed']} lines", "snapshot": sid}, count=1, source="rules", now=now)
    except Exception as e:
        print(f"[config_history] alert failed: {type(e).__name__}: {e}")


async def snapshot_device(device_id: int) -> dict:
    """Takes the export of one device now. Never raises: {"error": ...} when it could not be done."""
    if _running.get(device_id):
        return {"error": "already running"}
    _running[device_id] = True
    try:
        with SessionLocal() as db:
            dev = db.get(Device, device_id)
            cred = db.get(Credential, dev.credential_id) if dev and dev.credential_id else None
            if dev is None:
                return {"error": "device not found"}
            if (dev.vendor or "mikrotik") not in SUPPORTED:
                return {"error": "only MikroTik and Cisco devices are supported"}
            if cred is None:
                return {"error": "no credential assigned to the device"}
            name = dev.name or dev.ip
            vendor = dev.vendor or "mikrotik"
        try:
            text = await _export(dev, cred)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"[:300]
            with SessionLocal() as db:
                chk = db.get(ConfigCheck, device_id) or ConfigCheck(device_id=device_id)
                db.add(chk)
                chk.last_check_at, chk.last_error = datetime.utcnow(), msg
                db.commit()
            return {"error": msg}
        try:
            return record(device_id, name, text, vendor=vendor)
        except ValueError as e:
            return {"error": str(e)}
    finally:
        _running[device_id] = False


async def run_cycle(force: bool = False) -> dict:
    """Takes the export of every managed MikroTik that is due (a few at a time)."""
    with SessionLocal() as db:
        due = []
        interval = timedelta(hours=float(_settings.get("interval_hours") or 6))
        checks = {c.device_id: c for c in db.execute(select(ConfigCheck)).scalars().all()}
        for d in db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all():
            if (d.vendor or "mikrotik") not in SUPPORTED:
                continue
            c = checks.get(d.id)
            if force or c is None or c.last_check_at is None or datetime.utcnow() - c.last_check_at >= interval:
                due.append(d.id)
    sem = asyncio.Semaphore(3)
    out = {"checked": 0, "changed": 0, "errors": 0}

    async def one(did):
        async with sem:
            r = await snapshot_device(did)
            out["checked"] += 1
            out["errors"] += "error" in r
            out["changed"] += bool(r.get("changed"))
    await asyncio.gather(*[one(i) for i in due])
    return out


async def _loop():
    load_settings()
    await asyncio.sleep(90)
    while True:
        try:
            if _settings.get("enabled"):
                await run_cycle()
        except Exception as e:
            print(f"[config_history] cycle error: {type(e).__name__}: {e}")
        await asyncio.sleep(900)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None


# ── Reading ──────────────────────────────────────────────────────────────────

def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.isoformat() + "Z" if d else None


def overview() -> dict:
    with SessionLocal() as db:
        devices = db.execute(select(Device).where(Device.credential_id.is_not(None))).scalars().all()
        checks = {c.device_id: c for c in db.execute(select(ConfigCheck)).scalars().all()}
        counts = dict(db.execute(select(ConfigSnapshot.device_id, func.count()).group_by(ConfigSnapshot.device_id)).all())
        last = {}
        for s in db.execute(select(ConfigSnapshot).order_by(ConfigSnapshot.id)).scalars().all():
            last[s.device_id] = s
        items = []
        for d in devices:
            if (d.vendor or "mikrotik") not in SUPPORTED:
                continue
            c, s = checks.get(d.id), last.get(d.id)
            items.append({"id": d.id, "name": d.name or d.ip, "ip": d.ip, "vendor": d.vendor or "mikrotik", "versions": counts.get(d.id, 0), "last_check": _iso(c.last_check_at) if c else None,
                          "last_error": c.last_error if c else None, "last_change": _iso(c.last_change_at) if c else None, "last_version": _iso(s.at) if s else None,
                          "last_added": s.added if s else None, "last_removed": s.removed if s else None,
                          "last_sections": json.loads(s.sections) if s and s.sections else []})
    items.sort(key=lambda r: (r["last_change"] or "") , reverse=True)
    return {"items": items, "settings": settings()}


def versions(device_id: int) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id).order_by(ConfigSnapshot.id.desc())).scalars().all()
        return [{"id": r.id, "at": _iso(r.at), "size": r.size, "lines": r.lines, "added": r.added, "removed": r.removed, "sections": json.loads(r.sections) if r.sections else []} for r in rows]


def get_text(device_id: int, snap_id: int) -> Optional[str]:
    with SessionLocal() as db:
        r = db.get(ConfigSnapshot, snap_id)
        return r.text if r and r.device_id == device_id else None


def compare(device_id: int, a: int, b: int) -> Optional[dict]:
    """The diff from version a (older) to version b."""
    ta, tb = get_text(device_id, a), get_text(device_id, b)
    if ta is None or tb is None:
        return None
    with SessionLocal() as db:
        dev = db.get(Device, device_id)
        vendor = (dev.vendor if dev else None) or "mikrotik"
    d = diff(ta, tb, vendor)
    d["hunks"] = d["hunks"][:300]
    return {**d, "a": a, "b": b, "sensitive": _sensitive(d["sections"])}


def delete_history(device_id: int) -> int:
    with SessionLocal() as db:
        n = db.execute(delete(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id)).rowcount
        db.execute(delete(ConfigCheck).where(ConfigCheck.device_id == device_id))
        db.commit()
        return n or 0


def public_summary() -> dict:
    """For Central: how many routers changed their configuration in the last 24 hours and which (names, when, the sections - no configuration text)."""
    day = datetime.utcnow() - timedelta(hours=24)
    with SessionLocal() as db:
        n_dev = db.execute(select(func.count(func.distinct(ConfigSnapshot.device_id)))).scalar() or 0
        rows = db.execute(select(ConfigSnapshot, Device.name, Device.ip).join(Device, Device.id == ConfigSnapshot.device_id)
                          .where(ConfigSnapshot.at >= day, ConfigSnapshot.added.is_not(None)).order_by(ConfigSnapshot.id.desc()).limit(20)).all()
    return {"tracked": n_dev, "changed_24h": [{"n": name or ip, "at": _iso(s.at), "added": s.added, "removed": s.removed, "sections": json.loads(s.sections)[:6] if s.sections else []}
                                               for s, name, ip in rows]}
