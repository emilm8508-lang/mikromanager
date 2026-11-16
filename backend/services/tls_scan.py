"""
TLS certificates and protocols of the services the agent already knows (services/vuln_scan.py found them open).

A certificate that runs out is one of the most common, most avoidable outages - and a router, a printer, a NAS or an old server that still answers TLS 1.0 is a finding
no package scan reports. This module only READS: it opens an ordinary TLS connection to a port that is known to be open, takes the certificate the server presents (no
request is sent over it), and tries once per legacy protocol (TLS 1.0, 1.1) whether the handshake is accepted. No exploitation, no guessing of anything.

  * targets: the open services of the vulnerability scan on TLS ports (443, 8443, 993, 995, 636, 465, 5986 ...) or fingerprinted as TLS, plus targets added by hand
    (only addresses the inventory knows);
  * per target: subject, issuer, names, validity, key and signature, the negotiated protocol and cipher, the legacy protocols that are still accepted;
  * findings: expired / expiring (<= 30 days: medium, <= 7 days: high), self-signed (low), RSA key under 2048 bits, SHA-1 / MD5 signature, TLS 1.0 / 1.1 accepted;
  * every finding is an alert of the SOC queue that closes by itself once it is gone; Central gets a compact summary.
"""
import asyncio
import ipaddress
import json
import os
import ssl
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, TlsCheck, VulnHost, VulnService, Asset, Device, SocAlert

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "tls.json")
DEFAULTS = {"enabled": True, "warn_days": 30, "crit_days": 7}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 2376, 4443, 5986, 6443, 8443, 8444, 8883, 9443, 10443}
TLS_SERVICES = ("https", "ssl", "tls", "imaps", "pop3s", "ldaps", "smtps", "ftps")
INTERVAL_SEC = 6 * 3600
TIMEOUT = 6.0
CONCURRENCY = 6
LEGACY = ("TLSv1", "TLSv1.1")
CODES = ("expired", "expiring", "self_signed", "self_signed_default", "weak_key", "weak_signature", "legacy_protocol")
# the ports people use (remote desktop, web applications, mail, directory): an expired certificate there is high; on a device's own
# management page (a camera, a printer, a switch) it is not - seen: 87 repeats per port of Hikvision cameras' factory certificates
USER_PORTS = {443, 465, 587, 636, 993, 995, 3389, 4443, 5986, 8443, 10443}
DEFAULT_CERT_YEARS = 50
# Antivirus / proxies that re-sign TLS on the machine the agent runs on: the certificate read is then THEIRS, not the server's, and says nothing about the server.
INTERCEPTORS = ("web/mail shield", "kaspersky", "eset ssl filter", "avast", "avg ", "bitdefender", "zscaler", "sophos", "fortinet", "untrusted root", "mitmproxy", "fiddler", "charles proxy")
_settings: Dict = dict(DEFAULTS)
_task: Optional[asyncio.Task] = None
_running = False
_last = {"at": None, "error": None}


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
    for k, lo, hi in (("warn_days", 2, 365), ("crit_days", 1, 90)):
        if body.get(k) is not None:
            v = int(body[k])
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            new[k] = v
    if new["crit_days"] >= new["warn_days"]:
        raise ValueError("the high-severity limit must be shorter than the warning limit")
    _settings.clear()
    _settings.update(new)
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_settings, f)
    os.replace(tmp, _PATH)
    return settings()


# ── Reading one endpoint ─────────────────────────────────────────────────────

def _context(version: Optional[ssl.TLSVersion] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    return ctx


async def _handshake(ip: str, port: int, ctx: ssl.SSLContext):
    try:
        from services import mikrotik_client
        mikrotik_client._note_access("tls-scan", ip, f"port {port}")      # a router logs a failed handshake: services/router_logs.py finds it was us
    except Exception:
        pass
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=None), timeout=TIMEOUT)
    try:
        obj = writer.get_extra_info("ssl_object")
        return obj.getpeercert(binary_form=True), obj.version(), obj.cipher()
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass


def parse_cert(der: bytes) -> dict:
    """What matters of a DER certificate, as plain values."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    from cryptography.x509.oid import NameOID
    c = x509.load_der_x509_certificate(der)

    def cn(name) -> Optional[str]:
        a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return a[0].value if a else (name.rfc4514_string() or None)
    names: List[str] = []
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    key = c.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        kind, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        kind, bits = "EC", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        kind, bits = "DSA", key.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        kind, bits = "EdDSA", None
    else:
        kind, bits = type(key).__name__, None
    try:
        sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else None
    except Exception:
        sig = None
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
    return {"subject": cn(c.subject), "issuer": cn(c.issuer), "names": names[:20], "not_before": nb.replace(tzinfo=None), "not_after": na.replace(tzinfo=None),
            "key_kind": kind, "key_bits": bits, "sig_alg": sig, "self_signed": c.subject == c.issuer}


async def probe(ip: str, port: int) -> dict:
    """The facts of one endpoint, or {"error": ...}. Never raises."""
    try:
        der, version, cipher = await _handshake(ip, port, _context())
        out = parse_cert(der)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:200]}
    out["protocol"] = version
    out["cipher"] = cipher[0] if cipher else None
    issuer = (out.get("issuer") or "").lower()
    out["intercepted"] = any(m in issuer for m in INTERCEPTORS)
    legacy = []
    for name, v in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            await _handshake(ip, port, _context(v))
            legacy.append(name)
        except Exception:
            pass
    out["legacy"] = legacy
    return out


# ── Findings ─────────────────────────────────────────────────────────────────

def findings(r: dict, now: Optional[datetime] = None, warn_days: int = 30, crit_days: int = 7) -> List[dict]:
    """[{code, severity, message}] for the facts of one endpoint (as probe() returns them)."""
    now = now or datetime.utcnow()
    out: List[dict] = []
    if r.get("intercepted"):
        return [{"code": "intercepted", "severity": "info", "message": "the certificate is re-signed on the agent's computer (antivirus / proxy), so it is not the server's"}]
    na, nb = r.get("not_after"), r.get("not_before")
    # A factory default certificate of an embedded device: dated before 2000 or valid for more than 50 years (seen: cameras whose
    # certificate "expired" 17121 and 19676 days ago). Not a lapse anyone can renew on a schedule - one low finding, nothing else.
    if (na and na.year < 2000) or (nb and nb.year < 2000) or (na and nb and (na - nb).days > DEFAULT_CERT_YEARS * 365):
        out.append({"code": "self_signed_default", "severity": "low",
                    "message": "a device's factory default certificate (dated before 2000 or valid for over 50 years)"})
        na = None
        r = dict(r, self_signed=False)
    if na:
        days = (na - now).total_seconds() / 86400
        if days < 0:
            out.append({"code": "expired", "severity": "high", "message": f"certificate expired {int(-days) or 1} day(s) ago"})
        elif days <= warn_days:
            out.append({"code": "expiring", "severity": "high" if days <= crit_days else "medium", "message": f"certificate expires in {max(0, int(days))} day(s)"})
    if r.get("self_signed"):
        out.append({"code": "self_signed", "severity": "low", "message": "self-signed certificate"})
    if r.get("key_kind") in ("RSA", "DSA") and r.get("key_bits") and r["key_bits"] < 2048:
        out.append({"code": "weak_key", "severity": "medium", "message": f"{r['key_kind']} key of {r['key_bits']} bits"})
    if (r.get("sig_alg") or "").lower() in ("md5", "sha1"):
        out.append({"code": "weak_signature", "severity": "medium", "message": f"{r['sig_alg'].upper()} signature"})
    legacy = r.get("legacy") or []
    if legacy:
        out.append({"code": "legacy_protocol", "severity": "medium", "message": "accepts " + ", ".join(legacy)})
    return out


# ── Targets and the run ──────────────────────────────────────────────────────

def _known(ip: str) -> bool:
    with SessionLocal() as db:
        return bool(db.execute(select(Asset.id).where(Asset.ip == ip).limit(1)).first() or db.execute(select(VulnHost.id).where(VulnHost.ip == ip).limit(1)).first()
                    or db.execute(select(Device.id).where(Device.ip == ip).limit(1)).first())


def add_target(ip: str, port: int) -> int:
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError("an IP address is required")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port out of range")
    ip = str(a)
    if not _known(ip):
        raise ValueError("only addresses the inventory knows can be checked")
    with SessionLocal() as db:
        row = db.execute(select(TlsCheck).where(TlsCheck.ip == ip, TlsCheck.port == int(port))).scalars().first()
        if row is None:
            row = TlsCheck(ip=ip, port=int(port), manual=True)
            db.add(row)
        else:
            row.manual = True
        db.commit()
        return row.id


def remove_target(check_id: int) -> bool:
    with SessionLocal() as db:
        row = db.get(TlsCheck, check_id)
        if row is None:
            return False
        db.delete(row)
        db.commit()
    return True


def discover() -> int:
    """Adds the TLS services of the vulnerability scan as targets and drops the automatic ones whose service is gone. Returns how many targets exist."""
    with SessionLocal() as db:
        want = set()
        for svc, host in db.execute(select(VulnService, VulnHost).join(VulnHost, VulnHost.id == VulnService.host_id)).all():
            if svc.port in TLS_PORTS or (svc.service_name or "").lower() in TLS_SERVICES:
                want.add((host.ip, svc.port))
        have = {(r.ip, r.port): r for r in db.execute(select(TlsCheck)).scalars().all()}
        for key in want - set(have):
            db.add(TlsCheck(ip=key[0], port=key[1], manual=False))
        for key, row in have.items():
            if key not in want and not row.manual:
                db.delete(row)
        db.commit()
        return db.query(TlsCheck).count()


def _device_name(db, ip: str) -> str:
    a = db.execute(select(Asset).where(Asset.ip == ip).limit(1)).scalars().first()
    return (a.name if a and a.name else ip)


def _store(check_id: int, r: dict, now: datetime) -> None:
    from services import soc
    with SessionLocal() as db:
        row = db.get(TlsCheck, check_id)
        if row is None:
            return
        row.last_check_at = now
        if "error" in r:
            row.error = r["error"]
            db.commit()
            return
        row.error = None
        row.last_ok_at = now
        row.subject, row.issuer, row.names = r["subject"], r["issuer"], json.dumps(r["names"])
        row.not_before, row.not_after = r["not_before"], r["not_after"]
        row.key_desc = f"{r['key_kind']} {r['key_bits']}" if r.get("key_bits") else r["key_kind"]
        row.sig_alg, row.self_signed, row.protocol, row.cipher = r["sig_alg"], bool(r["self_signed"]), r["protocol"], r["cipher"]
        row.legacy = json.dumps(r["legacy"])
        fs = findings(dict(r, intercepted=r.get("intercepted")), now, _settings["warn_days"], _settings["crit_days"])
        row.findings = json.dumps(fs)
        ip, port, name = row.ip, row.port, _device_name(db, row.ip)
        db.commit()
    # the alerts are raised per device after the whole run (alerts()): one per device and kind of finding, with its ports


def _is_server(db, ip: str) -> bool:
    a = db.execute(select(Asset).where(Asset.ip == ip).limit(1)).scalars().first()
    return bool(a and (a.role == "server" or a.asset_type in ("server", "virtual") or "server" in (a.os_name or "").lower()))


def severity_for(code: str, severity: str, port: int, server: bool) -> str:
    """The finding's severity for alerting: an expired / expiring certificate is high only where people connect (a server's user-facing
    port); on a device's management page it is low."""
    if code in ("expired", "expiring") and not (server and port in USER_PORTS):
        return "low"
    return severity


def alerts(now: Optional[datetime] = None) -> dict:
    """One SOC alert per device and kind of finding, listing its ports - raised once and refreshed afterwards (no count growing with every
    scan), closed when no port of the device has it any more. Alerts of the old per-port form are closed as regrouped."""
    from services import soc
    now = now or datetime.utcnow()
    with SessionLocal() as db:
        rows = db.execute(select(TlsCheck)).scalars().all()
        groups: Dict[tuple, dict] = {}
        names: Dict[str, str] = {}
        for row in rows:
            if row.error:
                continue
            server = _is_server(db, row.ip)
            names.setdefault(row.ip, _device_name(db, row.ip))
            for f in json.loads(row.findings or "[]"):
                if f.get("code") not in CODES:
                    continue
                g = groups.setdefault((row.ip, f["code"]), {"ports": [], "sev": "info", "messages": []})
                sev = severity_for(f["code"], f["severity"], row.port, server)
                g["ports"].append(row.port)
                g["messages"].append(f"{row.port}: {f['message']}")
                if soc.RANK.get(sev, 0) > soc.RANK.get(g["sev"], 0):
                    g["sev"] = sev
        open_tls = db.execute(select(SocAlert).where(SocAlert.rule.like("tls_%"), SocAlert.status.in_(soc.OPEN))).scalars().all()
        stale = [(a.rule, a.device_name, a.fingerprint) for a in open_tls]
    active = set()
    merged = 0
    for (ip, code), g in groups.items():
        name = names.get(ip, ip)
        fp = f"tls_{code}|{name.strip().lower()}|{ip}"[:240]
        active.add(fp)
        # 3.69: one alert per device even when its name changes between scans (seen: aluplasti ALU-SW2 with a second alert under its
        # address 192.168.1.127): an open alert of this device under another name is carried over to this one, any further copy closed
        mine = [a for a in open_tls if a.rule == f"tls_{code}" and a.fingerprint != fp and (a.ip == ip or a.fingerprint.endswith(f"|{ip}"))
                and a.fingerprint.rsplit("|", 1)[-1].count(":") == 0]
        if mine:
            with SessionLocal() as db:
                have = db.execute(select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.status.in_(soc.OPEN))).scalars().first()
                for a in sorted((db.get(SocAlert, m.id) for m in mine), key=lambda x: x.first_seen):
                    if a is None or a.status not in soc.OPEN:
                        continue
                    if have is None:
                        a.fingerprint, a.device_name = fp, name
                        have = a
                    else:
                        a.status, a.closed_at, a.closed_by = "closed", now, "auto: merged into the device's alert"
                        merged += 1
                db.commit()
        soc.raise_alert(rule=f"tls_{code}", device=name, title=_TITLES[code], severity=g["sev"],
                        category="vulnerability" if code not in ("expired", "expiring") else "system", fp_detail=ip, ip=ip,
                        detail={"message": f"{ip} - " + "; ".join(sorted(set(g["messages"])))[:400], "ports": sorted(set(g["ports"]))},
                        source="rules", now=now, count=0)
    closed = 0
    with SessionLocal() as db:
        for rule, device, fp in stale:
            if fp in active:
                continue
            for a in db.execute(select(SocAlert).where(SocAlert.fingerprint == fp, SocAlert.status.in_(soc.OPEN))).scalars().all():
                regrouped = fp.rsplit("|", 1)[-1].count(":") == 1          # the per-port form "ip:port" of before 3.64
                a.status, a.closed_at, a.closed_by = "closed", now, ("auto: regrouped per device" if regrouped else "auto: recovered")
                closed += 1
        db.commit()
    return {"alerts": len(active), "closed": closed, "merged": merged}


_TITLES = {"self_signed_default": "Factory default TLS certificate", "expired": "TLS certificate expired", "expiring": "TLS certificate about to expire", "self_signed": "Self-signed TLS certificate", "weak_key": "Weak key in a TLS certificate",
           "weak_signature": "Weak signature of a TLS certificate", "legacy_protocol": "Outdated TLS protocol accepted"}


async def run_all(ids: Optional[List[int]] = None) -> dict:
    """Checks every target (or the given ones). One run at a time."""
    global _running
    if _running:
        return {"ok": False, "error": "a check is already running"}
    _running = True
    try:
        discover()
        with SessionLocal() as db:
            q = select(TlsCheck.id, TlsCheck.ip, TlsCheck.port)
            if ids:
                q = q.where(TlsCheck.id.in_(ids))
            rows = db.execute(q).all()
        from services import asset_state
        gone = asset_state.inactive_ips()
        rows = [r for r in rows if r[1] not in gone]               # 3.76: no TLS tries on an entry that is probably removed / set aside
        # 3.77: one ping / port answer per address first - a dead address gets no tries on its ports in this cycle
        from services import availability
        alive = {}
        for ip in {r[1] for r in rows}:
            try:
                alive[ip] = (await availability._answers(ip))[0]
            except Exception:
                alive[ip] = True
        skipped = sum(1 for r in rows if not alive.get(r[1], True))
        rows = [r for r in rows if alive.get(r[1], True)]
        _last["skipped_dead"] = skipped
        sem = asyncio.Semaphore(CONCURRENCY)

        async def one(cid, ip, port):
            async with sem:
                r = await probe(ip, port)
            _store(cid, r, datetime.utcnow())
        await asyncio.gather(*(one(*r) for r in rows))
        alerts()
        _last.update(at=datetime.utcnow().isoformat() + "Z", error=None)
        return {"ok": True, "checked": len(rows)}
    except Exception as e:
        _last.update(error=f"{type(e).__name__}: {e}"[:200])
        return {"ok": False, "error": _last["error"]}
    finally:
        _running = False


def _view(r: TlsCheck, now: datetime, name: str) -> dict:
    def j(v):
        try:
            return json.loads(v) if v else []
        except Exception:
            return []
    days = None
    if r.not_after:
        days = round((r.not_after - now).total_seconds() / 86400, 1)
    return {"id": r.id, "ip": r.ip, "name": name, "port": r.port, "manual": bool(r.manual), "subject": r.subject, "issuer": r.issuer, "names": j(r.names),
            "not_before": r.not_before.isoformat() + "Z" if r.not_before else None, "not_after": r.not_after.isoformat() + "Z" if r.not_after else None, "days": days, "key": r.key_desc,
            "sig": r.sig_alg, "self_signed": bool(r.self_signed), "protocol": r.protocol, "cipher": r.cipher, "legacy": j(r.legacy), "findings": j(r.findings),
            "last_check_at": r.last_check_at.isoformat() + "Z" if r.last_check_at else None, "error": r.error}


def overview() -> dict:
    now = datetime.utcnow()
    with SessionLocal() as db:
        names = {a.ip: a.name or a.ip for a in db.execute(select(Asset).where(Asset.ip.is_not(None))).scalars().all()}
        rows = [_view(r, now, names.get(r.ip, r.ip)) for r in db.execute(select(TlsCheck)).scalars().all()]
    rows.sort(key=lambda v: (v["days"] is None, v["days"] if v["days"] is not None else 0))
    return {"settings": settings(), "running": _running, "last": dict(_last), "items": rows}


def public_summary() -> dict:
    """For Central: how many certificates, how many are expired / about to expire / weak, and the worst few (no addresses)."""
    ov = overview()
    items = [i for i in ov["items"] if i["days"] is not None]
    worst = [i for i in items if any(f["code"] in CODES for f in i["findings"])]
    return {"total": len(items), "expired": sum(1 for i in items if any(f["code"] == "expired" for f in i["findings"])),
            "expiring": sum(1 for i in items if any(f["code"] == "expiring" for f in i["findings"])),
            "weak": sum(1 for i in items if any(f["code"] in ("weak_key", "weak_signature", "legacy_protocol") for f in i["findings"])),
            "intercepted": sum(1 for i in items if any(f["code"] == "intercepted" for f in i["findings"])),
            "worst": [{"n": i["name"], "p": i["port"], "d": i["days"], "f": [f["code"] for f in i["findings"]][:4]} for i in worst][:12]}


# ── Loop ─────────────────────────────────────────────────────────────────────

async def _loop():
    await asyncio.sleep(300)
    while True:
        try:
            if _settings.get("enabled"):
                await run_all()
        except Exception as e:
            print(f"[tls] cycle error: {type(e).__name__}: {e}")
        await asyncio.sleep(INTERVAL_SEC)


def start():
    global _task
    if _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())


def stop():
    global _task
    if _task:
        _task.cancel()
        _task = None
