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

from models.database import SessionLocal, TlsCheck, VulnHost, VulnService, Asset, Device

_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "tls.json")
DEFAULTS = {"enabled": True, "warn_days": 30, "crit_days": 7}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 2376, 4443, 5986, 6443, 8443, 8444, 8883, 9443, 10443}
TLS_SERVICES = ("https", "ssl", "tls", "imaps", "pop3s", "ldaps", "smtps", "ftps")
INTERVAL_SEC = 6 * 3600
TIMEOUT = 6.0
CONCURRENCY = 6
LEGACY = ("TLSv1", "TLSv1.1")
CODES = ("expired", "expiring", "self_signed", "weak_key", "weak_signature", "legacy_protocol")
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
    na = r.get("not_after")
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
    present = {f["code"]: f for f in fs if f["code"] in CODES}
    for code in CODES:
        rule = f"tls_{code}"
        if code in present:
            f = present[code]
            soc.raise_alert(rule=rule, device=name, title=_TITLES[code], severity=f["severity"], category="vulnerability" if code != "expired" and code != "expiring" else "system",
                            fp_detail=f"{ip}:{port}", ip=ip, detail={"message": f"{ip}:{port} - {f['message']}", "description": f"{ip}:{port}"}, source="rules", now=now)
        else:
            soc.resolve(rule=rule, device=name, fp_detail=f"{ip}:{port}")


_TITLES = {"expired": "TLS certificate expired", "expiring": "TLS certificate about to expire", "self_signed": "Self-signed TLS certificate", "weak_key": "Weak key in a TLS certificate",
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
        sem = asyncio.Semaphore(CONCURRENCY)

        async def one(cid, ip, port):
            async with sem:
                r = await probe(ip, port)
            _store(cid, r, datetime.utcnow())
        await asyncio.gather(*(one(*r) for r in rows))
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
