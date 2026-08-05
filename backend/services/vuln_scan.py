"""
Passive network vulnerability scanner.

Scope, deliberately: NO exploitation, NO login/brute-force attempts against
unknown hosts. For every live host found in the configured CIDR ranges
(services.scanner / ScanRange — same ranges the device scanner uses), this
just:

  1. Probes a broad set of common ports (connect only).
  2. For a handful of protocols that announce themselves on connect (SSH,
     FTP, SMTP, POP3, IMAP, Telnet, HTTP/S, MySQL), reads the banner/greeting
     and parses a product+version out of it with a regex. Ports without a
     banner-grab implemented here (SMB/RDP/MSSQL/VNC/PPTP) are just recorded
     as "open" — no version, no CVE lookup for those in this MVP.
  3. Known Mikrotik/Cisco devices already have an accurate, authenticated
     version (services.refresher's daily enrichment) — that's fed into the
     same CVE pipeline directly, no need to re-probe.
  4. Optional, opt-in per host: if a host has a Credential assigned
     (VulnHost.credential_id — the SAME Credential model used for Mikrotik
     devices) and SSH (22) is open, log in and run two read-only commands
     (`cat /etc/os-release`, `uname -a`) to get a precise Linux distro/version
     instead of relying on the bare SSH banner. Still read-only, still no
     package audit — just a more accurate OS identifier for hosts the user
     explicitly trusted with credentials.
  5. Every unique (product, version) found anywhere in the scan is looked up
     ONCE against the public NVD CVE API (deduped — a LAN with 20 identical
     Ubuntu boxes only costs one NVD query, not 20), cached in the DB for
     NVD_CACHE_DAYS so a weekly re-scan doesn't re-query versions we already
     know about.

Runs on a weekly schedule (default Sunday 02:00 local time) plus a manual
trigger, mirroring the start()/stop() pattern in services/refresher.py.
"""
import asyncio
import io
import os
import re
import time
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import quote

import aiohttp
from sqlalchemy import select, delete

from models.database import SessionLocal, Device, Credential, ScanRange, VulnHost, VulnService, VulnFinding
from services.crypto import decrypt
from services import scanner as scan_svc

# ── Config ────────────────────────────────────────────────────────────────
SCAN_DAY = int(os.environ.get("MIKROTIK_VULN_SCAN_DAY", "6"))     # 0=Mon .. 6=Sun
SCAN_HOUR = int(os.environ.get("MIKROTIK_VULN_SCAN_HOUR", "2"))   # local time, 24h
NVD_API_KEY = os.environ.get("MIKROTIK_NVD_API_KEY", "")
NVD_CACHE_DAYS = int(os.environ.get("MIKROTIK_NVD_CACHE_DAYS", "7"))
# Free-tier NVD: ~5 requests / 30s without a key, ~50 / 30s with one.
NVD_MIN_INTERVAL = 1.2 if NVD_API_KEY else 6.5

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
SCAN_CONCURRENCY = int(os.environ.get("MIKROTIK_VULN_SCAN_CONCURRENCY", "40"))

# Ports we actively fingerprint (banner grab + version parse).
BANNER_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    993: "imaps", 995: "pop3s", 3306: "mysql",
    8080: "http", 8443: "https",
}
# Ports we just record as open (no reliable pre-auth version available here).
FLAG_ONLY_PORTS = {
    135: "msrpc", 139: "netbios", 445: "smb",
    1433: "mssql", 1723: "pptp", 3389: "rdp", 5900: "vnc",
}
# WinRM — used for the optional, credentialed Windows identity check (like
# SSH for Linux, see _winrm_identity below). Not banner-grabbed pre-auth.
WINRM_PORTS = {5985: "winrm", 5986: "winrm-ssl"}
ALL_PORTS = sorted(set(BANNER_PORTS) | set(FLAG_ONLY_PORTS) | set(WINRM_PORTS) | {8291, 8728, 8729})

# Credential auth attempts are capped at one try per (host, credential) per
# scan — never retried in a loop — specifically to avoid ever contributing to
# an Active Directory account lockout policy. A credential that fails is
# simply not tried again until the NEXT scheduled scan (a week later by
# default), which is far outside any realistic lockout window.
_failed_combo_cache: dict = {}  # (ip, credential_id) -> last_failed_at
FAILED_COMBO_RETRY_DAYS = int(os.environ.get("MIKROTIK_VULN_CRED_RETRY_DAYS", "30"))


# ── State (read by /api/vuln endpoints) ──────────────────────────────────────
_in_progress = False
_last_run: Optional[datetime] = None
_last_duration_sec: Optional[float] = None
_hosts_scanned = 0
_findings_count = 0
_task: Optional[asyncio.Task] = None
_nvd_last_call = 0.0


def status() -> dict:
    now = datetime.utcnow()
    next_dt = _next_run_datetime(now)
    return {
        "in_progress": _in_progress,
        "last_run": _last_run.isoformat() if _last_run else None,
        "last_duration_sec": round(_last_duration_sec, 1) if _last_duration_sec else None,
        "hosts_scanned_last": _hosts_scanned,
        "findings_count_last": _findings_count,
        "scan_day": SCAN_DAY,
        "scan_hour": SCAN_HOUR,
        "next_run_estimated": next_dt.timestamp(),
    }


# ── Scheduling ────────────────────────────────────────────────────────────

def _next_run_datetime(now: datetime) -> datetime:
    """Next occurrence of SCAN_DAY (0=Mon..6=Sun) at SCAN_HOUR:00, in UTC
    (server local time — same convention as the rest of this app)."""
    days_ahead = (SCAN_DAY - now.weekday()) % 7
    candidate = (now + timedelta(days=days_ahead)).replace(
        hour=SCAN_HOUR, minute=0, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate


async def _loop():
    while True:
        try:
            now = datetime.utcnow()
            sleep_sec = max(1.0, (_next_run_datetime(now) - now).total_seconds())
            await asyncio.sleep(sleep_sec)
            await run_scan()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[vuln_scan] loop error: {e}")


def start():
    global _task
    if _task is None or _task.done():
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
        _task = None


# ── Banner parsing (product, version) ────────────────────────────────────────

_SSH_RE = re.compile(r"SSH-\d\.\d-([A-Za-z][\w.]*?)[_-]?(\d+(?:\.\d+){0,3})")
_SLASH_VER_RE = re.compile(r"([A-Za-z][\w.\-]*)/(\d+(?:\.\d+){0,3})")
_GENERIC_VER_RE = re.compile(
    r"\b(vsftpd|proftpd|pure-ftpd|postfix|exim|sendmail|dovecot|courier|"
    r"openssh|mysql|mariadb|nginx|apache|microsoft-iis)\b[^\d]*(\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)


def _parse_banner(banner: str) -> tuple:
    """Best-effort (product, version) extraction from a raw service banner.
    Returns (None, None) if nothing recognisable was found — that's normal
    and expected for a lot of banners (custom builds, hardened services,
    version strings deliberately hidden, etc.)."""
    if not banner:
        return None, None
    m = _SSH_RE.search(banner)
    if m:
        return m.group(1), m.group(2)
    m = _GENERIC_VER_RE.search(banner)
    if m:
        return m.group(1), m.group(2)
    m = _SLASH_VER_RE.search(banner)
    if m:
        return m.group(1), m.group(2)
    return None, None


async def _read_greeting(ip: str, port: int, send: Optional[bytes] = None,
                         size: int = 512) -> Optional[str]:
    """Connect, optionally send a probe, read whatever the service sends
    back unprompted (or in response to `send`), then disconnect. Pure
    read — no protocol negotiation, no auth."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
        if send:
            writer.write(send)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(size), timeout=BANNER_TIMEOUT)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def _grab_http(ip: str, port: int) -> tuple:
    """Return (banner_raw, product, version) from the Server header (falls
    back to X-Powered-By). No SSL cert validation needed — we're only
    reading a header, not trusting the connection for anything sensitive."""
    import ssl as ssl_mod
    scheme = "https" if port in (443, 8443) else "http"
    ssl_ctx = None
    if scheme == "https":
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE
    try:
        timeout = aiohttp.ClientTimeout(total=CONNECT_TIMEOUT + BANNER_TIMEOUT)
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, force_close=True, limit=1)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(f"{scheme}://{ip}:{port}/", allow_redirects=False) as resp:
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                banner = " | ".join(x for x in (server, powered) if x)
                product, version = _parse_banner(server) if server else (None, None)
                if not product and powered:
                    product, version = _parse_banner(powered)
                return banner or None, product, version
    except Exception:
        return None, None, None


async def _grab_mysql(ip: str, port: int) -> tuple:
    """MySQL/MariaDB sends a plaintext version string in its initial
    handshake packet, before any authentication."""
    data = await _read_greeting(ip, port)
    if not data:
        return None, None, None
    # The handshake packet is binary ([3-byte length][seq][protocol version]
    # [version\x00...]); _read_greeting already decoded it permissively as
    # text, so rather than rely on exact byte offsets we just scan the
    # (lossy but digit/dot-preserving) decoded string for a plausible
    # "x.y.z" version pattern.
    m = re.search(r"(\d+\.\d+\.\d+)(-MariaDB)?", data)
    if not m:
        return data[:80], None, None
    version = m.group(1)
    product = "MariaDB" if m.group(2) or "mariadb" in data.lower() else "MySQL"
    return data[:80], product, version


async def _grab_service(ip: str, port: int, kind: str) -> tuple:
    """Dispatch to the right passive grabber. Returns (banner_raw, product, version)."""
    if kind in ("http", "https"):
        return await _grab_http(ip, port)
    if kind == "mysql":
        return await _grab_mysql(ip, port)
    # SSH/FTP/SMTP/POP3/IMAP/Telnet all announce themselves unprompted on connect.
    banner = await _read_greeting(ip, port)
    if not banner:
        return None, None, None
    product, version = _parse_banner(banner)
    return banner.strip()[:200], product, version


# ── Optional authenticated SSH identity check (opt-in, credentialed hosts only) ──

_OS_RELEASE_RE = re.compile(r'^ID="?([\w.-]+)"?', re.MULTILINE)
_VERSION_ID_RE = re.compile(r'^VERSION_ID="?([\w.-]+)"?', re.MULTILINE)

_LINUX_DISTRO_NAMES = {
    "ubuntu": "Ubuntu", "debian": "Debian", "centos": "CentOS", "rhel": "Red Hat Enterprise Linux",
    "fedora": "Fedora", "rocky": "Rocky Linux", "almalinux": "AlmaLinux", "opensuse": "openSUSE",
}


def _ssh_identity_sync(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Blocking — run via loop.run_in_executor. Read-only: only ever runs
    `cat /etc/os-release` and `uname -a`, nothing that changes device state."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password,
                        timeout=8, banner_timeout=8, auth_timeout=8,
                        look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command(
            "cat /etc/os-release 2>/dev/null; echo ---UNAME---; uname -a", timeout=8)
        output = stdout.read().decode("utf-8", errors="ignore")
        return {"output": output}
    except Exception:
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


async def _ssh_identity(ip: str, port: int, username: str, password: str) -> tuple:
    """Returns (product, version) parsed from /etc/os-release, or (None, None)."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _ssh_identity_sync, ip, port, username, password)
    if not result:
        return None, None
    output = result["output"]
    id_m = _OS_RELEASE_RE.search(output)
    ver_m = _VERSION_ID_RE.search(output)
    if id_m and ver_m:
        product = _LINUX_DISTRO_NAMES.get(id_m.group(1).lower(), id_m.group(1))
        return product, ver_m.group(1)
    return None, None


# ── Optional authenticated Windows identity check (SSH's counterpart) ───────

def _winrm_identity_sync(ip: str, port: int, username: str, password: str,
                         domain: Optional[str]) -> Optional[dict]:
    """Blocking — run via loop.run_in_executor. Read-only: only ever runs
    `systeminfo`, nothing that changes device state. `domain` set → domain
    account (DOMAIN\\user via NTLM); left blank → local Windows account."""
    import winrm
    user = f"{domain}\\{username}" if domain else username
    scheme = "https" if port == 5986 else "http"
    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(user, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=10, operation_timeout_sec=8,
        )
        result = session.run_cmd("systeminfo")
        if result.status_code != 0:
            return None
        return {"output": result.std_out.decode("utf-8", errors="ignore")}
    except Exception:
        return None


async def _winrm_identity(ip: str, port: int, username: str, password: str,
                          domain: Optional[str]) -> tuple:
    """Returns (product, version) parsed from `systeminfo` output, or (None, None)."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, _winrm_identity_sync, ip, port, username, password, domain)
    if not result:
        return None, None
    output = result["output"]
    name_m = re.search(r"OS Name:\s*(.+)", output)
    ver_m = re.search(r"OS Version:\s*([\d.]+)", output)
    if name_m and ver_m:
        return name_m.group(1).strip(), ver_m.group(1).strip()
    return None, None


# ── Credential auto-detection (SSH + WinRM) ──────────────────────────────────
# Same idea as MikrotikClient remembering which access method works: try
# every configured credential ONCE per host per scan (see FAILED_COMBO_RETRY_
# DAYS at the top of this file for why never more than once), remember
# whichever one succeeds so the next scan goes straight to it.

async def _auth_augment(ip: str, ports_found: dict, version_pairs: dict,
                        remembered_cred_id: Optional[int], all_creds: list) -> Optional[int]:
    """Returns the id of the credential that worked, or None. Does not touch
    the DB itself — the caller applies the result once the VulnHost row is
    guaranteed to exist (see _apply_credentials)."""
    has_ssh = 22 in ports_found
    winrm_port = 5985 if 5985 in ports_found else (5986 if 5986 in ports_found else None)
    if not has_ssh and winrm_port is None:
        return None

    candidates = [c for c in all_creds if c.password_enc]
    if remembered_cred_id:
        candidates.sort(key=lambda c: 0 if c.id == remembered_cred_id else 1)

    now = datetime.utcnow()
    for cred in candidates:
        combo_key = (ip, cred.id)
        last_failed = _failed_combo_cache.get(combo_key)
        if last_failed and (now - last_failed).days < FAILED_COMBO_RETRY_DAYS:
            continue

        try:
            password = decrypt(cred.password_enc)
        except Exception:
            continue

        product = version = None
        if has_ssh:
            product, version = await _ssh_identity(ip, 22, cred.username, password)
        if not (product and version) and winrm_port:
            product, version = await _winrm_identity(ip, winrm_port, cred.username, password, cred.domain)

        if product and version:
            version_pairs.setdefault((product, version), []).append(
                (ip, 22 if has_ssh else winrm_port, "auth"))
            _failed_combo_cache.pop(combo_key, None)
            return cred.id
        _failed_combo_cache[combo_key] = now

    return None


async def _apply_credentials(auth_results: dict) -> None:
    """Persist auto-detected credential_id onto each host — called after
    _persist_services so the VulnHost rows are guaranteed to already exist."""
    if not auth_results:
        return
    with SessionLocal() as db:
        for ip, cred_id in auth_results.items():
            host = db.execute(select(VulnHost).where(VulnHost.ip == ip)).scalar_one_or_none()
            if host and host.credential_id != cred_id:
                host.credential_id = cred_id
        db.commit()


# ── NVD CVE lookup (deduped + cached) ────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}


async def _nvd_query_live(product: str, version: str) -> list:
    """Live NVD API call. Never raises — any failure just yields no findings
    for this (product, version), the rest of the scan continues normally."""
    global _nvd_last_call
    wait = NVD_MIN_INTERVAL - (time.time() - _nvd_last_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _nvd_last_call = time.time()

    keyword = quote(f"{product} {version}")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception as e:
        print(f"[vuln_scan] NVD query failed for {product} {version}: {e}")
        return []

    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score, severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = entries[0].get("baseSeverity") or cvss_data.get("baseSeverity")
                break
        refs = cve.get("references", [])
        ref_url = refs[0].get("url") if refs else None
        findings.append({
            "cve_id": cve_id,
            "cvss_score": score,
            "severity": (severity or "").upper() or None,
            "summary": (summary or "")[:1000],
            "published": cve.get("published"),
            "ref_url": ref_url,
        })
    return findings


async def _get_findings_for(db, product: str, version: str) -> list:
    """DB-cached NVD lookup — re-queries only if the cache entry is missing
    or older than NVD_CACHE_DAYS."""
    cutoff = datetime.utcnow() - timedelta(days=NVD_CACHE_DAYS)
    cached = db.execute(
        select(VulnFinding)
        .where(VulnFinding.product == product, VulnFinding.version == version)
        .where(VulnFinding.queried_at >= cutoff)
    ).scalars().all()
    if cached:
        return cached

    live = await _nvd_query_live(product, version)
    # Clear stale rows for this pair, insert fresh ones (even if empty —
    # an empty result is itself worth caching so we don't re-query a clean
    # version every week).
    db.execute(delete(VulnFinding).where(
        VulnFinding.product == product, VulnFinding.version == version))
    now = datetime.utcnow()
    rows = []
    for f in live:
        row = VulnFinding(
            product=product, version=version, queried_at=now,
            cve_id=f["cve_id"], cvss_score=f["cvss_score"], severity=f["severity"],
            summary=f["summary"], published=f["published"], ref_url=f["ref_url"],
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return rows


# ── Orchestration ────────────────────────────────────────────────────────────

async def _prune_dead_hosts(candidate_ips: list, alive_ips: set) -> None:
    """Remove VulnHost (+ its VulnService rows) for any host that was part of
    this scan's target set but didn't answer this time. The report should
    only ever reflect devices currently active on the network — a host that
    went away shouldn't linger in the list from a previous scan."""
    dead_ips = [ip for ip in candidate_ips if ip not in alive_ips]
    if not dead_ips:
        return
    with SessionLocal() as db:
        dead_hosts = db.execute(select(VulnHost).where(VulnHost.ip.in_(dead_ips))).scalars().all()
        for h in dead_hosts:
            db.execute(delete(VulnService).where(VulnService.host_id == h.id))
            db.delete(h)
        db.commit()


async def _probe_host(ip: str, sem: asyncio.Semaphore) -> dict:
    """Returns {port: (service_name, banner, product, version)} for every
    open port found on this host."""
    async with sem:
        open_ports = await asyncio.gather(*[
            scan_svc._tcp_open(ip, p, timeout=CONNECT_TIMEOUT) for p in ALL_PORTS
        ])
        found = {}
        for port, is_open in zip(ALL_PORTS, open_ports):
            if not is_open:
                continue
            if port in FLAG_ONLY_PORTS:
                found[port] = (FLAG_ONLY_PORTS[port], None, None, None)
                continue
            kind = BANNER_PORTS.get(port, "unknown")
            banner, product, version = await _grab_service(ip, port, kind)
            found[port] = (kind, banner, product, version)
        return found


def _device_version_pair(d) -> Optional[tuple]:
    """Known Mikrotik/Cisco devices already have an accurate, authenticated
    version (services/refresher.py's daily enrichment) — reuse it directly
    instead of re-probing."""
    if not d.ros_version:
        return None
    product = "MikroTik RouterOS" if d.vendor == "mikrotik" else f"{d.vendor} {d.model or ''}".strip()
    return product, d.ros_version




async def _persist_services(alive_ips: list, results: list) -> dict:
    """Upsert VulnHost + VulnService rows for the given (ip, ports_found)
    pairs. Returns {ip: host_id}. A service no longer present on a re-scan
    (e.g. upgraded/replaced) overwrites the stale row in place, so a fixed
    vulnerability naturally stops matching in /api/vuln/findings without
    any separate "resolved" bookkeeping."""
    with SessionLocal() as db:
        device_by_ip = {d.ip: d.id for d in db.execute(select(Device)).scalars().all()}
        host_by_ip = {}
        for ip in alive_ips:
            host = db.execute(select(VulnHost).where(VulnHost.ip == ip)).scalar_one_or_none()
            if not host:
                host = VulnHost(ip=ip, device_id=device_by_ip.get(ip))
                db.add(host)
                db.flush()
            host.last_scan_at = datetime.utcnow()
            if not host.device_id and ip in device_by_ip:
                host.device_id = device_by_ip[ip]
            host_by_ip[ip] = host.id
        db.commit()

        for ip, ports_found in zip(alive_ips, results):
            host_id = host_by_ip.get(ip)
            if not host_id:
                continue
            for port, (kind, banner, product, version) in ports_found.items():
                svc_row = db.execute(
                    select(VulnService).where(VulnService.host_id == host_id, VulnService.port == port)
                ).scalar_one_or_none()
                if svc_row:
                    svc_row.service_name = kind
                    svc_row.banner_raw = banner
                    svc_row.product = product
                    svc_row.version = version
                    svc_row.last_seen = datetime.utcnow()
                else:
                    db.add(VulnService(
                        host_id=host_id, port=port, service_name=kind,
                        banner_raw=banner, product=product, version=version,
                    ))
        db.commit()
        return host_by_ip


async def _lookup_findings(version_pairs: dict) -> int:
    count = 0
    with SessionLocal() as db:
        for product, version in version_pairs:
            try:
                rows = await _get_findings_for(db, product, version)
                count += len(rows)
            except Exception as e:
                print(f"[vuln_scan] finding lookup error for {product} {version}: {e}")
    return count


async def run_scan() -> dict:
    """Full pass: known devices' tracked versions + live network banner-grab
    across all active ScanRange CIDRs, deduped CVE lookups, persisted results."""
    global _in_progress, _last_run, _last_duration_sec, _hosts_scanned, _findings_count

    if _in_progress:
        return {"skipped": "already in progress"}
    _in_progress = True
    start_time = datetime.utcnow()

    try:
        version_pairs: dict = {}  # (product, version) -> list of (ip, port, source)
        with SessionLocal() as db:
            for d in db.execute(select(Device)).scalars().all():
                pair = _device_version_pair(d)
                if pair:
                    version_pairs.setdefault(pair, []).append((d.ip, None, "device"))

        with SessionLocal() as db:
            ranges = db.execute(select(ScanRange).where(ScanRange.active == True)).scalars().all()
            all_creds = db.execute(select(Credential)).scalars().all()
            existing_cred_by_ip = {h.ip: h.credential_id for h in db.execute(select(VulnHost)).scalars().all()}

        import ipaddress
        all_ips_set: set = set()
        for r in ranges:
            try:
                net = ipaddress.ip_network(r.cidr, strict=False)
                all_ips_set.update(str(h) for h in net.hosts())
            except ValueError:
                continue
        all_ips = sorted(all_ips_set)

        sem = asyncio.Semaphore(SCAN_CONCURRENCY)
        results = await asyncio.gather(*[_probe_host(ip, sem) for ip in all_ips])

        alive_ips, alive_results = [], []
        auth_results: dict = {}  # ip -> credential_id that worked
        for ip, ports_found in zip(all_ips, results):
            if not ports_found:
                continue
            alive_ips.append(ip)
            alive_results.append(ports_found)
            for port, (kind, banner, product, version) in ports_found.items():
                if product and version:
                    version_pairs.setdefault((product, version), []).append((ip, port, "banner"))
            cred_id = await _auth_augment(ip, ports_found, version_pairs,
                                          existing_cred_by_ip.get(ip), all_creds)
            if cred_id:
                auth_results[ip] = cred_id

        await _persist_services(alive_ips, alive_results)
        await _apply_credentials(auth_results)
        await _prune_dead_hosts(all_ips, set(alive_ips))
        findings_count = await _lookup_findings(version_pairs)

        _hosts_scanned = len(alive_ips)
        _findings_count = findings_count
        return {"hosts_scanned": len(alive_ips), "unique_versions": len(version_pairs),
                "findings_count": findings_count}
    finally:
        _last_run = datetime.utcnow()
        _last_duration_sec = (_last_run - start_time).total_seconds()
        _in_progress = False


async def scan_one_host(ip: str) -> dict:
    """Targeted re-check of a single host — e.g. to confirm a patch actually
    took effect, without waiting for (or re-running) the whole weekly network
    scan. Reuses the exact same probe/persist/lookup pipeline as run_scan()."""
    sem = asyncio.Semaphore(1)
    ports_found = await _probe_host(ip, sem)

    version_pairs: dict = {}
    with SessionLocal() as db:
        device = db.execute(select(Device).where(Device.ip == ip)).scalar_one_or_none()
        if device:
            pair = _device_version_pair(device)
            if pair:
                version_pairs.setdefault(pair, []).append((ip, None, "device"))
        all_creds = db.execute(select(Credential)).scalars().all()
        existing_host = db.execute(select(VulnHost).where(VulnHost.ip == ip)).scalar_one_or_none()
        remembered_cred_id = existing_host.credential_id if existing_host else None

    for port, (kind, banner, product, version) in ports_found.items():
        if product and version:
            version_pairs.setdefault((product, version), []).append((ip, port, "banner"))

    if ports_found:
        cred_id = await _auth_augment(ip, ports_found, version_pairs, remembered_cred_id, all_creds)
        await _persist_services([ip], [ports_found])
        if cred_id:
            await _apply_credentials({ip: cred_id})
    else:
        await _prune_dead_hosts([ip], set())

    findings_count = await _lookup_findings(version_pairs)
    return {"ip": ip, "alive": bool(ports_found), "unique_versions": len(version_pairs),
            "findings_count": findings_count}
