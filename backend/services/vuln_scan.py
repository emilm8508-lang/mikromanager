"""
Passive network vulnerability scanner.

Scope, deliberately: NO exploitation, NO login/brute-force attempts against
unknown hosts. For every live host found in the configured CIDR ranges
(services.scanner / ScanRange — same ranges the device scanner uses), this
just:

  1. Probes a broad set of common ports (connect only) — general services,
     web/admin ports, databases, Windows/SMB, legacy r-services, etc.
  2. For protocols that announce themselves on connect or reply to a
     harmless plaintext query (SSH, FTP, SMTP, POP3, IMAP, Telnet, HTTP/S,
     MySQL, Redis, Memcached), reads the banner/greeting/reply and parses a
     product+version out of it with a regex. Ports without a banner-grab
     implemented here (SMB/RDP/MSSQL/Oracle/Postgres/MongoDB/VNC/PPTP/NFS/
     etc.) are just recorded as "open" — no version, no CVE lookup for those
     in this MVP.
  3. Known Mikrotik/Cisco devices already have an accurate, authenticated
     version (services.refresher's daily enrichment) — that's fed into the
     same CVE pipeline directly, no need to re-probe.
  4. Optional, opt-in per host: if a host has a Credential assigned
     (VulnHost.credential_id — the SAME Credential model used for Mikrotik
     devices), log in over SSH (Linux) or WinRM (Windows, domain or local)
     and read OS/version info (`cat /etc/os-release`/`uname -a`, or
     `systeminfo`) instead of relying on the bare service banner. Still
     read-only. If MIKROTIK_VULNERS_API_KEY is configured, goes one step
     deeper (throttled to once every MIKROTIK_VULN_PACKAGE_AUDIT_DAYS per
     host, not every scan): pulls the FULL installed-package list
     (dpkg-query/rpm -qa) or Windows KB+software inventory (Get-HotFix +
     registry read) and submits it to vulners.com's audit endpoints — this
     catches vulnerabilities in specific outdated libraries on that host,
     not just "this is Ubuntu 22.04". Every command here is still
     read-only — no package installed/removed, no MSI side effects (Win32_
     Product is deliberately avoided for that reason).
  5. Every unique (product, version) found anywhere in the scan is looked up
     ONCE (deduped — a LAN with 20 identical Ubuntu boxes only costs one
     query per source, not 20) against the public NVD CVE API (keyword
     search, always on, no key required) and, if MIKROTIK_VULNERS_API_KEY is
     configured, also against vulners.com via the official `vulners` pip
     package — a proper CPE-based match, more accurate than NVD's keyword
     search alone. Both sources' CVEs land in the same VulnFinding table
     (deduped by cve_id) and are cached for NVD_CACHE_DAYS so a weekly
     re-scan doesn't re-query versions already known about. No external
     binary (e.g. nmap) is used anywhere in this file — everything here is
     plain Python sockets/aiohttp/paramiko/pywinrm/vulners.

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

import aiohttp
from sqlalchemy import select, delete

from models.database import SessionLocal, Device, Credential, ScanRange, VulnHost, VulnService, VulnPackage, VulnFinding
from services.crypto import decrypt
from services import scanner as scan_svc

# ── Config ────────────────────────────────────────────────────────────────
SCAN_DAY = int(os.environ.get("MIKROTIK_VULN_SCAN_DAY", "6"))     # 0=Mon .. 6=Sun
SCAN_HOUR = int(os.environ.get("MIKROTIK_VULN_SCAN_HOUR", "2"))   # local time, 24h
NVD_API_KEY = os.environ.get("MIKROTIK_NVD_API_KEY", "")
NVD_CACHE_DAYS = int(os.environ.get("MIKROTIK_NVD_CACHE_DAYS", "7"))
# Free-tier NVD: ~5 requests / 30s without a key, ~50 / 30s with one.
NVD_MIN_INTERVAL = 1.2 if NVD_API_KEY else 6.5

# Optional second CVE source — vulners.com via the official `vulners` pip
# package (no external binary). Does proper CPE-based matching (more
# accurate than NVD's keywordSearch) but needs a free API key from
# vulners.com, so it's opt-in: blank key = skip this source entirely, NVD
# alone still covers the baseline.
VULNERS_API_KEY = os.environ.get("MIKROTIK_VULNERS_API_KEY", "")
VULNERS_MIN_INTERVAL = float(os.environ.get("MIKROTIK_VULNERS_MIN_INTERVAL", "1.5"))

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
SCAN_CONCURRENCY = int(os.environ.get("MIKROTIK_VULN_SCAN_CONCURRENCY", "40"))

# Ports we actively fingerprint (banner grab + version parse).
BANNER_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "smtp", 990: "ftps", 993: "imaps", 995: "pop3s",
    3306: "mysql", 6379: "redis", 11211: "memcached",
    # Common alternate/dev HTTP ports and HTTP-based admin panels/APIs —
    # these all go through the same Server-header grab as 80/443.
    3000: "http", 5000: "http", 5601: "http", 5984: "http",
    8000: "http", 8006: "http", 8008: "http", 8080: "http", 8081: "http",
    8086: "http", 8443: "https", 8888: "http", 9000: "http", 9090: "http",
    9200: "http", 9443: "https", 10000: "http", 15672: "http",
}
# Ports we just record as open (no reliable pre-auth version available here).
FLAG_ONLY_PORTS = {
    135: "msrpc", 139: "netbios", 445: "smb",
    1433: "mssql", 1521: "oracle", 1723: "pptp",
    3389: "rdp", 5900: "vnc", 5901: "vnc",
    5432: "postgres", 27017: "mongodb", 2181: "zookeeper",
    111: "rpcbind", 2049: "nfs", 9100: "printer",
    6000: "x11", 512: "rexec", 513: "rlogin", 514: "rsh",
    2375: "docker", 2376: "docker-tls", 5672: "amqp", 61616: "activemq",
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
_vulners_last_call = 0.0


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


async def _grab_redis(ip: str, port: int) -> tuple:
    """Redis accepts simple inline commands — `INFO` (pre-auth, works on any
    instance without `requirepass`/protected-mode auth) replies with a
    plaintext key:value dump including `redis_version`. If auth blocks it we
    just get an error reply and no version — still recorded as open."""
    data = await _read_greeting(ip, port, send=b"INFO\r\n", size=4096)
    if not data:
        return None, None, None
    m = re.search(r"redis_version:(\S+)", data)
    if not m:
        return data[:80], None, None
    return data[:80], "Redis", m.group(1)


async def _grab_memcached(ip: str, port: int) -> tuple:
    """Memcached's classic text protocol has no built-in auth — `version`
    replies with `VERSION x.y.z` pre-auth."""
    data = await _read_greeting(ip, port, send=b"version\r\n", size=256)
    if not data:
        return None, None, None
    m = re.search(r"VERSION\s+(\S+)", data)
    if not m:
        return data[:80], None, None
    return data[:80], "Memcached", m.group(1)


async def _grab_service(ip: str, port: int, kind: str) -> tuple:
    """Dispatch to the right passive grabber. Returns (banner_raw, product, version)."""
    if kind in ("http", "https"):
        return await _grab_http(ip, port)
    if kind == "mysql":
        return await _grab_mysql(ip, port)
    if kind == "redis":
        return await _grab_redis(ip, port)
    if kind == "memcached":
        return await _grab_memcached(ip, port)
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
    """Returns (product, version, distro_id) parsed from /etc/os-release, or
    (None, None, None). distro_id is the raw /etc/os-release ID (e.g.
    "ubuntu"), kept alongside the human-readable product name so callers can
    pick a package manager (see _PACKAGE_MANAGER_BY_DISTRO below) without
    re-deriving it from the display name."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _ssh_identity_sync, ip, port, username, password)
    if not result:
        return None, None, None
    output = result["output"]
    id_m = _OS_RELEASE_RE.search(output)
    ver_m = _VERSION_ID_RE.search(output)
    if id_m and ver_m:
        distro_id = id_m.group(1).lower()
        product = _LINUX_DISTRO_NAMES.get(distro_id, distro_id)
        return product, ver_m.group(1), distro_id
    return None, None, None


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


# ── Full package/software inventory (credentialed hosts only) ───────────────
# Only ever called for a host where a Credential has ALREADY been confirmed
# working via _auth_augment — this is strictly deeper identification for
# hosts the user explicitly trusted, never a new attack surface. Every
# command here is read-only, same guarantee as the identity checks above.

_PACKAGE_MANAGER_BY_DISTRO = {
    "ubuntu": "dpkg", "debian": "dpkg",
    "centos": "rpm", "rhel": "rpm", "fedora": "rpm",
    "rocky": "rpm", "almalinux": "rpm", "opensuse": "rpm",
}


_RPM_LINE_RE = re.compile(r'^(.+)-([^-]+)-([^-]+)\.(\w+)$')


def _ssh_list_packages_sync(ip: str, port: int, username: str, password: str,
                            distro_id: Optional[str]) -> Optional[list]:
    """Blocking — run via loop.run_in_executor. dpkg-query/rpm -qa only ever
    list already-installed packages, nothing changes on the host. Returns a
    list of (raw_line, name, version) — the raw line matches vulners'
    linux_audit() docstring examples exactly ("openssl 1.1.1d-0+deb10u3
    amd64" / "openssl-1.0.2k-19.el7.x86_64") and goes to vulners verbatim;
    name/version are parsed out separately for our own VulnPackage
    inventory (verified the rpm regex against vulners' own examples,
    including a package name that itself contains a dash like
    "bash-completion-2.1-6.el7.noarch")."""
    pkg_mgr = _PACKAGE_MANAGER_BY_DISTRO.get((distro_id or "").lower())
    if not pkg_mgr:
        return None
    cmd = ("dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'" if pkg_mgr == "dpkg"
           else "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'")
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=username, password=password,
                        timeout=8, banner_timeout=8, auth_timeout=8,
                        look_for_keys=False, allow_agent=False)
        _, stdout, _ = client.exec_command(cmd, timeout=20)
        output = stdout.read().decode("utf-8", errors="ignore")
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        entries = []
        for line in lines:
            if pkg_mgr == "dpkg":
                parts = line.split()
                if len(parts) >= 2:
                    entries.append((line, parts[0], parts[1]))
            else:
                m = _RPM_LINE_RE.match(line)
                if m:
                    entries.append((line, m.group(1), m.group(2)))
        return entries or None
    except Exception:
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


async def _ssh_list_packages(ip: str, port: int, username: str, password: str,
                             distro_id: Optional[str]) -> Optional[list]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _ssh_list_packages_sync, ip, port, username, password, distro_id)


_WINRM_INVENTORY_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue'; "
    "(Get-HotFix | Select-Object -Expand HotFixID) -join '|'; "
    "Write-Output '---SOFTWARE---'; "
    "Get-ItemProperty "
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
    "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
    "| Where-Object { $_.DisplayName -and $_.DisplayVersion } "
    "| ForEach-Object { \"$($_.DisplayName)|$($_.DisplayVersion)\" }"
)


def _winrm_list_inventory_sync(ip: str, port: int, username: str, password: str,
                               domain: Optional[str]) -> Optional[dict]:
    """Blocking — run via loop.run_in_executor. Read-only: Get-HotFix (list
    installed KBs) plus a registry read of the standard Uninstall keys (list
    installed software) — the same technique Programs & Features itself
    uses. Deliberately NOT using WMI's Win32_Product (a common alternative)
    — it's documented to trigger MSI package reconfiguration as a side
    effect just from enumerating it, which would violate the read-only
    guarantee the rest of this scanner holds to."""
    import winrm
    user = f"{domain}\\{username}" if domain else username
    scheme = "https" if port == 5986 else "http"
    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(user, password), transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=30, operation_timeout_sec=25,
        )
        result = session.run_ps(_WINRM_INVENTORY_SCRIPT)
        if result.status_code != 0:
            return None
        output = result.std_out.decode("utf-8", errors="ignore")
    except Exception:
        return None

    if "---SOFTWARE---" not in output:
        return None
    kb_part, _, sw_part = output.partition("---SOFTWARE---")
    kbs = [k.strip() for k in kb_part.strip().split("|") if k.strip()]
    software = []
    for line in sw_part.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, _, ver = line.partition("|")
        if name.strip() and ver.strip():
            software.append({"software": name.strip(), "version": ver.strip()})
    return {"kbs": kbs, "software": software}


async def _winrm_list_inventory(ip: str, port: int, username: str, password: str,
                                domain: Optional[str]) -> Optional[dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _winrm_list_inventory_sync, ip, port, username, password, domain)


# ── Credential auto-detection (SSH + WinRM) ──────────────────────────────────
# Same idea as MikrotikClient remembering which access method works: try
# every configured credential ONCE per host per scan (see FAILED_COMBO_RETRY_
# DAYS at the top of this file for why never more than once), remember
# whichever one succeeds so the next scan goes straight to it.

async def _auth_augment(ip: str, ports_found: dict, version_pairs: dict,
                        remembered_cred_id: Optional[int], all_creds: list,
                        known_device_ips: frozenset = frozenset()) -> Optional[dict]:
    """Returns details of the credential that worked, or None:
    {"cred_id", "product", "version", "distro_id" (SSH only, else None),
    "via_ssh", "winrm_port"} — used both to persist the winning credential
    (_apply_credentials) and, for hosts where it worked, to drive the
    deeper package/software audit afterward (_package_audit). Does not
    touch the DB itself — the caller applies results once the VulnHost row
    is guaranteed to exist (see _apply_credentials).

    Skips entirely for any ip already in `known_device_ips` (a Mikrotik/Cisco
    Device row, per services/scanner.py's vendor detection — network
    appliances, not general-purpose servers): those already have an accurate,
    authenticated version via refresher.py's daily enrichment
    (_device_version_pair below), so this generic Linux-flavored SSH probe
    (`cat /etc/os-release`) would only ever produce noise there — RouterOS's
    CLI doesn't understand it ("bad command name cat"), and cycling through
    every saved credential against it generates spurious failed-login
    entries in the device's own log for zero benefit."""
    if ip in known_device_ips:
        return None

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

        product = version = distro_id = None
        via_ssh = False
        if has_ssh:
            product, version, distro_id = await _ssh_identity(ip, 22, cred.username, password)
            via_ssh = bool(product and version)
        if not (product and version) and winrm_port:
            product, version = await _winrm_identity(ip, winrm_port, cred.username, password, cred.domain)
            distro_id = None
            via_ssh = False

        if product and version:
            version_pairs.setdefault((product, version), []).append(
                (ip, 22 if via_ssh else winrm_port, "auth"))
            _failed_combo_cache.pop(combo_key, None)
            return {
                "cred_id": cred.id, "product": product, "version": version,
                "distro_id": distro_id if via_ssh else None,
                "via_ssh": via_ssh, "winrm_port": None if via_ssh else winrm_port,
            }
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


# ── Full package/software audit via vulners (credentialed hosts only) ───────
# Runs AFTER a credential is confirmed working (_auth_augment) and the
# lightweight OS-version identification already succeeded — this goes one
# level deeper: submits the ACTUAL installed package/software list, so we
# catch vulnerabilities in specific outdated libraries, not just "this is
# Ubuntu 22.04". Requires MIKROTIK_VULNERS_API_KEY (NVD has no equivalent
# audit-by-package-list endpoint) — skipped entirely without a key, same as
# the passive vulners.com CVE source elsewhere in this file. Gated per-host
# by PACKAGE_AUDIT_DAYS since a single call here can submit thousands of
# packages — much "heavier" than the weekly scan's usual per-(product,
# version) lookups, so it runs far less often.

PACKAGE_AUDIT_DAYS = int(os.environ.get("MIKROTIK_VULN_PACKAGE_AUDIT_DAYS", "7"))
_VULNERS_MAX_PACKAGES = 2500  # vulners' own documented limit per audit call


def _audit_entries_to_findings(entries: list) -> list:
    """Shared defensive parsing for one (package_name, raw_vuln_dict) entry
    list, used by both _vulners_linux_audit_sync and _vulners_win_audit_sync.
    Same philosophy as _vulners_query_sync above: the exact response shape
    of vulners' audit endpoints is "provider-shaped" (not a fixed schema
    per the package's own code) and wasn't verified against a live call
    from this dev sandbox — try several plausible field names, skip a
    malformed entry rather than fail the whole audit."""
    findings = []
    for pkg_name, v in entries:
        if not isinstance(v, dict) or not pkg_name:
            continue
        try:
            cve_id = v.get("id") or v.get("cve_id") or v.get("cveId")
            if not cve_id:
                continue
            pkg_version = v.get("packageVersion") or v.get("version") or v.get("installedVersion")
            cvss = v.get("cvss") or v.get("cvss3") or v.get("cvss2") or {}
            score = cvss.get("score") if isinstance(cvss, dict) else None
            if score is None:
                score = v.get("cvss_score") or v.get("score")
            severity = (cvss.get("severity") if isinstance(cvss, dict) else None) \
                or _cvss_to_severity(score)
            findings.append({
                "package": pkg_name, "package_version": pkg_version,
                "cve_id": cve_id, "cvss_score": score, "severity": severity,
                "summary": (v.get("description") or v.get("summary") or v.get("title") or "")[:1000],
                "published": v.get("published"),
                "ref_url": v.get("href") or v.get("url") or v.get("ref_url"),
            })
        except Exception:
            continue
    return findings


def _vulners_linux_audit_sync(os_name: str, os_version: str, package_lines: list) -> list:
    """Blocking — run via loop.run_in_executor (vulners' HTTP client is
    synchronous). `package_lines` are the raw dpkg-query/rpm -qa lines from
    _ssh_list_packages — vulners' own docstring gives those exact formats
    as expected input, no reformatting needed."""
    import vulners
    api = vulners.VulnersApi(api_key=VULNERS_API_KEY)
    try:
        result = api.audit.linux_audit(os_name, os_version, package_lines) or {}
    except Exception:
        return []

    entries = []
    if isinstance(result, dict):
        packages = result.get("packages")
        if isinstance(packages, dict):
            for pkg_name, pkg_data in packages.items():
                if isinstance(pkg_data, dict):
                    for v in (pkg_data.get("vulnerabilities") or []):
                        entries.append((pkg_name, v))
        for v in (result.get("vulnerabilities") or []):
            if isinstance(v, dict):
                entries.append((v.get("package") or v.get("pkg"), v))
    return _audit_entries_to_findings(entries)


async def _vulners_linux_audit(os_name: str, os_version: str, package_lines: list) -> list:
    if not VULNERS_API_KEY or not package_lines:
        return []
    global _vulners_last_call
    wait = VULNERS_MIN_INTERVAL - (time.time() - _vulners_last_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _vulners_last_call = time.time()
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _vulners_linux_audit_sync, os_name, os_version, package_lines)
    except Exception as e:
        print(f"[vuln_scan] vulners linux_audit failed for {os_name} {os_version}: {e}")
        return []


def _vulners_win_audit_sync(os_name: str, os_version: str, kbs: list, software: list) -> list:
    """Blocking — run via loop.run_in_executor. `software` is already the
    [{"software":..,"version":..}] shape vulners' WinAuditItem expects
    (built by _winrm_list_inventory), `kbs` a list of "KB..." strings."""
    import vulners
    api = vulners.VulnersApi(api_key=VULNERS_API_KEY)
    try:
        result = api.audit.win_audit(os_name, os_version, kbs, software) or {}
    except Exception:
        return []

    entries = []
    if isinstance(result, dict):
        for key in ("vulnerabilities", "software"):
            items = result.get(key)
            if isinstance(items, list):
                for v in items:
                    if isinstance(v, dict):
                        entries.append((v.get("software") or v.get("package") or v.get("name"), v))
    return _audit_entries_to_findings(entries)


async def _vulners_win_audit(os_name: str, os_version: str, kbs: list, software: list) -> list:
    if not VULNERS_API_KEY or (not kbs and not software):
        return []
    global _vulners_last_call
    wait = VULNERS_MIN_INTERVAL - (time.time() - _vulners_last_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _vulners_last_call = time.time()
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _vulners_win_audit_sync, os_name, os_version, kbs, software)
    except Exception as e:
        print(f"[vuln_scan] vulners win_audit failed for {os_name} {os_version}: {e}")
        return []


async def _persist_packages(host_id: int, packages: list) -> None:
    """Upsert VulnPackage rows for one host (`packages` a list of
    (name, version) tuples), then drop any package no longer in the current
    list (upgraded away or uninstalled) so a fixed vulnerability doesn't
    linger as a false positive — unlike VulnService, which only ever
    upserts and never prunes individual stale ports, this cleans up
    per-package since a full audit gives us the complete current set to
    diff against, not just a handful of newly-observed ports."""
    if not packages:
        return
    current_names = {name for name, _ in packages}
    with SessionLocal() as db:
        for name, version in packages:
            row = db.execute(
                select(VulnPackage).where(VulnPackage.host_id == host_id, VulnPackage.name == name)
            ).scalar_one_or_none()
            if row:
                row.version = version
                row.last_seen = datetime.utcnow()
            else:
                db.add(VulnPackage(host_id=host_id, name=name, version=version))
        db.commit()

        stale = db.execute(select(VulnPackage).where(VulnPackage.host_id == host_id)).scalars().all()
        removed = False
        for row in stale:
            if row.name not in current_names:
                db.delete(row)
                removed = True
        if removed:
            db.commit()


async def _package_audit(ip: str, cred, auth_info: dict, host_id: int,
                         last_audit_at: Optional[datetime]) -> None:
    """The deeper, opt-in step for a host where credentials already work:
    pulls the full installed-package/software inventory and submits it to
    vulners.com, instead of relying only on the OS name+version
    _auth_augment already established. Every command run here (dpkg-query/
    rpm -qa/Get-HotFix/registry read) is read-only — same guarantee as the
    rest of this scanner."""
    if not VULNERS_API_KEY:
        return
    if last_audit_at and (datetime.utcnow() - last_audit_at).days < PACKAGE_AUDIT_DAYS:
        return

    try:
        password = decrypt(cred.password_enc)
    except Exception:
        return

    findings_raw: list = []
    packages: list = []

    if auth_info["via_ssh"]:
        entries = await _ssh_list_packages(ip, 22, cred.username, password, auth_info["distro_id"])
        if not entries:
            return
        if len(entries) > _VULNERS_MAX_PACKAGES:
            print(f"[vuln_scan] {ip}: {len(entries)} packages exceeds vulners' "
                  f"{_VULNERS_MAX_PACKAGES}-package limit, submitting the first {_VULNERS_MAX_PACKAGES}")
            entries = entries[:_VULNERS_MAX_PACKAGES]
        package_lines = [e[0] for e in entries]
        packages = [(e[1], e[2]) for e in entries]
        findings_raw = await _vulners_linux_audit(auth_info["distro_id"], auth_info["version"], package_lines)
    elif auth_info["winrm_port"]:
        inv = await _winrm_list_inventory(ip, auth_info["winrm_port"], cred.username, password, cred.domain)
        if not inv:
            return
        findings_raw = await _vulners_win_audit(
            auth_info["product"], auth_info["version"], inv["kbs"], inv["software"])
        packages = [(s["software"], s["version"]) for s in inv["software"]]
    else:
        return

    if packages:
        await _persist_packages(host_id, packages)

    # Prefer the version WE submitted (we know it exactly) over whatever
    # vulners echoes back per finding — its audit response shape is
    # unverified from this sandbox, and if it simply doesn't include a
    # per-vulnerability version field at all, relying solely on that would
    # silently drop every finding. Package names are matched case-
    # sensitively as submitted; a mismatch just falls back to whatever
    # vulners itself provided (if anything).
    known_versions = {name: version for name, version in packages}

    now = datetime.utcnow()
    if findings_raw:
        with SessionLocal() as db:
            for f in findings_raw:
                pkg_name, cve_id = f.get("package"), f.get("cve_id")
                pkg_version = known_versions.get(pkg_name) or f.get("package_version")
                if not (pkg_name and pkg_version and cve_id):
                    continue
                existing = db.execute(
                    select(VulnFinding).where(
                        VulnFinding.product == pkg_name, VulnFinding.version == pkg_version,
                        VulnFinding.cve_id == cve_id)
                ).scalar_one_or_none()
                if existing:
                    continue
                db.add(VulnFinding(
                    product=pkg_name, version=pkg_version, queried_at=now, cve_id=cve_id,
                    cvss_score=f.get("cvss_score"), severity=f.get("severity"),
                    summary=f.get("summary"), published=f.get("published"), ref_url=f.get("ref_url"),
                ))
            db.commit()

    with SessionLocal() as db:
        host = db.get(VulnHost, host_id)
        if host:
            host.last_package_audit_at = now
            db.commit()


# ── NVD CVE lookup (deduped + cached) ────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}


def _cve_to_finding(cve) -> Optional[dict]:
    """Convert an nvdlib CVE object (already has getvars() applied by
    nvdlib itself) into our finding-dict shape. Wrapped defensively per-CVE
    by the caller — nvdlib's own getvars() call can itself raise (observed:
    IndexError on an empty `configurations` list, AttributeError if a CVSS
    entry is missing an expected sub-field) for individual malformed CVE
    entries in NVD's dataset, so treat every attribute access as fallible."""
    cve_id = getattr(cve, "id", None)
    if not cve_id:
        return None
    score = severity = None
    for score_attr, sev_attr in (("v31score", "v31severity"), ("v30score", "v30severity"), ("v2score", "v2severity")):
        if hasattr(cve, score_attr):
            score = getattr(cve, score_attr, None)
            severity = getattr(cve, sev_attr, None)
            break
    summary = ""
    try:
        summary = next((d.value for d in cve.descriptions if getattr(d, "lang", "") == "en"), "")
    except Exception:
        pass
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": (severity or "").upper() or None,
        "summary": (summary or "")[:1000],
        "published": getattr(cve, "published", None),
        "ref_url": getattr(cve, "url", None),
    }


def _nvd_query_live_sync(product: str, version: str) -> list:
    """Blocking — run via loop.run_in_executor (nvdlib's HTTP client is
    synchronous, same convention as the SSH/WinRM identity checks in this
    file). Proper CPE-based matching: look up the official CPE for
    `product` via NVD's own CPE dictionary, then query CVEs against that
    CPE — much more accurate than a raw keyword search over CVE
    descriptions (misses CVEs whose description text doesn't happen to
    contain the product/version string verbatim). Falls back to a keyword
    search (the old behavior) only if no CPE could be found, so coverage
    never gets worse than before, only better."""
    import nvdlib
    key = NVD_API_KEY or None

    try:
        candidates = nvdlib.searchCPE(keywordSearch=f"{product} {version}", key=key, limit=20) or []
    except Exception:
        candidates = []

    cpe_name = None
    for c in candidates:
        name = getattr(c, "cpeName", "") or ""
        if version and version.lower() in name.lower():
            cpe_name = name
            break
    if not cpe_name and candidates:
        cpe_name = getattr(candidates[0], "cpeName", None)

    cves = []
    if cpe_name:
        try:
            cves = nvdlib.searchCVE(cpeName=cpe_name, key=key, limit=50) or []
        except Exception:
            cves = []

    if not cves:
        try:
            cves = nvdlib.searchCVE(keywordSearch=f"{product} {version}", key=key, limit=20) or []
        except Exception:
            cves = []

    findings = []
    for cve in cves:
        try:
            f = _cve_to_finding(cve)
        except Exception:
            continue
        if f:
            findings.append(f)
    return findings


async def _nvd_query_live(product: str, version: str) -> list:
    """Live NVD lookup via nvdlib, rate-limited by NVD_MIN_INTERVAL. Never
    raises — any failure just yields no findings for this (product,
    version), the rest of the scan continues normally."""
    global _nvd_last_call
    wait = NVD_MIN_INTERVAL - (time.time() - _nvd_last_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _nvd_last_call = time.time()

    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _nvd_query_live_sync, product, version)
    except Exception as e:
        print(f"[vuln_scan] NVD query failed for {product} {version}: {e}")
        return []


def _cvss_to_severity(score) -> Optional[str]:
    """vulners bulletins don't always carry a categorical severity label —
    derive one from the numeric CVSS score using the standard NVD bands."""
    if score is None:
        return None
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return None


def _vulners_query_sync(product: str, version: str) -> list:
    """Blocking — run via loop.run_in_executor (the `vulners` package's HTTP
    client is synchronous, same convention as _ssh_identity_sync/
    _winrm_identity_sync above).

    Uses VulnersApi().audit.software(["product version"], match="partial") —
    confirmed (by reading the installed `vulners` 4.x package's own source,
    since this sandbox has no outbound network access to test a live call,
    see module docstring) to be the current, non-deprecated endpoint for
    exactly this "given a product+version, what CVEs affect it" lookup; the
    package's bundled MCP tool docstring documents it as accepting a plain
    "product version" string and returning one result per matched product
    with "a capped list of affecting vulnerabilities". That vulnerability
    list is described in the package's own code as "provider-shaped" (i.e.
    not a fixed, typed schema), so the field names below are best-effort
    guesses across the common ones seen elsewhere in this same package
    (id/cvss/description/href) — every item is parsed in its own try/except
    so one unexpected shape just drops that entry rather than breaking the
    whole source. MUST be confirmed against a real API key + live response
    on the user's actual agent before relying on it."""
    import vulners
    api = vulners.VulnersApi(api_key=VULNERS_API_KEY)
    try:
        results = api.audit.software([f"{product} {version}"], match="partial") or []
    except Exception:
        return []

    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        vulns = (result.get("vulnerabilities") or result.get("cves")
                 or result.get("bulletins") or [])
        for v in vulns:
            if not isinstance(v, dict):
                continue
            try:
                cve_id = v.get("id") or v.get("cve_id") or v.get("cveId")
                if not cve_id:
                    continue
                cvss = v.get("cvss") or v.get("cvss3") or v.get("cvss2") or {}
                score = cvss.get("score") if isinstance(cvss, dict) else None
                if score is None:
                    score = v.get("cvss_score") or v.get("score")
                severity = (cvss.get("severity") if isinstance(cvss, dict) else None) \
                    or _cvss_to_severity(score)
                findings.append({
                    "cve_id": cve_id, "cvss_score": score, "severity": severity,
                    "summary": (v.get("description") or v.get("summary") or v.get("title") or "")[:1000],
                    "published": v.get("published"),
                    "ref_url": v.get("href") or v.get("url") or v.get("ref_url"),
                })
            except Exception:
                continue
    return findings


async def _vulners_query(product: str, version: str) -> list:
    """Live vulners.com lookup — proper CPE-based CVE matching, more accurate
    than NVD's keywordSearch alone. Opt-in (skipped entirely if no API key is
    configured) and never raises: a failure here just means this source
    contributes nothing, NVD's results (or an empty list) still apply."""
    if not VULNERS_API_KEY:
        return []
    global _vulners_last_call
    wait = VULNERS_MIN_INTERVAL - (time.time() - _vulners_last_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _vulners_last_call = time.time()
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _vulners_query_sync, product, version)
    except Exception as e:
        print(f"[vuln_scan] vulners query failed for {product} {version}: {e}")
        return []


async def _get_findings_for(db, product: str, version: str) -> list:
    """DB-cached CVE lookup — re-queries only if the cache entry is missing
    or older than NVD_CACHE_DAYS. Merges NVD (always-on baseline) with
    vulners.com (optional, only when MIKROTIK_VULNERS_API_KEY is set) — the
    same CVE surfacing from both sources collapses into one row via the
    (product, version, cve_id) unique constraint."""
    cutoff = datetime.utcnow() - timedelta(days=NVD_CACHE_DAYS)
    cached = db.execute(
        select(VulnFinding)
        .where(VulnFinding.product == product, VulnFinding.version == version)
        .where(VulnFinding.queried_at >= cutoff)
    ).scalars().all()
    if cached:
        return cached

    live = await _nvd_query_live(product, version)
    if VULNERS_API_KEY:
        try:
            live = live + await _vulners_query(product, version)
        except Exception as e:
            print(f"[vuln_scan] vulners lookup error for {product} {version}: {e}")

    # Clear stale rows for this pair, insert fresh ones (even if empty —
    # an empty result is itself worth caching so we don't re-query a clean
    # version every week).
    db.execute(delete(VulnFinding).where(
        VulnFinding.product == product, VulnFinding.version == version))
    now = datetime.utcnow()
    rows = []
    seen_cve_ids = set()
    for f in live:
        if f["cve_id"] in seen_cve_ids:
            continue
        seen_cve_ids.add(f["cve_id"])
        row = VulnFinding(
            product=product, version=version, queried_at=now,
            cve_id=f["cve_id"], cvss_score=f["cvss_score"], severity=f["severity"],
            summary=f["summary"], published=f["published"], ref_url=f["ref_url"],
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return rows


def _finding_brief(f: VulnFinding) -> dict:
    return {"cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
            "summary": f.summary, "ref_url": f.ref_url}


async def hosts_with_findings() -> list:
    """Compact, phone/central-viewer-friendly summary: only hosts or known
    devices that CURRENTLY have at least one matching CVE finding, grouped
    by ip with the finding list beneath — hosts with zero matches are
    omitted entirely (unlike /api/vuln/findings, which lists every finding
    regardless of grouping). Reuses the exact same (product, version)
    match-against-current-state logic as GET /api/vuln/findings in
    api/vuln_scan.py, just grouped by host instead of by finding."""
    with SessionLocal() as db:
        findings = db.execute(select(VulnFinding)).scalars().all()
        services = db.execute(select(VulnService)).scalars().all()
        packages = db.execute(select(VulnPackage)).scalars().all()
        hosts = {h.id: h for h in db.execute(select(VulnHost)).scalars().all()}
        devices = db.execute(select(Device)).scalars().all()

        findings_by_pv: dict = {}
        for f in findings:
            findings_by_pv.setdefault((f.product, f.version), []).append(f)

        by_ip: dict = {}
        for s in services:
            if not (s.product and s.version):
                continue
            host = hosts.get(s.host_id)
            if not host:
                continue
            matches = findings_by_pv.get((s.product, s.version))
            if not matches:
                continue
            entry = by_ip.setdefault(host.ip, {"ip": host.ip, "device_name": None, "findings": []})
            entry["findings"].extend(_finding_brief(f) for f in matches)

        for p in packages:
            host = hosts.get(p.host_id)
            if not host:
                continue
            matches = findings_by_pv.get((p.name, p.version))
            if not matches:
                continue
            entry = by_ip.setdefault(host.ip, {"ip": host.ip, "device_name": None, "findings": []})
            entry["findings"].extend(_finding_brief(f) for f in matches)

        for d in devices:
            if not d.ros_version:
                continue
            product = "MikroTik RouterOS" if d.vendor == "mikrotik" else f"{d.vendor} {d.model or ''}".strip()
            matches = findings_by_pv.get((product, d.ros_version))
            if not matches:
                continue
            entry = by_ip.setdefault(d.ip, {"ip": d.ip, "device_name": d.identity or d.name, "findings": []})
            entry["findings"].extend(_finding_brief(f) for f in matches)

        out = list(by_ip.values())
        for entry in out:
            seen_cve_ids = set()
            deduped = []
            for fnd in entry["findings"]:
                if fnd["cve_id"] in seen_cve_ids:
                    continue
                seen_cve_ids.add(fnd["cve_id"])
                deduped.append(fnd)
            deduped.sort(key=lambda x: (_SEVERITY_ORDER.get(x["severity"], 4), -(x["cvss_score"] or 0)))
            entry["findings"] = deduped
        out.sort(key=lambda e: [int(p) for p in e["ip"].split(".")])
        return out


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
        known_device_ips: frozenset = frozenset()
        with SessionLocal() as db:
            all_devices = db.execute(select(Device)).scalars().all()
            known_device_ips = frozenset(d.ip for d in all_devices)
            for d in all_devices:
                pair = _device_version_pair(d)
                if pair:
                    version_pairs.setdefault(pair, []).append((d.ip, None, "device"))

        with SessionLocal() as db:
            ranges = db.execute(select(ScanRange).where(ScanRange.active == True)).scalars().all()
            all_creds = db.execute(select(Credential)).scalars().all()
            existing_hosts = db.execute(select(VulnHost)).scalars().all()
            existing_cred_by_ip = {h.ip: h.credential_id for h in existing_hosts}
            existing_pkg_audit_by_ip = {h.ip: h.last_package_audit_at for h in existing_hosts}
        creds_by_id = {c.id: c for c in all_creds}

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
        auth_by_ip: dict = {}  # ip -> auth_info dict from _auth_augment
        for ip, ports_found in zip(all_ips, results):
            if not ports_found:
                continue
            alive_ips.append(ip)
            alive_results.append(ports_found)
            for port, (kind, banner, product, version) in ports_found.items():
                if product and version:
                    version_pairs.setdefault((product, version), []).append((ip, port, "banner"))
            auth_info = await _auth_augment(ip, ports_found, version_pairs,
                                            existing_cred_by_ip.get(ip), all_creds, known_device_ips)
            if auth_info:
                auth_by_ip[ip] = auth_info

        host_ids = await _persist_services(alive_ips, alive_results)
        await _apply_credentials({ip: info["cred_id"] for ip, info in auth_by_ip.items()})
        await _prune_dead_hosts(all_ips, set(alive_ips))

        # Deeper, opt-in full package/software audit — only for hosts where
        # a credential just worked, gated per-host by PACKAGE_AUDIT_DAYS
        # inside _package_audit itself (see that function's docstring).
        for ip, auth_info in auth_by_ip.items():
            host_id = host_ids.get(ip)
            cred = creds_by_id.get(auth_info["cred_id"])
            if not (host_id and cred):
                continue
            try:
                await _package_audit(ip, cred, auth_info, host_id, existing_pkg_audit_by_ip.get(ip))
            except Exception as e:
                print(f"[vuln_scan] package audit error for {ip}: {e}")

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
        last_pkg_audit_at = existing_host.last_package_audit_at if existing_host else None

    for port, (kind, banner, product, version) in ports_found.items():
        if product and version:
            version_pairs.setdefault((product, version), []).append((ip, port, "banner"))

    known_device_ips = frozenset([ip]) if device else frozenset()
    if ports_found:
        auth_info = await _auth_augment(ip, ports_found, version_pairs, remembered_cred_id, all_creds, known_device_ips)
        host_ids = await _persist_services([ip], [ports_found])
        if auth_info:
            await _apply_credentials({ip: auth_info["cred_id"]})
            host_id = host_ids.get(ip)
            cred = next((c for c in all_creds if c.id == auth_info["cred_id"]), None)
            if host_id and cred:
                try:
                    await _package_audit(ip, cred, auth_info, host_id, last_pkg_audit_at)
                except Exception as e:
                    print(f"[vuln_scan] package audit error for {ip}: {e}")
    else:
        await _prune_dead_hosts([ip], set())

    findings_count = await _lookup_findings(version_pairs)
    return {"ip": ip, "alive": bool(ports_found), "unique_versions": len(version_pairs),
            "findings_count": findings_count}
