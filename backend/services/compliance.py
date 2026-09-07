"""
Configuration-hardening ("compliance") checks — read-only pass/fail
checks against Linux/Windows/RouterOS targets this agent already knows
about (managed LinuxHost/WindowsHost, known Device). This is NOT
vulnerability scanning (no CVE involved anywhere here) — it answers "is
this configured safely", the same category of thing OpenVAS's policy/
compliance scans do. Deliberately a SMALL, easy-to-extend starting set
(5-8 checks per platform) rather than a full CIS benchmark — every
check is plain data (id/title/severity + how to run it and how to read
the result), so adding more later is just appending to a list.

Best-effort, not a guarantee: most checks pattern-match a command's
text output rather than tracking a real exit code (the SSH/WinRM exec
helpers reused here — linux_manage._plain_exec_sync, windows_manage.
_run_script_sync — don't uniformly expose one either). A wrong reading
here is a wrong hardening SUGGESTION, not a false vulnerability report,
so this trades a little precision for reusing what's already built
rather than adding a parallel, exit-code-aware exec path. The one
check that reads a genuinely sensitive file (Linux empty-password
accounts) is written so an unreadable/failed command can never be
silently misread as "compliant" — see its check() below.
"""
import asyncio
import os
import re
from datetime import datetime
from typing import Optional
from sqlalchemy import select

from models.database import SessionLocal, LinuxHost, WindowsHost, Device, Credential, ComplianceCheckResult
from services.crypto import decrypt
from services import linux_manage
from services import windows_manage
from services import vuln_scan as vs

COMPLIANCE_CHECK_DAYS = int(os.environ.get("MIKROTIK_COMPLIANCE_CHECK_DAYS", "7"))
_CHECK_TIMEOUT_SEC = 15


# ── Check catalogs (data, not code — extend by appending a dict) ────────────

LINUX_CHECKS = [
    {"id": "linux.ssh_root_login_disabled", "title": "SSH: logowanie root wyłączone", "severity": "high",
     "cmd": "sudo -n sshd -T 2>/dev/null | grep -i '^permitrootlogin' || grep -Ei '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
     "check": lambda out: bool(out.strip()) and "yes" not in out.lower()},
    {"id": "linux.ssh_password_auth_disabled", "title": "SSH: logowanie hasłem wyłączone (tylko klucze)", "severity": "medium",
     "cmd": "sudo -n sshd -T 2>/dev/null | grep -i '^passwordauthentication' || grep -Ei '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null",
     "check": lambda out: bool(out.strip()) and "yes" not in out.lower()},
    {"id": "linux.firewall_active", "title": "Firewall aktywny", "severity": "high",
     "cmd": "(systemctl is-active ufw firewalld nftables 2>/dev/null; ufw status 2>/dev/null) | tr '\\n' ' '",
     # \b word boundary, not a plain substring check — "inactive" contains
     # "active" as a substring and would otherwise register as a false pass.
     "check": lambda out: bool(re.search(r"\bactive\b", out.lower()))},
    {"id": "linux.unattended_upgrades_enabled", "title": "Automatyczne aktualizacje bezpieczeństwa włączone", "severity": "medium",
     "cmd": "systemctl is-enabled unattended-upgrades 2>/dev/null; dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii' && echo installed",
     "check": lambda out: "enabled" in out.lower() or "installed" in out.lower()},
    {"id": "linux.no_empty_passwords", "title": "Brak kont z pustym hasłem", "severity": "high",
     # Always prints an explicit "COUNT:N" marker on success (even N=0) —
     # deliberately NOT relying on "empty output = pass", since that would
     # silently misread "sudo denied" or "couldn't read /etc/shadow" as
     # "no empty-password accounts found", which is the one wrong-direction
     # mistake this module can't afford for a check like this.
     "cmd": "sudo -n awk -F: '{if ($2==\"\") c++} END{print \"COUNT:\" (c+0)}' /etc/shadow 2>/dev/null",
     "check": lambda out: (out.count("COUNT:0") > 0) if "COUNT:" in out else None},
]

WINDOWS_CHECKS = [
    {"id": "windows.smb1_disabled", "title": "SMBv1 wyłączony", "severity": "high",
     "ps": "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State",
     "check": lambda out: "disabled" in out.lower()},
    {"id": "windows.defender_enabled", "title": "Windows Defender aktywny", "severity": "high",
     "ps": "(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled",
     "check": lambda out: "true" in out.lower()},
    {"id": "windows.guest_disabled", "title": "Konto Gościa wyłączone", "severity": "medium",
     "ps": "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled",
     # Deliberately NOT treating empty output as a pass (an absent/errored
     # result must never read as "disabled") — same reasoning as the Linux
     # empty-password check above.
     "check": lambda out: "false" in out.lower()},
    {"id": "windows.firewall_all_profiles_enabled", "title": "Zapora systemowa aktywna (wszystkie profile)", "severity": "high",
     "ps": "(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled) -join ','",
     "check": lambda out: bool(out.strip()) and all(v.strip().lower() in ("true", "1") for v in out.split(","))},
    {"id": "windows.rdp_nla_required", "title": "RDP wymaga uwierzytelniania na poziomie sieci (NLA)", "severity": "medium",
     "ps": "(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root/cimv2/terminalservices "
           "-Filter \"TerminalName='RDP-tcp'\" -ErrorAction SilentlyContinue).UserAuthenticationRequired",
     # Exact-match the stripped output ("0" or "1") rather than a
     # substring "in" check — same false-positive risk class as the
     # firewall_active fix above.
     "check": lambda out: out.strip() == "1"},
]


def _service_disabled(rows: list, name: str) -> Optional[bool]:
    """None = the service wasn't even listed (older RouterOS/unexpected
    output shape) — treated as indeterminate, never a silent pass."""
    if not isinstance(rows, list):
        return None
    for r in rows:
        if isinstance(r, dict) and r.get("name") == name:
            return str(r.get("disabled", "")).lower() in ("true", "yes")
    return None


def _snmp_not_public(rows: list) -> Optional[bool]:
    if not isinstance(rows, list):
        return None
    if not rows:
        return None  # no communities configured at all — can't tell
    for r in rows:
        if isinstance(r, dict) and (r.get("name") or "").lower() == "public":
            return False
    return True


MIKROTIK_CHECKS = [
    {"id": "mikrotik.telnet_disabled", "title": "Telnet wyłączony", "severity": "high",
     "path": "/ip/service", "check": lambda rows: _service_disabled(rows, "telnet")},
    {"id": "mikrotik.ftp_disabled", "title": "FTP wyłączony", "severity": "high",
     "path": "/ip/service", "check": lambda rows: _service_disabled(rows, "ftp")},
    {"id": "mikrotik.www_disabled", "title": "Zwykłe HTTP (www) wyłączone", "severity": "medium",
     "path": "/ip/service", "check": lambda rows: _service_disabled(rows, "www")},
    {"id": "mikrotik.snmp_not_default_community", "title": "Community SNMP inna niż domyślne \"public\"", "severity": "medium",
     "path": "/snmp/community", "check": lambda rows: _snmp_not_public(rows)},
]


# ── RouterOS firewall-rule recommendations ──────────────────────────────
# Distinct from MIKROTIK_CHECKS above: those are one-line "is flag X set"
# checks against a single endpoint. These need chain=input/forward AND NAT
# rules read together and reasoned about, so they're plain functions
# instead of one-liner lambdas — same {"passed","detail"} shape, but
# "detail" here is a real, actionable recommendation, not just an echo of
# raw output (this is what the user asked for directly: "what standard
# practice looks like, and what would be needed to get there" for an
# actual rule they have, not just a pass/fail flag).
#
# Best-effort, same philosophy as the rest of this module: pattern-matches
# rule fields rather than simulating RouterOS's actual packet-matching
# engine (mangle marks, address-lists populated dynamically, VRF, etc. are
# not modeled) — a missed edge case produces an imprecise suggestion, not
# a false vulnerability report.

_MGMT_PORTS = {
    "8291": "Winbox", "8728": "API", "8729": "API-SSL",
    "22": "SSH", "23": "Telnet", "21": "FTP", "80": "WWW", "443": "WWW-SSL",
}


def _rule_active(r) -> bool:
    return isinstance(r, dict) and str(r.get("disabled", "false")).lower() not in ("true", "yes")


def _check_forward_chain_open(filter_rows: list, nat_rows: list) -> tuple:
    """The exact scenario the user described: a NAT rule forwards traffic
    to an internal server. RouterOS's own default with NO forward-chain
    filter rules at all is accept-everything — meaning a dst-nat rule
    alone, with nothing in chain=forward, exposes that server to the WAN
    with zero restriction. Only checks for PRESENCE of forward rules, not
    a port-by-port correlation with each NAT rule (see module docstring)."""
    dst_nats = [r for r in (nat_rows or [])
                if isinstance(r, dict) and r.get("chain") == "dstnat"
                and r.get("action") == "dst-nat" and _rule_active(r)]
    forward_rules = [r for r in (filter_rows or [])
                      if isinstance(r, dict) and r.get("chain") == "forward" and _rule_active(r)]
    if not dst_nats:
        return True, "Brak reguł NAT (port forwarding) na tym urządzeniu — sprawdzenie nie dotyczy."
    if not forward_rules:
        targets = ", ".join(
            f"{r.get('protocol', '?')}/{r.get('dst-port', '?')} -> {r.get('to-addresses', '?')}"
            for r in dst_nats[:5]
        )
        return False, (
            f"Znaleziono {len(dst_nats)} regułę/reguł NAT przekierowujących ruch do sieci wewnętrznej "
            f"({targets}), ale łańcuch forward nie ma ŻADNEJ reguły filtra — cały przekierowany ruch jest "
            f"w pełni otwarty z internetu. Zalecenie (standard rynkowy): dla każdej przekierowanej usługi "
            f"dodaj w chain=forward regułę accept ograniczoną do konkretnego adresu/listy adresów źródłowych "
            f"(src-address-list), a łańcuch forward zakończ jawną regułą drop. Jeśli to dostęp administracyjny "
            f"(np. RDP, SSH) — lepszym rozwiązaniem jest w ogóle nie przekierowywać portu na WAN, tylko "
            f"udostępnić usługę przez tunel WireGuard/IPsec."
        )
    return True, (
        f"{len(dst_nats)} regułę/reguł NAT, {len(forward_rules)} reguł filtra w chain=forward — wykryto samą "
        f"obecność reguł filtra, bez pełnej korelacji port-po-porcie z każdą regułą NAT (do zweryfikowania ręcznie)."
    )


def _check_input_chain_default_drop(filter_rows: list) -> tuple:
    """Standard practice (RouterOS's own default configuration, and CIS-
    style hardening guides generally): chain=input should end with an
    unconditional drop, so anything not explicitly allowed above is
    rejected by default rather than falling through to RouterOS's own
    implicit accept."""
    input_rules = [r for r in (filter_rows or [])
                    if isinstance(r, dict) and r.get("chain") == "input" and _rule_active(r)]
    if not input_rules:
        return None, "Brak (aktywnych) reguł w chain=input — nie można ocenić."
    last = input_rules[-1]
    is_catch_all_drop = (
        last.get("action") in ("drop", "reject")
        and not last.get("src-address") and not last.get("src-address-list")
        and not last.get("dst-port") and not last.get("protocol")
        and not last.get("in-interface") and not last.get("in-interface-list")
    )
    if is_catch_all_drop:
        return True, "Ostatnia reguła w chain=input to bezwarunkowy drop/reject — zgodnie z dobrą praktyką."
    return False, (
        f"Ostatnia reguła w chain=input to action={last.get('action', '?')} i nie jest to bezwarunkowy "
        f"drop. Zalecenie: zakończ łańcuch input jawną regułą 'drop' bez żadnych dodatkowych warunków, "
        f"żeby domyślnie odrzucać ruch niewymieniony wcześniejszymi regułami (domyślna praktyka RouterOS/CIS)."
    )


async def _check_wan_management_exposed(client, filter_rows: list) -> tuple:
    """Reuses the same 'WAN' interface-list signal built for WAN link
    monitoring (services/edge_discovery.py) — the operator's own explicit
    statement of which interface faces the internet, far more reliable
    here than guessing from routing tables."""
    try:
        members = await client.get_interface_list_members()
    except Exception:
        return None, "Nie udało się odczytać listy interfejsów WAN — sprawdzenie pominięte."
    wan_ifaces = {
        str(m.get("interface")) for m in (members or [])
        if isinstance(m, dict) and str(m.get("list", "")).strip().lower() == "wan" and m.get("interface")
    }
    if not wan_ifaces:
        return None, "Urządzenie nie ma zdefiniowanej listy interfejsów 'WAN' — nie można ocenić, które reguły dotyczą ruchu z internetu."

    exposed = set()
    for r in (filter_rows or []):
        if not isinstance(r, dict) or r.get("chain") != "input" or r.get("action") != "accept" or not _rule_active(r):
            continue
        in_iface = str(r.get("in-interface") or "")
        in_iface_list = str(r.get("in-interface-list") or "")
        on_wan = in_iface in wan_ifaces or in_iface_list.strip().lower() == "wan"
        if not on_wan or (r.get("src-address") or r.get("src-address-list")):
            continue
        dst_port = str(r.get("dst-port") or "")
        dst_ports = {p.strip() for p in dst_port.split(",")} if dst_port else set()
        for port, label in _MGMT_PORTS.items():
            if port in dst_ports:
                exposed.add(f"{label} (port {port})")

    if exposed:
        return False, (
            f"Wykryto dostęp do usług zarządzania z sieci WAN bez ograniczenia adresu źródłowego: "
            f"{', '.join(sorted(exposed))}. Zalecenie: ogranicz src-address/src-address-list do konkretnych "
            f"adresów administracyjnych, albo (bezpieczniej) całkowicie wyłącz dostęp do zarządzania z WAN "
            f"i korzystaj z tunelu WireGuard/IPsec."
        )
    return True, "Brak wykrytych reguł dopuszczających zarządzanie z WAN bez ograniczenia adresu źródłowego."


MIKROTIK_FIREWALL_CHECKS = [
    {"id": "mikrotik.forward_chain_not_fully_open",
     "title": "Reguły NAT (port forwarding) mają odpowiadające reguły filtra w chain=forward", "severity": "high"},
    {"id": "mikrotik.input_chain_default_drop",
     "title": "Łańcuch input kończy się jawną regułą drop", "severity": "medium"},
    {"id": "mikrotik.wan_management_restricted",
     "title": "Dostęp do zarządzania z WAN ograniczony adresem źródłowym", "severity": "high"},
]


def _persist_results(target_type: str, target_id: int, results: list) -> None:
    now = datetime.utcnow()
    with SessionLocal() as db:
        for r in results:
            row = db.execute(
                select(ComplianceCheckResult).where(
                    ComplianceCheckResult.target_type == target_type,
                    ComplianceCheckResult.target_id == target_id,
                    ComplianceCheckResult.check_id == r["check_id"],
                )
            ).scalar_one_or_none()
            if not row:
                row = ComplianceCheckResult(target_type=target_type, target_id=target_id, check_id=r["check_id"])
                db.add(row)
            row.title = r["title"]
            row.severity = r["severity"]
            row.passed = r["passed"]
            row.detail = r["detail"]
            row.checked_at = now
        db.commit()


# ── Linux ────────────────────────────────────────────────────────────────

async def run_linux_checks(host_id: int) -> list:
    with SessionLocal() as db:
        host = db.get(LinuxHost, host_id)
        if not host or not host.managed:
            return []
        ip = host.ip

    cred = linux_manage._shared_credential()
    if not cred:
        return []
    username, password = cred

    loop = asyncio.get_event_loop()
    results = []
    for check in LINUX_CHECKS:
        try:
            raw = await loop.run_in_executor(
                vs._EXECUTOR, linux_manage._plain_exec_sync, ip, username, password, check["cmd"], _CHECK_TIMEOUT_SEC)
            output = raw.get("output", "")
            try:
                passed = check["check"](output)
            except Exception:
                passed = None
            detail = output.strip()[:500]
        except Exception as e:
            passed, detail = None, f"błąd: {e}"
        results.append({"check_id": check["id"], "title": check["title"], "severity": check["severity"],
                         "passed": passed, "detail": detail})

    _persist_results("linux", host_id, results)
    with SessionLocal() as db:
        h = db.get(LinuxHost, host_id)
        if h:
            h.last_compliance_check_at = datetime.utcnow()
            db.commit()
    return results


# ── Windows ──────────────────────────────────────────────────────────────

async def run_windows_checks(host_id: int) -> list:
    with SessionLocal() as db:
        host = db.get(WindowsHost, host_id)
        if not host or not host.managed:
            return []
        ip, port = host.ip, host.winrm_port

    cred = windows_manage._shared_credential()
    if not cred:
        return []
    username, password, domain = cred

    loop = asyncio.get_event_loop()
    results = []
    for check in WINDOWS_CHECKS:
        try:
            raw = await loop.run_in_executor(
                vs._EXECUTOR, windows_manage._run_script_sync, ip, port, username, password, domain,
                check["ps"], _CHECK_TIMEOUT_SEC)
            output = raw.get("output", "")
            try:
                passed = check["check"](output)
            except Exception:
                passed = None
            detail = output.strip()[:500]
        except Exception as e:
            passed, detail = None, f"błąd: {e}"
        results.append({"check_id": check["id"], "title": check["title"], "severity": check["severity"],
                         "passed": passed, "detail": detail})

    _persist_results("windows", host_id, results)
    with SessionLocal() as db:
        h = db.get(WindowsHost, host_id)
        if h:
            h.last_compliance_check_at = datetime.utcnow()
            db.commit()
    return results


# ── Mikrotik / RouterOS ──────────────────────────────────────────────────

async def run_mikrotik_checks(device_id: int) -> list:
    with SessionLocal() as db:
        row = db.execute(
            select(Device, Credential)
            .outerjoin(Credential, Device.credential_id == Credential.id)
            .where(Device.id == device_id)
        ).one_or_none()
        if not row:
            return []
        device, cred = row
        if not cred:
            return []
        ip, api_port, web_port = device.ip, device.api_port, device.web_port
        username = cred.username
        try:
            password = decrypt(cred.password_enc)
        except Exception:
            return []

    from services.mikrotik_client import MikrotikClient
    client = MikrotikClient(ip, username, password, api_port=api_port or 8728, web_port=web_port or 80)

    results = []
    for check in MIKROTIK_CHECKS:
        try:
            rows = await client.api_command(check["path"])
            try:
                passed = check["check"](rows)
            except Exception:
                passed = None
            detail = f"{len(rows)} wpisów" if isinstance(rows, list) else str(rows)[:500]
        except Exception as e:
            passed, detail = None, f"błąd: {e}"
        results.append({"check_id": check["id"], "title": check["title"], "severity": check["severity"],
                         "passed": passed, "detail": detail})

    # Firewall-rule recommendations (need filter+NAT correlated together —
    # see MIKROTIK_FIREWALL_CHECKS above for why these aren't simple lambdas).
    try:
        fw = await client.get_firewall_rules()
        filter_rows, nat_rows = fw.get("filter") or [], fw.get("nat") or []
        checks_meta = {c["id"]: c for c in MIKROTIK_FIREWALL_CHECKS}

        passed, detail = _check_forward_chain_open(filter_rows, nat_rows)
        meta = checks_meta["mikrotik.forward_chain_not_fully_open"]
        results.append({"check_id": meta["id"], "title": meta["title"], "severity": meta["severity"],
                         "passed": passed, "detail": detail})

        passed, detail = _check_input_chain_default_drop(filter_rows)
        meta = checks_meta["mikrotik.input_chain_default_drop"]
        results.append({"check_id": meta["id"], "title": meta["title"], "severity": meta["severity"],
                         "passed": passed, "detail": detail})

        passed, detail = await _check_wan_management_exposed(client, filter_rows)
        meta = checks_meta["mikrotik.wan_management_restricted"]
        results.append({"check_id": meta["id"], "title": meta["title"], "severity": meta["severity"],
                         "passed": passed, "detail": detail})
    except Exception as e:
        results.append({"check_id": "mikrotik.firewall_checks_error", "title": "Analiza reguł firewall",
                         "severity": "medium", "passed": None, "detail": f"błąd: {e}"})

    _persist_results("mikrotik", device_id, results)
    return results


# ── Listing ──────────────────────────────────────────────────────────────

def list_results(target_type: Optional[str] = None, target_id: Optional[int] = None) -> list:
    with SessionLocal() as db:
        query = select(ComplianceCheckResult)
        if target_type:
            query = query.where(ComplianceCheckResult.target_type == target_type)
        if target_id is not None:
            query = query.where(ComplianceCheckResult.target_id == target_id)
        rows = db.execute(query).scalars().all()
        return [{
            "id": r.id, "target_type": r.target_type, "target_id": r.target_id,
            "check_id": r.check_id, "title": r.title, "severity": r.severity,
            "passed": r.passed, "detail": r.detail,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None,
        } for r in rows]


def summary() -> list:
    """One row per target with a pass/fail/unknown tally — for a
    dashboard-style overview instead of the full flat check list."""
    with SessionLocal() as db:
        rows = db.execute(select(ComplianceCheckResult)).scalars().all()
        linux_hosts = {h.id: h for h in db.execute(select(LinuxHost)).scalars().all()}
        windows_hosts = {h.id: h for h in db.execute(select(WindowsHost)).scalars().all()}
        devices = {d.id: d for d in db.execute(select(Device)).scalars().all()}

    by_target: dict = {}
    for r in rows:
        key = (r.target_type, r.target_id)
        by_target.setdefault(key, []).append(r)

    out = []
    for (target_type, target_id), checks in by_target.items():
        if target_type == "linux":
            host = linux_hosts.get(target_id)
            label = (host.hostname or host.ip) if host else str(target_id)
        elif target_type == "windows":
            host = windows_hosts.get(target_id)
            label = (host.hostname or host.ip) if host else str(target_id)
        else:
            dev = devices.get(target_id)
            label = (dev.identity or dev.name or dev.ip) if dev else str(target_id)
        passed = sum(1 for c in checks if c.passed is True)
        failed = sum(1 for c in checks if c.passed is False)
        unknown = sum(1 for c in checks if c.passed is None)
        out.append({
            "target_type": target_type, "target_id": target_id, "label": label,
            "passed": passed, "failed": failed, "unknown": unknown, "total": len(checks),
        })
    out.sort(key=lambda x: (-x["failed"], x["label"]))
    return out
