"""
A remediation plan for one asset, as a Markdown document an administrator can read, edit, put into a ticket or hand to a client (idea: RedAudit's per-host playbooks).

It is built only from what the agent already knows about the asset: the open vulnerability findings of the last scan (worst and actively exploited ones first - CISA KEV, EPSS),
the support status of its operating system, the TLS findings of its services, and the exceptions someone already decided on (accepted / mitigated). For every
product it says what to do and gives the commands for the common cases. It does NOT invent fixes: where the data has no fixed version the plan says "update to the latest
supported release and check the advisory", and the commands are templates to check, not a script to run blindly. Polish and English.
"""
import json
import re
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select

from models.database import SessionLocal, TlsCheck

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
OPEN = ("open", "in_progress")

TEXT = {
    "pl": {
        "title": "Plan naprawy", "generated": "Wygenerowano {when} przez MikroManager z danych ostatniego skanu ({scan}).",
        "disclaimer": "To lista kontrolna, nie dowód i nie skrypt: sprawdź każdy punkt przed zmianą, zrób kopię i wybierz okno serwisowe.",
        "meta": "Dane zasobu", "address": "Adres", "type": "Typ", "os": "System", "model": "Producent / model", "scan": "Poziom skanu", "never": "brak skanu",
        "summary": "Podsumowanie", "sum_line": "Otwarte podatności: **{total}** (krytyczne {critical}, wysokie {high}, średnie {medium}, niskie {low}); aktywnie wykorzystywane (CISA KEV): **{kev}**.",
        "none": "Brak otwartych podatności w ostatnim skanie.", "kev_h": "1. Najpilniejsze: aktywnie wykorzystywane w atakach (CISA KEV)",
        "kev_note": "Te podatności są wykorzystywane w prawdziwych atakach. Naprawiaj je pierwsze, niezależnie od oceny CVSS.",
        "os_h": "2. System operacyjny", "os_eol": "Producent zakończył wsparcie dla **{product}** ({eol}). Nowe poprawki nie powstają: zaplanuj migrację lub aktualizację do wspieranej wersji; do czasu migracji odizoluj host (segment sieci, zapora).",
        "os_ending": "Wsparcie dla **{product}** kończy się {eol} (za {days} dni). Zaplanuj aktualizację do wspieranej wersji.",
        "prod_h": "3. Podatności według produktu", "fix": "Co zrobić", "cmds": "Komendy (szablon do sprawdzenia)", "cve": "CVE", "cvss": "CVSS", "epss": "EPSS", "kev": "KEV", "desc": "Opis",
        "highest": "najwyższa", "count": "{n} CVE", "yes": "tak",
        "act_windows": "Zainstaluj aktualizacje systemu Windows (w tym opcjonalne dla tego produktu) i uruchom ponownie. Po restarcie sprawdź, czy poprawka figuruje w historii aktualizacji.",
        "act_linux": "Zaktualizuj pakiet z repozytorium dystrybucji (poprawki bezpieczeństwa są tam przenoszone też do starszych wersji — numer wersji produktu może się nie zmienić, więc sprawdź dziennik zmian pakietu pod kątem CVE).",
        "act_ros": "Zaktualizuj RouterOS do aktualnego wydania z kanału „long-term” albo „stable”, a potem firmware routerboard. Zrób kopię konfiguracji przed aktualizacją.",
        "act_cisco": "Pobierz wydanie firmware wskazane w biuletynie bezpieczeństwa producenta (wymaga konta na stronie producenta), zrób kopię konfiguracji i zaktualizuj w oknie serwisowym.",
        "act_generic": "Zaktualizuj **{product}** do najnowszego wspieranego wydania i sprawdź biuletyn producenta pod kątem wymaganej wersji naprawiającej (dane skanu jej nie zawierają). Jeśli aktualizacja nie jest możliwa: ogranicz dostęp do usługi zaporą lub wyłącz ją, gdy nie jest potrzebna.",
        "tls_h": "4. Certyfikaty i protokoły TLS", "tls_none": "Brak ustaleń TLS.", "port": "Port",
        "tls_expired": "Certyfikat wygasł: wystaw nowy (CA wewnętrzna lub publiczna), zainstaluj go w usłudze i sprawdź cały łańcuch.", "tls_expiring": "Certyfikat wygasa wkrótce ({msg}): odnów go przed terminem i dodaj przypomnienie.",
        "tls_self_signed": "Certyfikat samopodpisany: dla usług używanych przez ludzi zastąp go certyfikatem z zaufanej CA; dla urządzeń zapisz wyjątek w dokumentacji.",
        "tls_weak_key": "Słaby klucz ({msg}): wygeneruj nowy klucz RSA co najmniej 2048 bitów lub ECDSA P-256 i wystaw certyfikat ponownie.",
        "tls_weak_signature": "Słaby podpis ({msg}): wystaw certyfikat ponownie z podpisem SHA-256 lub lepszym.",
        "tls_legacy_protocol": "Usługa przyjmuje stare protokoły ({msg}): ustaw minimum TLS 1.2.",
        "tls_cmds": "Przykłady ustawienia minimum TLS 1.2 (sprawdź dla swojej wersji)",
        "exc_h": "5. Wyjątki i prace w toku", "exc_note": "Te podatności ktoś już oznaczył (zaakceptowane / złagodzone / w toku). Przejrzyj, czy uzasadnienie nadal jest aktualne.", "status": "Status", "note": "Notatka",
        "verify_h": "Weryfikacja po naprawie", "v1": "Uruchom ponowny skan hosta w MikroManagerze (Podatności / Zasoby → Skanuj) i sprawdź, że pozycje zniknęły.",
        "v2": "Zamknij powiązane alerty w SOC.", "v3": "Zapisz zmianę (kto, kiedy, co) w rejestrze zmian lub zgłoszeniu.", "v4": "Jeśli podatność zostaje świadomie, oznacz ją jako „zaakceptowana” z uzasadnieniem i datą przeglądu.",
        "unknown": "nieznany",
    },
    "en": {
        "title": "Remediation plan", "generated": "Generated {when} by MikroManager from the data of the last scan ({scan}).",
        "disclaimer": "This is a checklist, not proof and not a script: check every item before changing anything, take a backup and pick a maintenance window.",
        "meta": "Asset", "address": "Address", "type": "Type", "os": "System", "model": "Manufacturer / model", "scan": "Scan level", "never": "never scanned",
        "summary": "Summary", "sum_line": "Open vulnerabilities: **{total}** (critical {critical}, high {high}, medium {medium}, low {low}); actively exploited (CISA KEV): **{kev}**.",
        "none": "No open vulnerabilities in the last scan.", "kev_h": "1. Most urgent: actively exploited in attacks (CISA KEV)",
        "kev_note": "These vulnerabilities are being used in real attacks. Fix them first, whatever their CVSS score says.",
        "os_h": "2. Operating system", "os_eol": "The vendor has ended support for **{product}** ({eol}). No new fixes are made: plan a migration or an upgrade to a supported version; until then isolate the host (network segment, firewall).",
        "os_ending": "Support for **{product}** ends on {eol} (in {days} days). Plan an upgrade to a supported version.",
        "prod_h": "3. Vulnerabilities by product", "fix": "What to do", "cmds": "Commands (a template to check)", "cve": "CVE", "cvss": "CVSS", "epss": "EPSS", "kev": "KEV", "desc": "Description",
        "highest": "highest", "count": "{n} CVE", "yes": "yes",
        "act_windows": "Install the Windows updates (including the optional ones for this product) and restart. After the restart check that the fix appears in the update history.",
        "act_linux": "Update the package from the distribution's repository (security fixes are back-ported there, so the product's version number may not change - check the package changelog for the CVE).",
        "act_ros": "Update RouterOS to the current release of the long-term or stable channel, then the routerboard firmware. Back up the configuration first.",
        "act_cisco": "Download the firmware release named in the vendor's security advisory (needs a vendor account), back up the configuration and update in a maintenance window.",
        "act_generic": "Update **{product}** to the latest supported release and check the vendor advisory for the fixed version (the scan data does not carry it). If updating is not possible: restrict access to the service with the firewall, or turn it off when it is not needed.",
        "tls_h": "4. TLS certificates and protocols", "tls_none": "No TLS findings.", "port": "Port",
        "tls_expired": "The certificate has expired: issue a new one (internal or public CA), install it in the service and check the whole chain.", "tls_expiring": "The certificate expires soon ({msg}): renew it before the deadline and add a reminder.",
        "tls_self_signed": "Self-signed certificate: for services people use, replace it with one from a trusted CA; for devices, record the exception in the documentation.",
        "tls_weak_key": "Weak key ({msg}): generate a new RSA key of at least 2048 bits or ECDSA P-256 and re-issue the certificate.",
        "tls_weak_signature": "Weak signature ({msg}): re-issue the certificate with a SHA-256 or better signature.",
        "tls_legacy_protocol": "The service accepts old protocols ({msg}): set the minimum to TLS 1.2.",
        "tls_cmds": "Examples of setting the minimum to TLS 1.2 (check for your version)",
        "exc_h": "5. Exceptions and work in progress", "exc_note": "Someone has already marked these (accepted / mitigated / in progress). Check that the reasoning still holds.", "status": "Status", "note": "Note",
        "verify_h": "Verification after the fix", "v1": "Run a new scan of the host in MikroManager (Vulnerabilities / Assets -> Scan) and check that the items are gone.",
        "v2": "Close the related alerts in the SOC.", "v3": "Record the change (who, when, what) in the change log or the ticket.", "v4": "If a vulnerability stays on purpose, mark it \"accepted\" with the reason and a review date.",
        "unknown": "unknown",
    },
}

TLS_CMDS = """```
# nginx
ssl_protocols TLSv1.2 TLSv1.3;
# Apache httpd
SSLProtocol -all +TLSv1.2 +TLSv1.3
# MikroTik RouterOS (web over TLS)
/ip service set www-ssl tls-version=only-1.2
# Windows (SCHANNEL): disable TLS 1.0 / 1.1 under
# HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols (Enabled=0, DisabledByDefault=1), then restart
```"""


def product_class(product: str, os_name: Optional[str], asset_type: Optional[str]) -> str:
    p = (product or "").lower()
    o = (os_name or "").lower()
    if "routeros" in p or "mikrotik" in p:
        return "ros"
    if "cisco" in p or "ios" == p:
        return "cisco"
    if any(k in p for k in ("windows", "microsoft", ".net", "iis", "exchange", "office", "smb", "rdp", "remote desktop")):
        return "windows"
    if any(k in p for k in ("openssh", "openssl", "apache", "nginx", "httpd", "mysql", "mariadb", "postgres", "samba", "bind", "curl", "dropbear", "sudo", "kernel", "php", "proftpd", "vsftpd", "exim", "postfix", "dovecot")) or "linux" in o:
        return "linux"
    return "generic"


def commands(cls: str, product: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._+-]", "", (product or "").split()[0] if product else "") or "<package>"
    if cls == "windows":
        return ("```powershell\n# the pending updates (needs the PSWindowsUpdate module)\nGet-WindowsUpdate\nInstall-WindowsUpdate -AcceptAll -AutoReboot\n"
                "# or: Settings -> Windows Update -> Check for updates; WSUS / Endpoint Central if you use them\n```")
    if cls == "linux":
        return (f"```bash\n# Debian / Ubuntu\nsudo apt update && apt list --upgradable | grep -i {safe}\nsudo apt upgrade   # or: sudo apt install --only-upgrade <package>\n"
                f"# RHEL / Rocky / Alma / Fedora\nsudo dnf check-update | grep -i {safe}\nsudo dnf upgrade --refresh\n# then check the running service uses the new binary\nsudo needs-restarting -r || sudo systemctl restart <service>\n```")
    if cls == "ros":
        return "```\n/system package update check-for-updates\n/system package update install     # reboots the router\n/system routerboard upgrade         # then reboot once more\n/export file=before-update          # BEFORE the update\n```"
    return ""


def render(asset: dict, findings: List[dict], tls_rows: List[dict], lang: str = "pl", now: Optional[datetime] = None) -> str:
    """The Markdown. `asset` is the dict of services.assets.get_asset; `findings` the dicts of vuln_scan._finding_brief; `tls_rows` {port, findings:[{code,message}]}."""
    T = TEXT.get(lang) or TEXT["en"]
    now = now or datetime.utcnow()
    name = asset.get("name") or asset.get("ip") or f"#{asset.get('id')}"
    open_f = [f for f in findings if (f.get("status") or "open") in OPEN]
    other = [f for f in findings if (f.get("status") or "open") not in OPEN]
    counts = {k: 0 for k in ("critical", "high", "medium", "low")}
    for f in open_f:
        sev = (f.get("severity") or "LOW").lower()
        counts[sev if sev in counts else "low"] += 1
    kev = [f for f in open_f if f.get("kev")]
    scan = asset.get("scan") or {}
    last_scan = scan.get("last_scan_at") or T["never"]
    out: List[str] = [f"# {T['title']}: {name}", "", f"> {T['generated'].format(when=now.strftime('%Y-%m-%d %H:%M UTC'), scan=last_scan)}", f"> {T['disclaimer']}", "",
                      f"## {T['meta']}", "", f"| | |", "|---|---|", f"| {T['address']} | {asset.get('ip') or '-'} |", f"| {T['type']} | {asset.get('type') or '-'} |",
                      f"| {T['os']} | {' '.join(x for x in (asset.get('os_name'), asset.get('os_version')) if x) or T['unknown']} |",
                      f"| {T['model']} | {' '.join(x for x in (asset.get('manufacturer'), asset.get('model')) if x) or '-'} |", f"| {T['scan']} | {scan.get('level') or asset.get('scan_level') or '-'} |", "",
                      f"## {T['summary']}", ""]
    if open_f:
        out.append(T["sum_line"].format(total=len(open_f), kev=len(kev), **counts))
    else:
        out.append(T["none"])
    out.append("")

    def table(rows: List[dict]) -> List[str]:
        t = [f"| {T['cve']} | {T['cvss']} | {T['epss']} | {T['kev']} | {T['desc']} |", "|---|---|---|---|---|"]
        for f in rows:
            cve = f"[{f['cve_id']}]({f['ref_url']})" if f.get("ref_url") else f["cve_id"]
            epss = f"{float(f['epss']) * 100:.1f}%" if f.get("epss") is not None else "-"
            summ = re.sub(r"\s+", " ", (f.get("summary") or "")).replace("|", "/")[:160]
            t.append(f"| {cve} | {f.get('cvss_score') if f.get('cvss_score') is not None else '-'} | {epss} | {T['yes'] if f.get('kev') else ''} | {summ} |")
        return t + [""]

    def order(f: dict):
        return (0 if f.get("kev") else 1, SEV_ORDER.get((f.get("severity") or "LOW").upper(), 4), -(f.get("cvss_score") or 0))

    if kev:
        out += [f"## {T['kev_h']}", "", T["kev_note"], ""] + table(sorted(kev, key=order))
    lc = asset.get("lifecycle_detail") or {}
    if lc.get("status") in ("eol", "ending") and lc.get("product"):
        out += [f"## {T['os_h']}", "", (T["os_eol"] if lc["status"] == "eol" else T["os_ending"]).format(product=lc["product"], eol=lc.get("eol"), days=lc.get("days_left")), ""]
    if open_f:
        out += [f"## {T['prod_h']}", ""]
        groups: dict = {}
        for f in open_f:
            groups.setdefault((f.get("product") or T["unknown"], f.get("version") or ""), []).append(f)
        for (product, version), rows in sorted(groups.items(), key=lambda kv: min(order(f) for f in kv[1])):
            worst = min(rows, key=order)
            cls = product_class(product, asset.get("os_name"), asset.get("type"))
            act = {"windows": "act_windows", "linux": "act_linux", "ros": "act_ros", "cisco": "act_cisco"}.get(cls, "act_generic")
            sev = f"{(worst.get('severity') or '?').upper()} {worst.get('cvss_score') or ''}".strip()
            out += [f"### {product} {version}".strip() + f" - {T['count'].format(n=len(rows))} ({T['highest']}: {sev})", "", f"**{T['fix']}:** {T[act].format(product=product)}", ""]
            cmd = commands(cls, product)
            if cmd:
                out += [f"**{T['cmds']}:**", "", cmd, ""]
            out += table(sorted(rows, key=order))
    bad_tls = [r for r in tls_rows if r["findings"]]
    out += [f"## {T['tls_h']}", ""]
    if not bad_tls:
        out += [T["tls_none"], ""]
    else:
        for r in bad_tls:
            out.append(f"- **{T['port']} {r['port']}**")
            for f in r["findings"]:
                out.append(f"  - {T['tls_' + f['code']].format(msg=f.get('message', ''))}")
        out += ["", f"**{T['tls_cmds']}:**", "", TLS_CMDS, ""]
    if other:
        out += [f"## {T['exc_h']}", "", T["exc_note"], "", f"| {T['cve']} | {T['status']} | {T['note']} |", "|---|---|---|"]
        for f in sorted(other, key=order):
            out.append(f"| {f['cve_id']} ({f.get('product') or ''} {f.get('version') or ''}) | {f.get('status')} | {(f.get('note') or '').replace('|', '/')[:200]} |")
        out.append("")
    out += [f"## {T['verify_h']}", "", f"- [ ] {T['v1']}", f"- [ ] {T['v2']}", f"- [ ] {T['v3']}", f"- [ ] {T['v4']}", ""]
    return "\n".join(out)


def _tls_for(ip: Optional[str]) -> List[dict]:
    if not ip:
        return []
    with SessionLocal() as db:
        rows = db.execute(select(TlsCheck).where(TlsCheck.ip == ip).order_by(TlsCheck.port)).scalars().all()
        res = []
        for r in rows:
            try:
                fs = [f for f in json.loads(r.findings or "[]") if f.get("code") in ("expired", "expiring", "self_signed", "weak_key", "weak_signature", "legacy_protocol")]
            except Exception:
                fs = []
            res.append({"port": r.port, "findings": fs})
        return res


async def build(asset_id: int, lang: str = "pl") -> Optional[dict]:
    """{"filename", "markdown"} for the asset, or None when it does not exist."""
    from services import assets
    a = await assets.get_asset(asset_id)
    if a is None:
        return None
    findings = await assets.asset_vulnerabilities(asset_id) or []
    md = render(a, findings, _tls_for(a.get("ip")), lang)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", (a.get("name") or a.get("ip") or f"asset-{asset_id}")).strip("-")[:60] or f"asset-{asset_id}"
    return {"filename": f"plan-naprawy-{slug}.md" if lang == "pl" else f"remediation-plan-{slug}.md", "markdown": md}
