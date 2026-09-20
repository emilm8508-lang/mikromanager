"""
Disaster-recovery documentation for Mikrotik devices — generates a single
Word document containing, for every device NOT marked drp_exclude, the
full plain-text /export of its configuration (see mikrotik_client.py's
get_config_export()) alongside enough identifying detail (model,
RouterOS version, credential NAME — never the password itself) to
actually rebuild it on replacement hardware.

Deliberately Mikrotik-only, per the user's own framing: RouterOS's
/export gives a genuinely restorable script (paste it back in and the
device is reconfigured); no general-purpose OS has an equivalent single
"print my whole config" command, so Linux/Windows hosts would only ever
get a much shallower inventory-level listing, not something worth
calling disaster-recovery documentation. Device.drp_exclude exists for
the opposite, common case the user described: a device whose
configuration is still effectively factory-default (their example — a
switch where only the admin password was ever changed) and isn't worth
a page of near-boilerplate config.

Triggered from Central (see uplink.py's "drp_doc_generate" command) so a
consultant managing several clients doesn't need to open each site's own
agent UI just to pull this. The finished .docx is:
  1. Saved locally under data/drp_exports/ — the on-site copy, available
     even if Central/OVH is unreachable.
  2. Encrypted with the SAME AES-256-GCM envelope services/agent_backup.py
     already uses for full agent-state backups (reusing its
     encrypt_archive() rather than re-implementing it) and uploaded to
     OVH's drp_documents table (ovh/drp.php, mirroring ovh/backup.php)
     for Central to list/download — skipped (not an error) if no enc_key
     is configured, same "never upload unencrypted" rule as backups.
"""
import asyncio
import hashlib
import hmac
import io
import json
import os
import time
from datetime import datetime
from typing import Optional

import aiohttp
from docx import Document
from docx.shared import Pt
from sqlalchemy import select

from models.database import SessionLocal, Device, Credential
from services import activity, uplink
from services.agent_backup import encrypt_archive
from services.crypto import decrypt as decrypt_secret
from services.mikrotik_client import MikrotikClient

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
EXPORT_DIR = os.path.join(_DATA_DIR, "drp_exports")

_state = {
    "last_generated_at": None,
    "last_error": None,
    "last_size_bytes": None,
    "last_local_path": None,
    "last_devices_included": None,
    "last_devices_skipped": None,
    "in_progress": False,
}


def status() -> dict:
    return dict(_state)


async def _collect_device_data(device: Device, cred: Optional[Credential]) -> dict:
    """Best-effort per device — never raises; records what failed so the
    document can note a skipped device explicitly instead of silently
    omitting it (same philosophy as vuln_scan.py's per-host error handling
    throughout this app)."""
    result = {"device": device, "credential_name": None, "export_text": None,
              "neighbors": [], "error": None}
    if not cred:
        result["error"] = "brak przypisanego poświadczenia"
        return result
    result["credential_name"] = cred.name
    try:
        password = decrypt_secret(cred.password_enc)
    except Exception as e:
        result["error"] = f"nie udało się odszyfrować hasła poświadczenia: {e}"
        return result

    client = MikrotikClient(device.ip, cred.username, password,
                             api_port=device.api_port or 8728, web_port=device.web_port or 80,
                             snmp_community=None, snmp_port=device.snmp_port or 161)
    try:
        result["export_text"] = await client.get_config_export(ssh_port=device.ssh_port or 22)
    except Exception as e:
        result["error"] = f"nie udało się pobrać konfiguracji przez SSH: {e}"
        return result
    try:
        result["neighbors"] = await client.get_neighbors()
    except Exception:
        pass  # neighbors are a nice-to-have context, never block the export itself
    return result


def _render_docx(rows: list) -> bytes:
    """Synchronous, CPU-only — safe to call directly (no executor needed,
    unlike the network-bound collection step above)."""
    doc = Document()
    doc.add_heading('Dokumentacja awaryjna sieci (DRP) — urządzenia Mikrotik', level=1)
    doc.add_paragraph(f"Wygenerowano: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    doc.add_paragraph(
        "Ten dokument zawiera pełny eksport konfiguracji (/export) każdego "
        "uwzględnionego urządzenia Mikrotik. W razie awarii skopiuj sekcję "
        "danego urządzenia i wklej ją w terminalu (konsoli) nowego lub "
        "zastępczego urządzenia. Hasła NIE są tu zapisane — użyj "
        "poświadczenia o nazwie wskazanej przy każdym urządzeniu."
    )

    included = [r for r in rows if r["export_text"]]
    skipped = [r for r in rows if not r["export_text"]]

    if skipped:
        doc.add_heading('Pominięte urządzenia', level=2)
        for r in skipped:
            d = r["device"]
            doc.add_paragraph(
                f"{d.identity or d.name or d.ip} ({d.ip}) — {r['error'] or 'nieznany błąd'}",
                style='List Bullet',
            )

    for r in included:
        d = r["device"]
        doc.add_heading(d.identity or d.name or d.ip, level=2)

        table = doc.add_table(rows=0, cols=2)
        table.style = 'Light Grid Accent 1'
        for label, value in [
            ("Adres IP", d.ip),
            ("Model", d.model or "—"),
            ("Płyta", d.board_name or "—"),
            ("RouterOS", d.ros_version or "—"),
            ("Poświadczenie", r["credential_name"] or "—"),
        ]:
            cells = table.add_row().cells
            cells[0].text = label
            cells[1].text = str(value)

        if r["neighbors"]:
            doc.add_paragraph("Sąsiedzi (LLDP/CDP):").bold = True
            for n in r["neighbors"][:20]:
                if not isinstance(n, dict):
                    continue
                label = n.get("identity") or n.get("address") or n.get("mac-address") or str(n)
                doc.add_paragraph(str(label), style='List Bullet')

        doc.add_paragraph("Eksport konfiguracji (/export):").bold = True
        # A single run's embedded "\n" characters do NOT render as line
        # breaks in Word — each line needs its own run + an explicit
        # add_break(), otherwise the whole export collapses onto one
        # unreadable line.
        export_para = doc.add_paragraph()
        lines = r["export_text"].splitlines()
        for i, line in enumerate(lines):
            run = export_para.add_run(line)
            run.font.name = 'Consolas'
            run.font.size = Pt(8)
            if i < len(lines) - 1:
                run.add_break()

        doc.add_page_break()

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


async def _upload(doc_bytes: bytes, enc_key_b64: str) -> None:
    body = encrypt_archive(doc_bytes, enc_key_b64)
    url = uplink.drp_url()
    if not url:
        raise RuntimeError("no DRP upload URL derivable from uplink config")

    ts = str(int(time.time()))
    api_key = uplink._config["api_key"]
    sig = hmac.new(api_key.encode(), (ts + "|").encode() + body, hashlib.sha256).hexdigest()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "X-Tenant": uplink._config["tenant"],
        "X-Timestamp": ts,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, data=body, headers=headers) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")


async def generate_document() -> dict:
    """Builds the .docx for every eligible Mikrotik device, saves a local
    plaintext copy under data/drp_exports/, and — if Central is configured
    with an enc_key — encrypts + uploads it for Central download too.
    Never raises: this runs unattended when triggered by a Central
    command, so every failure mode is reported in the returned dict
    instead (same shape as agent_backup.create_and_upload_backup())."""
    if _state["in_progress"]:
        return {"ok": False, "error": "a DRP export is already in progress"}
    _state["in_progress"] = True
    try:
        with SessionLocal() as db:
            device_ids = list(db.execute(
                select(Device.id).where(Device.vendor == "mikrotik", Device.drp_exclude.isnot(True))
            ).scalars().all())

        rows = []
        for did in device_ids:
            with SessionLocal() as db:
                device = db.get(Device, did)
                if not device:
                    continue
                cred = db.get(Credential, device.credential_id) if device.credential_id else None
                # Detach the row's plain values we need before the session
                # closes — _collect_device_data holds onto `device` past
                # this point purely for its already-loaded scalar columns.
                db.expunge(device)
                if cred:
                    db.expunge(cred)
            rows.append(await _collect_device_data(device, cred))

        if not rows:
            _state["last_error"] = "no eligible Mikrotik devices (none configured, or all excluded)"
            activity.record("drp_doc_generate_failed", error=_state["last_error"])
            return {"ok": False, "error": _state["last_error"]}

        loop = asyncio.get_event_loop()
        doc_bytes = await loop.run_in_executor(None, _render_docx, rows)

        os.makedirs(EXPORT_DIR, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        tenant = (uplink._config.get("tenant") if uplink.is_configured() else None) or "agent"
        safe_tenant = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant)
        local_path = os.path.join(EXPORT_DIR, f"drp_{safe_tenant}_{ts}.docx")
        with open(local_path, "wb") as f:
            f.write(doc_bytes)

        included = sum(1 for r in rows if r["export_text"])
        skipped = len(rows) - included
        _state.update({
            "last_generated_at": datetime.utcnow().isoformat(),
            "last_size_bytes": len(doc_bytes),
            "last_local_path": local_path,
            "last_devices_included": included,
            "last_devices_skipped": skipped,
            "last_error": None,
        })

        uploaded = False
        if uplink.is_configured():
            enc_key = uplink.get_enc_key()
            if enc_key:
                try:
                    await _upload(doc_bytes, enc_key)
                    uploaded = True
                except Exception as e:
                    _state["last_error"] = f"zapisano lokalnie, ale wysyłka do Centrali nie powiodła się: {e}"

        # Reported back to Central via the same activity_events pipeline
        # every other completion event in this app uses — without this,
        # a command triggered remotely from Central (see uplink.py's
        # "drp_doc_generate" handler) would only ever show as "delivered"
        # there, never as actually finished (see the new "recent actions"
        # panel this feeds).
        activity.record("drp_doc_generate_done", devices_included=included, devices_skipped=skipped,
                         uploaded_to_central=uploaded, size_bytes=len(doc_bytes))

        return {
            "ok": True, "local_path": local_path, "size_bytes": len(doc_bytes),
            "devices_included": included, "devices_skipped": skipped,
            "uploaded_to_central": uploaded, "error": _state["last_error"],
        }
    except Exception as e:
        _state["last_error"] = str(e)
        activity.record("drp_doc_generate_failed", error=str(e))
        return {"ok": False, "error": str(e)}
    finally:
        _state["in_progress"] = False
