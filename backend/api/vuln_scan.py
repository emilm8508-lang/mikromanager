import asyncio
import csv
import io
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select

from models.database import (
    SessionLocal, VulnHost, VulnService, VulnPackage, VulnFinding, VulnRemediation, Device, Credential,
)
from services import vuln_scan
from api.auth import require_login

router = APIRouter(prefix="/api/vuln", tags=["vuln"])

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_VALID_STATUSES = {"open", "in_progress", "accepted_risk", "resolved"}


@router.get("/status")
async def get_status():
    return vuln_scan.status()


@router.post("/run")
async def trigger_run():
    """Manually trigger a scan now. 409 if one (manual or scheduled) is
    already running — mirrors the pattern used by /api/system/refresh/run."""
    if vuln_scan._in_progress:
        raise HTTPException(409, "Skan podatności jest już w toku")
    asyncio.create_task(vuln_scan.run_scan())
    return {"started": True}


@router.get("/scan-stream")
async def scan_stream():
    """Same scan as POST /run, but as an SSE stream reporting live
    progress — added because the fire-and-forget POST gave zero visible
    feedback for however long the scan takes. Event shape: {"type":
    "phase", "phase": ..., "total": ...} announcing a new stage ("probing",
    "rechecking", "credentials", "persisting", "package_audit", "findings",
    "linux_discovery", "linux_identify", "linux_refresh"), or {"type":
    "progress", "phase": ..., "completed": ..., "total": ..., "ip": ...}
    per host within a stage, or {"type": "done", ...} at the end. 409 if a
    scan is already in progress (same guard as POST /run) — the stream
    would otherwise just sit there emitting nothing until the OTHER scan
    finishes, silently misleading whoever opened it."""
    if vuln_scan._in_progress:
        raise HTTPException(409, "Skan podatności jest już w toku")

    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def emit(event: dict):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def _run():
        try:
            result = await vuln_scan.run_scan(on_event=emit)
            emit({"type": "result", **result})
        except Exception as e:
            emit({"type": "error", "message": str(e)})
        finally:
            queue.put_nowait(None)  # sentinel = end stream

    async def event_generator():
        task = asyncio.create_task(_run())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/hosts")
async def list_hosts():
    with SessionLocal() as db:
        hosts = db.execute(select(VulnHost)).scalars().all()
        devices = {d.id: d for d in db.execute(select(Device)).scalars().all()}
        creds = {c.id: c for c in db.execute(select(Credential)).scalars().all()}
        services_by_host: dict = {}
        for s in db.execute(select(VulnService)).scalars().all():
            services_by_host.setdefault(s.host_id, []).append(s)

        out = []
        for h in hosts:
            device = devices.get(h.device_id)
            cred = creds.get(h.credential_id)
            out.append({
                "id": h.id,
                "ip": h.ip,
                "device_id": h.device_id,
                "device_name": (device.identity or device.name) if device else None,
                "credential_id": h.credential_id,
                "credential_name": cred.name if cred else None,
                "last_scan_at": h.last_scan_at.isoformat() if h.last_scan_at else None,
                "services": [
                    {
                        "port": s.port,
                        "service_name": s.service_name,
                        "product": s.product,
                        "version": s.version,
                        "banner_raw": s.banner_raw,
                        "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    }
                    for s in sorted(services_by_host.get(h.id, []), key=lambda s: s.port)
                ],
            })
        out.sort(key=lambda h: [int(p) for p in h["ip"].split(".")])
        return out


class HostCredentialIn(BaseModel):
    credential_id: Optional[int] = None


@router.post("/hosts/{host_id}/rescan")
async def rescan_host(host_id: int):
    """Re-check just this one host now — e.g. to confirm a patch actually
    fixed a finding, without waiting for the weekly scan."""
    with SessionLocal() as db:
        host = db.get(VulnHost, host_id)
        if not host:
            raise HTTPException(404, "Host not found")
        ip = host.ip
    return await vuln_scan.scan_one_host(ip)


@router.put("/hosts/{host_id}/credential")
async def set_host_credential(host_id: int, data: HostCredentialIn):
    """Opt-in per host: attach an existing Credential so the next scan can
    do a deeper, authenticated SSH identity check (os-release/uname) on top
    of the passive banner grab. Pass credential_id=null to remove."""
    with SessionLocal() as db:
        host = db.get(VulnHost, host_id)
        if not host:
            raise HTTPException(404, "Host not found")
        if data.credential_id is not None and not db.get(Credential, data.credential_id):
            raise HTTPException(404, "Credential not found")
        host.credential_id = data.credential_id
        db.commit()
    return {"ok": True}


def _build_findings(db, severity: Optional[str] = None) -> list:
    """Every cached CVE finding, joined against whatever currently has that
    (product, version) — live-scanned hosts (VulnService), installed
    packages/software on credentialed hosts (VulnPackage), and/or already-
    known Mikrotik/Cisco devices (Device.ros_version). Findings whose
    version nothing currently matches (e.g. the host disappeared) are
    omitted — this reflects current exposure, not historical trivia.
    Also joins in remediation status/SLA — see VulnRemediation's docstring
    for why that's a separate table from VulnFinding."""
    findings = db.execute(select(VulnFinding)).scalars().all()
    services = db.execute(select(VulnService)).scalars().all()
    packages = db.execute(select(VulnPackage)).scalars().all()
    hosts = {h.id: h for h in db.execute(select(VulnHost)).scalars().all()}
    devices = db.execute(select(Device)).scalars().all()
    remediations = {
        (r.product, r.version, r.cve_id): r
        for r in db.execute(select(VulnRemediation)).scalars().all()
    }

    affected_by_pv: dict = {}
    for s in services:
        if not (s.product and s.version):
            continue
        host = hosts.get(s.host_id)
        if not host:
            continue
        affected_by_pv.setdefault((s.product, s.version), []).append(
            {"kind": "host", "ip": host.ip, "port": s.port})
    for p in packages:
        host = hosts.get(p.host_id)
        if not host:
            continue
        affected_by_pv.setdefault((p.name, p.version), []).append(
            {"kind": "package", "ip": host.ip, "port": None})
    for d in devices:
        if not d.ros_version:
            continue
        product = "MikroTik RouterOS" if d.vendor == "mikrotik" else f"{d.vendor} {d.model or ''}".strip()
        affected_by_pv.setdefault((product, d.ros_version), []).append(
            {"kind": "device", "ip": d.ip, "port": None,
             "device_id": d.id, "device_name": d.identity or d.name})

    now = datetime.utcnow()
    out = []
    for f in findings:
        if severity and (f.severity or "") != severity.upper():
            continue
        affected = affected_by_pv.get((f.product, f.version), [])
        if not affected:
            continue
        r = remediations.get((f.product, f.version, f.cve_id))
        due = vuln_scan.sla_due_date(f.severity, r.first_seen_at if r else None)
        status = r.status if r else "open"
        out.append({
            "id": f.id, "product": f.product, "version": f.version,
            "cve_id": f.cve_id, "cvss_score": f.cvss_score, "severity": f.severity,
            "summary": f.summary, "published": f.published, "ref_url": f.ref_url,
            "affected": affected,
            "status": status,
            "note": r.note if r else None,
            "updated_by": r.updated_by if r else None,
            "updated_at": r.updated_at.isoformat() if r and r.updated_at else None,
            "first_seen_at": r.first_seen_at.isoformat() if r and r.first_seen_at else None,
            "due_date": due.isoformat() if due else None,
            "overdue": bool(due and now > due and status in ("open", "in_progress")),
        })

    out.sort(key=lambda x: (
        _SEVERITY_ORDER.get(x["severity"], 4),
        -(x["cvss_score"] or 0),
    ))
    return out


@router.get("/findings")
async def list_findings(severity: Optional[str] = None):
    with SessionLocal() as db:
        return _build_findings(db, severity)


class RemediationIn(BaseModel):
    product: str
    version: str
    cve_id: str
    status: str
    note: Optional[str] = None


@router.put("/remediation")
async def set_remediation(data: RemediationIn, session: dict = Depends(require_login)):
    """Update a finding's remediation status. Written directly onto
    VulnRemediation (not VulnFinding — see that model's docstring), keyed
    by the same (product, version, cve_id) identity findings already use.
    Read access to /findings works for any role; changing status is a
    write, so a viewer-role session is already rejected at the router-level
    RBAC in require_login before this body ever runs."""
    if data.status not in _VALID_STATUSES:
        raise HTTPException(400, f"invalid status — must be one of {sorted(_VALID_STATUSES)}")
    with SessionLocal() as db:
        row = db.execute(
            select(VulnRemediation).where(
                VulnRemediation.product == data.product,
                VulnRemediation.version == data.version,
                VulnRemediation.cve_id == data.cve_id,
            )
        ).scalar_one_or_none()
        if not row:
            # Defensive fallback — normally created by the scan itself
            # (services/vuln_scan.py's _ensure_remediation_row) the first
            # time this CVE is seen for this product/version.
            row = VulnRemediation(
                product=data.product, version=data.version, cve_id=data.cve_id,
                first_seen_at=datetime.utcnow(),
            )
            db.add(row)
        row.status = data.status
        row.note = data.note
        row.updated_by = session.get("username")
        row.updated_at = datetime.utcnow()
        db.commit()
        return {"ok": True}


def _csv_safe(value) -> str:
    """Neutralize CSV/formula injection (OWASP-standard mitigation) — a
    `note` is free-text from a PUT /remediation caller, and CVE product/
    summary strings ultimately come from NVD/vulners; a value starting with
    =, +, -, @, tab, or CR would be interpreted as a formula by Excel/
    Sheets when the export is opened. Prefixing a single quote keeps it as
    inert text without changing what's displayed in a spreadsheet cell."""
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


@router.get("/findings/export")
async def export_findings(severity: Optional[str] = None):
    """CSV export of the current findings list — evidence of regular
    scanning/remediation tracking for an ISO 27001 / NIS2 audit."""
    with SessionLocal() as db:
        findings = _build_findings(db, severity)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "cve_id", "severity", "cvss_score", "product", "version", "status",
        "first_seen_at", "due_date", "overdue", "updated_by", "updated_at",
        "note", "affected_count", "ref_url",
    ])
    for f in findings:
        writer.writerow([_csv_safe(v) for v in (
            f["cve_id"], f["severity"], f["cvss_score"], f["product"], f["version"], f["status"],
            f["first_seen_at"] or "", f["due_date"] or "", f["overdue"],
            f["updated_by"] or "", f["updated_at"] or "", f["note"] or "",
            len(f["affected"]), f["ref_url"] or "",
        )])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerability_findings.csv"},
    )
