import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from models.database import SessionLocal, VulnHost, VulnService, VulnPackage, VulnFinding, Device, Credential
from services import vuln_scan

router = APIRouter(prefix="/api/vuln", tags=["vuln"])

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


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


@router.get("/findings")
async def list_findings(severity: Optional[str] = None):
    """Every cached CVE finding, joined against whatever currently has that
    (product, version) — live-scanned hosts (VulnService), installed
    packages/software on credentialed hosts (VulnPackage), and/or already-
    known Mikrotik/Cisco devices (Device.ros_version). Findings whose
    version nothing currently matches (e.g. the host disappeared) are
    omitted — this reflects current exposure, not historical trivia."""
    with SessionLocal() as db:
        findings = db.execute(select(VulnFinding)).scalars().all()
        services = db.execute(select(VulnService)).scalars().all()
        packages = db.execute(select(VulnPackage)).scalars().all()
        hosts = {h.id: h for h in db.execute(select(VulnHost)).scalars().all()}
        devices = db.execute(select(Device)).scalars().all()

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

        out = []
        for f in findings:
            if severity and (f.severity or "") != severity.upper():
                continue
            affected = affected_by_pv.get((f.product, f.version), [])
            if not affected:
                continue
            out.append({
                "id": f.id, "product": f.product, "version": f.version,
                "cve_id": f.cve_id, "cvss_score": f.cvss_score, "severity": f.severity,
                "summary": f.summary, "published": f.published, "ref_url": f.ref_url,
                "affected": affected,
            })

        out.sort(key=lambda x: (
            _SEVERITY_ORDER.get(x["severity"], 4),
            -(x["cvss_score"] or 0),
        ))
        return out
