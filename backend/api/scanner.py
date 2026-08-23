import json
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import List, Optional
from models.database import ScanRange, Device, Credential, SessionLocal, get_db
from services.crypto import decrypt
from services import scanner as svc
from datetime import datetime

router = APIRouter(prefix="/api/scanner", tags=["scanner"])


class ScanRangeCreate(BaseModel):
    cidr: str
    label: Optional[str] = None
    active: bool = True


class ScanRangeOut(BaseModel):
    id: int
    cidr: str
    label: Optional[str]
    active: bool

    class Config:
        from_attributes = True


@router.get("/ranges", response_model=List[ScanRangeOut])
async def list_ranges(db: Session = Depends(get_db)):
    return db.execute(select(ScanRange)).scalars().all()


@router.post("/ranges", response_model=ScanRangeOut)
async def add_range(data: ScanRangeCreate, db: Session = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_network(data.cidr, strict=False)
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {data.cidr}")
    sr = ScanRange(cidr=data.cidr, label=data.label, active=data.active)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    return sr


@router.delete("/ranges/{range_id}")
async def delete_range(range_id: int, db: Session = Depends(get_db)):
    db.execute(delete(ScanRange).where(ScanRange.id == range_id))
    db.commit()
    return {"ok": True}


@router.get("/probe")
async def probe_single(ip: str, credential_id: Optional[int] = None,
                       timeout: float = 2.0, db: Session = Depends(get_db)):
    """Diagnostic single-IP probe — bypasses the mass-scan's MAX_CONCURRENT
    semaphore entirely (this is the only thing running against the
    network at this moment), so it reflects exactly what a single manual
    connection attempt (e.g. Test-NetConnection) would see. Built to
    diagnose a device the full-range scan can't seem to find: returns
    port-by-port liveness (not just a found/dead verdict), the discovery
    result if any, and — if a credential is given — the full
    enrich_device() result INCLUDING the raw error, not just success/fail,
    for that specific IP+credential pair."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip}")

    ports = await svc._is_alive(ip, base_timeout=timeout)
    has_api_ssl = await svc._tcp_open(ip, 8729, timeout=timeout)
    has_snmp = await svc._snmp_alive(ip)

    sem = asyncio.Semaphore(1)
    found = await svc._probe_host(ip, sem, liveness_timeout=timeout)

    result = {
        "ip": ip,
        "ports": {str(p): ok for p, ok in ports.items()},
        "api_ssl_8729": has_api_ssl,
        "snmp_public": has_snmp,
        "found": found,
    }

    if credential_id:
        cred = db.execute(select(Credential).where(Credential.id == credential_id)).scalar_one_or_none()
        if not cred:
            raise HTTPException(404, "Credential not found")
        try:
            extra = await svc.enrich_device(
                ip, cred.username, decrypt(cred.password_enc),
                web_port=(found or {}).get("web_port", 80),
                snmp_community=decrypt(cred.snmp_community_enc) if cred.snmp_community_enc else None,
                snmp_port=(found or {}).get("snmp_port", 161),
            )
            result["enrich"] = {"ok": True, "data": extra}
        except Exception as e:
            result["enrich"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    return result


@router.get("/run")
async def run_scan(credential_id: Optional[int] = None, full: bool = False):
    """SSE stream with full progress events.

    Query params:
      credential_id: limit credential set tried for enrichment
      full=true:    re-scan ALL IPs including ones already in DB. Default false:
                    skip known IPs (they are refreshed by the periodic refresher).

    Event types pushed to client:
      - info     : startup message
      - cidr_start : starting a new CIDR, includes total host count
      - progress : a host was checked (or skipped as dead). Includes ip + completed/total
      - found    : a Mikrotik device was discovered + enriched
      - cidr_done: a CIDR finished
      - done     : all scanning finished
    """
    with SessionLocal() as db:
        ranges = db.execute(select(ScanRange).where(ScanRange.active == True)).scalars().all()
        if not ranges:
            raise HTTPException(400, "No active scan ranges configured")
        cidrs = [r.cidr for r in ranges]

        if credential_id:
            cred_rows = db.execute(
                select(Credential).where(Credential.id == credential_id)
            ).scalars().all()
        else:
            cred_rows = db.execute(select(Credential)).scalars().all()

        creds = [
            {
                "id": c.id,
                "name": c.name,
                "username": c.username,
                "password": decrypt(c.password_enc),
                "snmp_community": decrypt(c.snmp_community_enc) if c.snmp_community_enc else None,
            }
            for c in cred_rows
        ]

        # Snapshot IPs already in DB — by default scanner skips them and
        # looks only for new devices. Existing ones are kept fresh by refresher.
        if full:
            known_ips: set = set()
        else:
            known_ips = {ip for (ip,) in db.execute(select(Device.ip)).all()}

    async def event_generator():
        # Event queue bridge: probe callbacks → SSE output
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def emit(event: dict):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

        async def scan_all():
            try:
                emit({"type": "info",
                      "message_key": "credsCount",
                      "count": len(creds),
                      "known_count": len(known_ips),
                      "full_scan": full})

                total_found = 0
                for cidr in cidrs:
                    emit({"type": "cidr_start", "cidr": cidr})
                    found = await svc.scan_range_with_progress(
                        cidr, emit, skip_ips=known_ips
                    )
                    total_found += found

                emit({"type": "done", "total_found": total_found})
            finally:
                emit(None)  # sentinel = end stream

        # Run scanner in background
        scan_task = asyncio.create_task(scan_all())

        try:
            while True:
                event = await queue.get()
                if event is None:
                    break

                # On 'found' — try credentials and upsert into DB
                if event.get("type") == "found":
                    found = event["device"]
                    matched_cred_id = None
                    matched_cred_name = None

                    # Order credentials: those WITHOUT SNMP-only role first (i.e. ones
                    # with non-empty password), SNMP-only ones last. This way if any
                    # real API/REST credential works, we prefer it over a pure SNMP
                    # match (which is read-only and limited).
                    def cred_priority(c):
                        has_password = bool(c.get("password"))
                        has_snmp = bool(c.get("snmp_community"))
                        # Lower = higher priority. Password creds first.
                        if has_password and not has_snmp:
                            return 0  # API-only
                        if has_password and has_snmp:
                            return 1  # Combined
                        if has_snmp and not has_password:
                            return 2  # SNMP-only
                        return 3

                    ordered_creds = sorted(creds, key=cred_priority)

                    # Try every credential CONCURRENTLY rather than one at a
                    # time — enrich_device() itself already does REST→API→
                    # SNMP fallback with several-second timeouts at each
                    # step, so a sequential loop over up to 6 credentials
                    # could take up to 6x that per found device (the main
                    # cause of "scan is very slow" — this single found-device
                    # step was blocking the whole SSE event loop, delaying
                    # progress updates for every other host too). Running
                    # them concurrently bounds the wait to the single
                    # slowest credential attempt instead of their sum.
                    async def _try_cred(cred):
                        try:
                            extra = await svc.enrich_device(
                                found["ip"], cred["username"], cred["password"],
                                web_port=found.get("web_port", 80),
                                snmp_community=cred.get("snmp_community"),
                                snmp_port=found.get("snmp_port", 161),
                            )
                        except Exception:
                            return None
                        # Score the result. Higher = better.
                        # API-capable cred (has password) that succeeded → bonus 100.
                        # Otherwise, count fields populated.
                        score = 0
                        if extra.get("identity"): score += 1
                        if extra.get("model"):    score += 2
                        if extra.get("ros_version"): score += 3
                        if extra.get("board_name"): score += 1
                        # Strong preference for password-bearing credentials when they actually returned anything
                        if cred.get("password") and score > 0:
                            score += 100
                        return {"cred_id": cred["id"], "cred_name": cred["name"],
                                "extra": extra, "score": score}

                    cred_results = await asyncio.gather(*[_try_cred(c) for c in ordered_creds])

                    best = None       # {cred_id, cred_name, extra, score}
                    best_score = -1
                    for r in cred_results:
                        if r and r["score"] > best_score:
                            best_score = r["score"]
                            best = r

                    if best and best_score > 0:
                        found.update(best["extra"])
                        matched_cred_id = best["cred_id"]
                        matched_cred_name = best["cred_name"]
                        found["matched_credential"] = matched_cred_name

                    # Upsert
                    with SessionLocal() as db:
                        device = db.execute(select(Device).where(Device.ip == found["ip"])).scalar_one_or_none()
                        if device:
                            device.has_api = found.get("has_api", device.has_api)
                            device.has_ssh = found.get("has_ssh", device.has_ssh)
                            device.has_web = found.get("has_web", device.has_web)
                            device.has_snmp = found.get("has_snmp", device.has_snmp)
                            device.api_port = found.get("api_port", device.api_port)
                            device.web_port = found.get("web_port", device.web_port)
                            device.snmp_port = found.get("snmp_port", device.snmp_port)
                            if found.get("vendor"):
                                device.vendor = found["vendor"]
                            device.online = True
                            device.last_seen = datetime.utcnow()
                            if found.get("identity"):
                                device.identity = found["identity"]
                            if found.get("model"):
                                device.model = found["model"]
                            if found.get("ros_version"):
                                device.ros_version = found["ros_version"]
                            if matched_cred_id:
                                # Assign if device has no cred yet, OR if existing cred
                                # is SNMP-only and the new match has a real password.
                                if not device.credential_id:
                                    device.credential_id = matched_cred_id
                                else:
                                    # Check existing cred — upgrade to password-bearing one if available
                                    existing_cred = next((c for c in creds if c["id"] == device.credential_id), None)
                                    new_cred = next((c for c in creds if c["id"] == matched_cred_id), None)
                                    if (existing_cred and new_cred
                                        and not existing_cred.get("password")
                                        and new_cred.get("password")):
                                        device.credential_id = matched_cred_id
                        else:
                            device = Device(
                                ip=found["ip"],
                                vendor=found.get("vendor", "mikrotik"),
                                has_api=found.get("has_api", False),
                                has_ssh=found.get("has_ssh", False),
                                has_web=found.get("has_web", False),
                                has_snmp=found.get("has_snmp", False),
                                api_port=found.get("api_port", 8728),
                                web_port=found.get("web_port", 80),
                                snmp_port=found.get("snmp_port", 161),
                                identity=found.get("identity"),
                                model=found.get("model"),
                                ros_version=found.get("ros_version"),
                                board_name=found.get("board_name"),
                                online=True,
                                last_seen=datetime.utcnow(),
                                credential_id=matched_cred_id,
                            )
                            db.add(device)
                        db.commit()

                yield f"data: {json.dumps(event)}\n\n"
        finally:
            if not scan_task.done():
                scan_task.cancel()

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})
