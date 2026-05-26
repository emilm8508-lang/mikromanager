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


@router.get("/run")
async def run_scan(credential_id: Optional[int] = None):
    """SSE stream with full progress events.

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
                      "count": len(creds)})

                total_found = 0
                for cidr in cidrs:
                    emit({"type": "cidr_start", "cidr": cidr})
                    found = await svc.scan_range_with_progress(cidr, emit)
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

                    for cred in creds:
                        try:
                            extra = await svc.enrich_device(
                                found["ip"], cred["username"], cred["password"],
                                web_port=found.get("web_port", 80),
                                snmp_community=cred.get("snmp_community"),
                                snmp_port=found.get("snmp_port", 161),
                            )
                            if extra.get("identity") or extra.get("model") or extra.get("ros_version"):
                                found.update(extra)
                                matched_cred_id = cred["id"]
                                matched_cred_name = cred["name"]
                                break
                        except Exception:
                            continue

                    if matched_cred_name:
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
                            device.online = True
                            device.last_seen = datetime.utcnow()
                            if found.get("identity"):
                                device.identity = found["identity"]
                            if found.get("model"):
                                device.model = found["model"]
                            if found.get("ros_version"):
                                device.ros_version = found["ros_version"]
                            if matched_cred_id and not device.credential_id:
                                device.credential_id = matched_cred_id
                        else:
                            device = Device(
                                ip=found["ip"],
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
