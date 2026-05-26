import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import List, Optional
from models.database import ScanRange, Device, Credential, get_db
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
async def list_ranges(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRange))
    return result.scalars().all()


@router.post("/ranges", response_model=ScanRangeOut)
async def add_range(data: ScanRangeCreate, db: AsyncSession = Depends(get_db)):
    import ipaddress
    try:
        ipaddress.ip_network(data.cidr, strict=False)
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {data.cidr}")
    sr = ScanRange(cidr=data.cidr, label=data.label, active=data.active)
    db.add(sr)
    await db.commit()
    await db.refresh(sr)
    return sr


@router.delete("/ranges/{range_id}")
async def delete_range(range_id: int, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(ScanRange).where(ScanRange.id == range_id))
    await db.commit()
    return {"ok": True}


@router.get("/run")
async def run_scan(credential_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    """SSE stream — yields discovered devices as JSON events during scan."""
    result = await db.execute(select(ScanRange).where(ScanRange.active == True))
    ranges = result.scalars().all()
    if not ranges:
        raise HTTPException(400, "No active scan ranges configured")

    # Optionally pre-fetch credentials for enrichment
    cred = None
    if credential_id:
        r = await db.execute(select(Credential).where(Credential.id == credential_id))
        cred = r.scalar_one_or_none()

    cidrs = [r.cidr for r in ranges]

    async def event_generator():
        for cidr in cidrs:
            yield f"data: {json.dumps({'status': 'scanning', 'cidr': cidr})}\n\n"
            async for found in svc.scan_range(cidr):
                # Try to enrich with identity if credentials supplied
                if cred:
                    try:
                        password = decrypt(cred.password_enc)
                        extra = await svc.enrich_device(
                            found["ip"], cred.username, password,
                            web_port=found.get("web_port", 80)
                        )
                        found.update(extra)
                    except Exception:
                        pass

                # Upsert into DB
                existing = await db.execute(select(Device).where(Device.ip == found["ip"]))
                device = existing.scalar_one_or_none()
                if device:
                    device.has_api = found.get("has_api", device.has_api)
                    device.has_ssh = found.get("has_ssh", device.has_ssh)
                    device.has_web = found.get("has_web", device.has_web)
                    device.api_port = found.get("api_port", device.api_port)
                    device.web_port = found.get("web_port", device.web_port)
                    device.online = True
                    device.last_seen = datetime.utcnow()
                    if found.get("identity"):
                        device.identity = found["identity"]
                    if found.get("model"):
                        device.model = found["model"]
                    if found.get("ros_version"):
                        device.ros_version = found["ros_version"]
                    if credential_id and not device.credential_id:
                        device.credential_id = credential_id
                else:
                    device = Device(
                        ip=found["ip"],
                        has_api=found.get("has_api", False),
                        has_ssh=found.get("has_ssh", False),
                        has_web=found.get("has_web", False),
                        api_port=found.get("api_port", 8728),
                        web_port=found.get("web_port", 80),
                        identity=found.get("identity"),
                        model=found.get("model"),
                        ros_version=found.get("ros_version"),
                        board_name=found.get("board_name"),
                        online=True,
                        last_seen=datetime.utcnow(),
                        credential_id=credential_id,
                    )
                    db.add(device)

                await db.commit()
                yield f"data: {json.dumps({'status': 'found', 'device': found})}\n\n"

        yield f"data: {json.dumps({'status': 'done'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})
