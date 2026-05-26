import json
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
    """SSE stream — discovers devices, then tries each stored credential
    to enrich and auto-assign whichever one authenticates.

    Query params:
      credential_id — if set, only try this one credential (legacy single-cred mode).
                      If omitted, tries ALL stored credentials in order until one works.
    """
    # Snapshot config + credential list under a short-lived session
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
            }
            for c in cred_rows
        ]

    async def event_generator():
        if creds:
            yield f"data: {json.dumps({'status': 'info', 'message': f'Skan z {len(creds)} zestaw(ami) poświadczeń'})}\n\n"
        else:
            yield f"data: {json.dumps({'status': 'info', 'message': 'Brak poświadczeń — tylko wykrycie portów'})}\n\n"

        for cidr in cidrs:
            yield f"data: {json.dumps({'status': 'scanning', 'cidr': cidr})}\n\n"
            async for found in svc.scan_range(cidr):
                matched_cred_id = None
                matched_cred_name = None

                # Try each credential until one returns real device data.
                # "Real" = we got identity OR model — i.e. auth worked.
                for cred in creds:
                    try:
                        extra = await svc.enrich_device(
                            found["ip"], cred["username"], cred["password"],
                            web_port=found.get("web_port", 80)
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

                # Upsert with a fresh per-event session
                with SessionLocal() as db:
                    device = db.execute(select(Device).where(Device.ip == found["ip"])).scalar_one_or_none()
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
                        # Only auto-assign credential if device has none yet
                        if matched_cred_id and not device.credential_id:
                            device.credential_id = matched_cred_id
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
                            credential_id=matched_cred_id,
                        )
                        db.add(device)
                    db.commit()

                yield f"data: {json.dumps({'status': 'found', 'device': found})}\n\n"

        yield f"data: {json.dumps({'status': 'done'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})
