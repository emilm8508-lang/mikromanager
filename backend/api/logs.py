"""
Live log streaming via Server-Sent Events — no storage, view only.
"""
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models.database import Device, Credential, get_db
from services.crypto import decrypt
from services.mikrotik_client import MikrotikClient

router = APIRouter(prefix="/api/logs", tags=["logs"])


async def _get_client(device_id: int, db: AsyncSession) -> MikrotikClient:
    result = await db.execute(
        select(Device, Credential)
        .join(Credential, Device.credential_id == Credential.id)
        .where(Device.id == device_id)
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(404, "Device or credential not found")
    device, cred = row
    return MikrotikClient(device.ip, cred.username, decrypt(cred.password_enc),
                          api_port=device.api_port, web_port=device.web_port)


@router.get("/{device_id}")
async def get_logs(device_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch last 200 log entries — live, not stored."""
    client = await _get_client(device_id, db)
    logs = await client.get_logs(limit=200)
    return logs


@router.get("/{device_id}/stream")
async def stream_logs(device_id: int, db: AsyncSession = Depends(get_db)):
    """SSE stream — polls device log every 3s and pushes new entries."""
    client = await _get_client(device_id, db)

    async def event_generator():
        seen_ids: set = set()
        while True:
            try:
                logs = await client.get_logs(limit=200)
                new_entries = [l for l in logs if l.get(".id") not in seen_ids]
                for entry in new_entries:
                    seen_ids.add(entry.get(".id"))
                    yield f"data: {json.dumps(entry)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})
