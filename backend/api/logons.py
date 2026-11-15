"""Who logged on to the assets (services/logons.py, 3.70). Personal data: an admin role only, and every read goes into the audit log."""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select

from api.auth import require_login
from models.database import SessionLocal, Asset, AssetLogon
from services import logons, audit as audit_svc

router = APIRouter(prefix="/api/logons", tags=["logons"])


def _admin_read(request: Request, session: dict, what: str) -> None:
    """Only an admin reads logons, and the read itself is recorded (who looked at whose logons)."""
    if session.get("role") != "admin":
        raise HTTPException(403, "admin role required (logon data is personal data)")
    audit_svc.record(username=session.get("username") or "?", role=session.get("role") or "?", source=session.get("source") or "?",
                     method="GET", path=f"/api/logons {what}"[:250], status_code=200, ip=request.client.host if request.client else None)


@router.get("")
async def list_logons(request: Request, asset_id: Optional[int] = None, host_ip: Optional[str] = None, user: Optional[str] = None,
                      days: int = Query(7, ge=1, le=365), result: Optional[str] = None, privileged: Optional[bool] = None,
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), session: dict = Depends(require_login)):
    _admin_read(request, session, f"list asset={asset_id} host={host_ip} user={user}")
    q = select(AssetLogon).where(AssetLogon.at >= datetime.utcnow() - timedelta(days=days))
    if asset_id:
        q = q.where(AssetLogon.asset_id == asset_id)
    if host_ip:
        q = q.where(AssetLogon.host_ip == host_ip)
    if user:
        q = q.where(AssetLogon.user.ilike(f"%{user.strip()[:64]}%"))
    if result in ("success", "failure"):
        q = q.where(AssetLogon.result == result)
    if privileged is not None:
        q = q.where(AssetLogon.is_privileged == privileged)
    with SessionLocal() as db:
        rows = db.execute(q.order_by(AssetLogon.at.desc()).offset(offset).limit(limit + 1)).scalars().all()
    more = len(rows) > limit
    return {"items": [{"id": r.id, "asset_id": r.asset_id, "host": r.host_name or r.host_ip, "host_ip": r.host_ip, **logons._brief(r)} for r in rows[:limit]],
            "next_offset": offset + limit if more else None}


@router.get("/asset/{asset_id}")
async def asset_summary(request: Request, asset_id: int, session: dict = Depends(require_login)):
    _admin_read(request, session, f"asset {asset_id}")
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        import json
        refs = json.loads(a.refs or "{}")
        return logons.summary(host_ip=a.ip, asset_id=a.id, asset_type=a.asset_type, refs=refs, name=a.name)


@router.get("/settings")
async def get_settings(session: dict = Depends(require_login)):
    return logons.settings()


class SettingsIn(BaseModel):
    retention_days: Optional[int] = None
    daily_days: Optional[int] = None
    work_hours: Optional[list] = None
    workdays: Optional[list] = None
    send_to_central: Optional[bool] = None
    rules: Optional[dict] = None


@router.put("/settings")
async def put_settings(body: SettingsIn, session: dict = Depends(require_login)):
    if session.get("role") != "admin":
        raise HTTPException(403, "admin role required")
    return logons.update_settings(body.model_dump(exclude_unset=True))
