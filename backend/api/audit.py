from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from models.database import AuditLog, get_db
from api.auth import require_login

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    username: Optional[str] = None,
    session: dict = Depends(require_login),
    db: Session = Depends(get_db),
):
    """Admin-only — the audit trail itself is sensitive (who did what,
    including who looked at credentials/scans), so a viewer-role session
    can't read it even though this is a GET (the router-level RBAC in
    require_login only blocks writes, not reads)."""
    if session.get("role") != "admin":
        raise HTTPException(403, "admin role required")

    q = select(AuditLog).order_by(desc(AuditLog.ts))
    if username:
        q = q.where(AuditLog.username == username)
    q = q.offset(offset).limit(limit)
    rows = db.execute(q).scalars().all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat() if r.ts else None,
            "username": r.username,
            "role": r.role,
            "source": r.source,
            "method": r.method,
            "path": r.path,
            "status_code": r.status_code,
            "ip": r.ip,
        }
        for r in rows
    ]
