import json
from typing import Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from api.auth import require_login
from services import reports, mailer, audit as audit_svc

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _who(user: dict) -> str:
    return str(user.get("username") or user.get("source") or "?")


class BuildBody(BaseModel):
    builtin: Optional[str] = None
    params: Optional[dict] = None
    format: Optional[str] = None                  # for /download
    title: Optional[str] = None
    labels: Optional[Dict[str, str]] = None       # column headings in the page's language


class DefBody(BaseModel):
    name: str
    builtin: Optional[str] = None
    params: Optional[dict] = None
    schedule: str = "none"
    format: str = "xlsx"
    hour: Optional[int] = None
    weekday: Optional[int] = None
    day: Optional[int] = None
    recipients: Union[List[str], str, None] = None


class SmtpBody(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    security: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None                # absent keeps the stored one, "" clears it
    from_addr: Optional[str] = None
    from_name: Optional[str] = None


class TestBody(BaseModel):
    to: str


@router.get("")
def overview():
    """The ready-made reports, the columns of each scope, the saved reports with their last runs, and whether e-mail is set up."""
    return {"builtin": list(reports.BUILTIN), "columns": {k: list(v) for k, v in reports.COLUMNS.items()}, "saved": reports.defs(),
            "smtp_configured": mailer.configured()}


@router.post("/preview")
def preview(body: BuildBody):
    """The rows of a report (at most 500 here; the file has all of them)."""
    try:
        d = reports.build(body.builtin, body.params)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {**d, "rows": d["rows"][:500]}


@router.post("/download")
def download(body: BuildBody):
    try:
        d = reports.build(body.builtin, body.params)
        data, ctype, fname = reports.render(body.format or "xlsx", body.title or body.builtin or "report", d, body.labels or reports.labels_for("en"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return Response(content=data, media_type=ctype, headers={"Content-Disposition": f'attachment; filename="{fname}"', "X-Content-Type-Options": "nosniff"})


@router.post("/saved")
def add_saved(body: DefBody, user: dict = Depends(require_login)):
    try:
        return {"id": reports.save_def(body.model_dump(), None, _who(user))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/saved/{rid}")
def edit_saved(rid: int, body: DefBody, user: dict = Depends(require_login)):
    try:
        return {"id": reports.save_def(body.model_dump(), rid, _who(user))}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/saved/{rid}")
def del_saved(rid: int, user: dict = Depends(require_login)):
    if not reports.delete_def(rid):
        raise HTTPException(404, "report not found")
    return {"ok": True}


@router.post("/saved/{rid}/send")
async def send_now(rid: int, user: dict = Depends(require_login)):
    if not mailer.configured():
        raise HTTPException(400, "e-mail (SMTP) is not set up")
    try:
        return await reports.send(rid)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/smtp")
def smtp_get():
    return mailer.settings()


@router.put("/smtp")
def smtp_set(body: SmtpBody, request: Request, user: dict = Depends(require_login)):
    """The SMTP server of the agent - an admin only (it holds a password); the change is recorded in the audit log."""
    if user.get("role") != "admin":
        raise HTTPException(403, "admin role required (SMTP settings)")
    try:
        r = mailer.save(body.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit_svc.record(username=user.get("username") or "?", role=user.get("role") or "?", source=user.get("source") or "?",
                     method="PUT", path="/api/reports/smtp", status_code=200, ip=request.client.host if request.client else None)
    return r


@router.post("/smtp/test")
async def smtp_test(body: TestBody, user: dict = Depends(require_login)):
    return await mailer.test(body.to.strip())
