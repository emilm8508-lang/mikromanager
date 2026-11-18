from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import app_checks

router = APIRouter(prefix="/api/app-checks", tags=["app-checks"])


class Check(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    kind: str
    target: str
    enabled: bool = True
    interval_min: int = 2
    timeout_s: float = 10
    slow_ms: Optional[float] = None
    expect_status: Optional[str] = None
    contains: Optional[str] = None
    insecure: bool = False
    dns_server: Optional[str] = None
    expect_ip: Optional[str] = None


class ChecksBody(BaseModel):
    checks: List[Check]


@router.get("")
def overview():
    """Every application check: the last result, the availability of 24 h / 7 d, the 95th percentile of the response time, the certificate."""
    return app_checks.overview()


@router.put("")
def set_checks(body: ChecksBody, user: dict = Depends(require_login)):
    try:
        return {"checks": app_checks.save([c.model_dump() for c in body.checks])}
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))


@router.post("/test")
async def test(body: Check, user: dict = Depends(require_login)):
    """Runs one check once, without saving it or alerting - to try it before adding it."""
    try:
        c = app_checks.clean(body.model_dump())
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))
    r = await app_checks.run_one(c)
    if r.get("cert_not_after"):
        r["cert_not_after"] = r["cert_not_after"].isoformat() + "Z"
    return r


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await app_checks.run_due(force=True)
