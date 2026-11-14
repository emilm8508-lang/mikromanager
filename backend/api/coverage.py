from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import coverage, comm_watch

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


@router.get("")
def report():
    """Every source of information of the agent with when it last worked, how often it should and its state (ok / stale / error / off)."""
    return coverage.report()


# ── per asset: expected data sources and loss of communication (services/comm_watch.py) ──

@router.get("/assets")
def assets_coverage(levels: str = "critical,important"):
    """The assets of these criticality levels with each data source (expected or not, last delivered, late / error) and what is recommended
    for their kind but never seen."""
    lv = tuple(x for x in levels.split(",") if x in ("critical", "important", "normal"))
    return {"items": comm_watch.coverage(lv or ("critical", "important")), "status": comm_watch.status(), "settings": comm_watch.settings()}


class CommSettings(BaseModel):
    enabled: Optional[bool] = None
    thresholds: Optional[dict] = None
    expect_days: Optional[int] = None


@router.put("/comm/settings")
def comm_settings(body: CommSettings):
    try:
        return comm_watch.update_settings({k: v for k, v in body.model_dump().items() if v is not None})
    except ValueError as e:
        raise HTTPException(400, str(e))


class Expected(BaseModel):
    asset_id: int
    source: str
    expected: Optional[bool] = None          # true / false, or null = automatic again


@router.put("/comm/expected")
def comm_expected(body: Expected):
    try:
        return comm_watch.set_expected(body.asset_id, body.source, body.expected)
    except ValueError as e:
        raise HTTPException(400, str(e))
