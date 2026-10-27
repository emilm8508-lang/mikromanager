from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import metrics

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


class RuleBody(BaseModel):
    name: str
    kind: str
    op: str = ">"
    threshold: float
    minutes: int = 0
    severity: str = "medium"
    match: Optional[str] = None
    enabled: bool = True


class RulesBody(BaseModel):
    rules: List[RuleBody]


@router.get("")
def overview():
    """Every series with its latest value, the trend of the last week and, for disks, the days until it is full (soonest first); and the rules."""
    return {"series": metrics.series_list(), "rules": metrics.load_rules(), "status": metrics.status()}


@router.get("/series")
def series(key: str, days: float = 7):
    """The readings of one series over the last `days` (at most 400 points) with the fitted trend."""
    days = max(0.1, min(float(days), metrics.KEEP_DAYS))
    pts = metrics.points(key, days)
    if not pts:
        raise HTTPException(404, "no readings for this series")
    full = metrics.points(key, metrics.FORECAST_DAYS, 2000)
    t = metrics.trend(full)
    return {"key": key, "points": [{"t": a.isoformat() + "Z", "v": round(v, 2)} for a, v in pts], "trend": t}


@router.put("/rules")
def set_rules(body: RulesBody, user: dict = Depends(require_login)):
    try:
        return {"rules": metrics.save_rules([r.model_dump() for r in body.rules])}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/run")
async def run_now(user: dict = Depends(require_login)):
    return await metrics.run_cycle()
