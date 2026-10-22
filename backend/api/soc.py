from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import require_login
from services import soc, soc_rules

router = APIRouter(prefix="/api/soc", tags=["soc"])


class AlertUpdate(BaseModel):
    ids: List[int]
    status: Optional[str] = None
    owner: Optional[str] = None
    note: Optional[str] = None
    set_owner: bool = False
    set_note: bool = False


@router.get("/alerts")
def alerts(status: str = "open", severity: Optional[str] = None, category: Optional[str] = None, source: Optional[str] = None,
           q: Optional[str] = None, limit: int = 300, offset: int = 0):
    """The alert queue. status: open (new + acknowledged + in progress) | all | closed (closed + false positives) | a single status."""
    return soc.list_alerts(status=status, severity=severity, category=category, source=source, q=q, limit=limit, offset=offset)


@router.get("/alerts/{alert_id}")
def alert(alert_id: int):
    a = soc.get_alert(alert_id)
    if a is None:
        raise HTTPException(404, "alert not found")
    return a


@router.post("/alerts/update")
def update(body: AlertUpdate, user: dict = Depends(require_login)):
    """Status / owner / note of one or more alerts (the same call for a single alert and for the bulk bar)."""
    if not body.ids:
        raise HTTPException(400, "no alerts selected")
    if body.status is not None and body.status not in soc.STATUSES:
        raise HTTPException(400, "unknown status")
    n = soc.update(body.ids[:500], status=body.status, owner=body.owner, note=body.note, who=str(user.get("username") or "?"),
                   set_owner=body.set_owner, set_note=body.set_note)
    return {"changed": n}


@router.get("/stats")
def stats():
    return soc.stats()


class RuleToggle(BaseModel):
    enabled: bool


@router.get("/rules")
def rules():
    """The agent's own detection rules: what each looks for, how often, whether it is on and what it found last."""
    return soc_rules.list_rules()


@router.post("/rules/{rule_id}")
def rule_toggle(rule_id: str, body: RuleToggle):
    if not soc_rules.set_enabled(rule_id, body.enabled):
        raise HTTPException(404, "unknown rule")
    return {"ok": True}


@router.post("/rules/{rule_id}/run")
async def rule_run(rule_id: str):
    """Runs one rule now (the first run of a rule only records what is already there; it raises nothing)."""
    if rule_id not in {r["id"] for r in soc_rules.list_rules()}:
        raise HTTPException(404, "unknown rule")
    return await soc_rules.run_due(only=rule_id, force=True)
