from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from api.auth import require_login
from services import anomaly

router = APIRouter(prefix="/api/anomalies", tags=["anomalies"])


class VerdictBody(BaseModel):
    verdict: Optional[str] = None     # "true" (a real problem) | "false" (a false alarm) | null (clear the label)


@router.get("")
def overview(days: int = 90):
    """The anomaly events of the last `days` (open ones first) and the detector's numbers."""
    days = max(1, min(int(days), 365))
    events = anomaly.list_events(days)
    events.sort(key=lambda e: (e["ended_at"] is not None, e["started_at"]), reverse=False)
    events = [e for e in events if e["ended_at"] is None] + [e for e in events if e["ended_at"] is not None]
    multi = sorted(({"host_key": k, **v} for k, v in anomaly._multi.items()), key=lambda r: -r["score"])[:25]
    return {"events": events, "stats": anomaly.stats(days), "multivariate": multi}


@router.get("/band")
def band(key: str, days: float = 3):
    """One series with its learned normal range, for the chart."""
    try:
        return anomaly.band(key, max(0.1, min(float(days), 28)))
    except KeyError:
        raise HTTPException(404, "no such series")


@router.put("/events/{event_id}/verdict")
def verdict(event_id: int, body: VerdictBody, user: dict = Depends(require_login)):
    try:
        return anomaly.set_verdict(event_id, body.verdict, user.get("username") or "?")
    except KeyError:
        raise HTTPException(404, "no such event")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/events.csv", response_class=PlainTextResponse)
def events_csv(days: int = 365):
    """Every event with its label, for measuring the detector outside the application."""
    rows = ["id,host,category,severity,started_at,ended_at,minutes,peak_score,if_score,series,verdict"]
    for e in anomaly.list_events(max(1, min(int(days), 3650))):
        series = "|".join(f"{s['label']}={s['value']}{s['unit']}~{s['expected']}" for s in e["series"])
        cells = [e["id"], e["host"] or "", e["category"], e["severity"], e["started_at"], e["ended_at"] or "", e["minutes"], e["peak_score"], e["if_score"] if e["if_score"] is not None else "", series, e["verdict"] or ""]
        rows.append(",".join('"' + str(c).replace('"', '""') + '"' for c in cells))
    return PlainTextResponse("﻿" + "\n".join(rows) + "\n", media_type="text/csv; charset=utf-8",          # BOM: Excel reads it as UTF-8
                             headers={"Content-Disposition": "attachment; filename=anomaly-events.csv"})


@router.post("/run")
def run_now(user: dict = Depends(require_login)):
    return anomaly.run_cycle()
