"""
The hardware life of an asset, from purchase to disposal, and what it cost (docs/plan-itam.md, stage A).

The inventory knows what is on the network; this is what the books know: the stage of its life, when it was bought and from whom, what it cost
and on which cost centre, until when the warranty runs, when it is planned to be replaced, and when and how it was disposed of. All of it is
entered by people (the asset page, a bulk edit in Central); nothing is read from devices.

  stages   ordered -> in_stock -> deployed -> in_repair -> retired -> disposed  (an empty stage reads as deployed - every asset found on the
           network is in use; "retired" is what the inventory state "decommissioned" (3.76) means, and setting one sets the other)
  history  every change of these fields goes to asset_history (who / when / from what to what), like the identity fields of 3.74
  alerts   itam.warranty_ending - the warranty ends within WARRANTY_WARN_DAYS (low); itam.replace_due - the planned replacement date has passed
           (low). Neither for assets that are retired or disposed. Checked every hour (services/forecasts.py's loop).
"""
import re
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, Asset

STAGES = ("ordered", "in_stock", "deployed", "in_repair", "retired", "disposed")
DISPOSAL = ("recycled", "sold", "donated", "returned", "destroyed", "lost", "other")
FIELDS = ("lifecycle_stage", "purchased_at", "warranty_until", "replace_at", "disposed_at", "disposal_method", "cost", "currency", "supplier",
          "invoice_no", "cost_center", "asset_tag")
_DATES = ("purchased_at", "warranty_until", "replace_at", "disposed_at")
_TEXT = {"supplier": 120, "invoice_no": 60, "cost_center": 60, "asset_tag": 40}
WARRANTY_WARN_DAYS = 30
_OUT = ("retired", "disposed")


def _d(v) -> Optional[date]:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v).strip()[:10])
    except ValueError:
        raise ValueError(f"not a date (YYYY-MM-DD): {v!r}")


def stage_of(a: Asset) -> str:
    return a.lifecycle_stage or ("retired" if a.state == "decommissioned" else "deployed")


def clean(fields: Dict, current: Optional[Asset] = None) -> Dict:
    """The ITAM fields of an edit, validated: {column: value}. Raises ValueError with what is wrong."""
    out: Dict = {}
    for k, v in (fields or {}).items():
        if k not in FIELDS:
            continue
        if k == "lifecycle_stage":
            v = (str(v or "").strip() or None)
            if v is not None and v not in STAGES:
                raise ValueError(f"lifecycle_stage: one of {', '.join(STAGES)}")
            out[k] = v
        elif k in _DATES:
            out[k] = _d(v)
        elif k == "disposal_method":
            v = (str(v or "").strip() or None)
            if v is not None and v not in DISPOSAL:
                raise ValueError(f"disposal_method: one of {', '.join(DISPOSAL)}")
            out[k] = v
        elif k == "cost":
            if v in (None, ""):
                out[k] = None
            else:
                try:
                    c = round(float(str(v).replace(",", ".").replace(" ", "")), 2)
                except ValueError:
                    raise ValueError("cost: a number")
                if c < 0 or c > 1e9:
                    raise ValueError("cost: 0 or more")
                out[k] = c
        elif k == "currency":
            v = str(v or "").strip().upper()
            if v and not re.fullmatch(r"[A-Z]{3}", v):
                raise ValueError("currency: a 3-letter code like PLN or EUR")
            out[k] = v or None
        else:
            out[k] = " ".join(str(v or "").split())[:_TEXT[k]] or None
    stage = out.get("lifecycle_stage", current.lifecycle_stage if current is not None else None)
    if stage == "disposed":
        if not out.get("disposed_at", current.disposed_at.date() if current is not None and current.disposed_at else None):
            raise ValueError("a disposed asset needs the date of its disposal")
        if not out.get("disposal_method", current.disposal_method if current is not None else None):
            raise ValueError("a disposed asset needs the way it was disposed of")
    pa = out.get("purchased_at", current.purchased_at.date() if current is not None and current.purchased_at else None)
    wu = out.get("warranty_until", current.warranty_until.date() if current is not None and current.warranty_until else None)
    if pa and wu and wu < pa:
        raise ValueError("the warranty cannot end before the purchase")
    return out


def apply(db, a: Asset, fields: Dict, who: str = "operator") -> int:
    """Validates and sets the ITAM fields on `a` (the caller commits), with the history and the inventory state kept in step. Returns how many
    fields changed."""
    from services import identity
    vals = clean(fields, a)
    if "asset_tag" in vals and vals["asset_tag"]:
        dup = db.execute(select(Asset.id).where(Asset.asset_tag == vals["asset_tag"], Asset.id != a.id)).first()
        if dup:
            raise ValueError(f"asset tag {vals['asset_tag']} is already used by another asset")
    n = 0
    for k, v in vals.items():
        if k in _DATES:
            v = datetime(v.year, v.month, v.day) if v else None
        old = getattr(a, k)
        if (old.date() if isinstance(old, datetime) else old) == (v.date() if isinstance(v, datetime) else v):
            continue
        identity.history(db, a.id, k, old.date().isoformat() if isinstance(old, datetime) else old,
                         v.date().isoformat() if isinstance(v, datetime) else v, f"itam: {who}"[:80])
        setattr(a, k, v)
        n += 1
    if "lifecycle_stage" in vals:                       # the inventory state follows: retired <-> decommissioned (3.76)
        if vals["lifecycle_stage"] == "retired" and a.state != "decommissioned":
            a.state, a.state_since = "decommissioned", datetime.utcnow()
        elif vals["lifecycle_stage"] in ("deployed", "in_repair", "in_stock", "ordered") and a.state == "decommissioned":
            a.state, a.state_since = None, datetime.utcnow()
    return n


def as_dict(a: Asset) -> Dict:
    def iso(d):
        return d.date().isoformat() if d else None
    today = datetime.utcnow().date()
    wu = a.warranty_until.date() if a.warranty_until else None
    return {"lifecycle_stage": stage_of(a), "stage_set": bool(a.lifecycle_stage), "purchased_at": iso(a.purchased_at), "warranty_until": iso(a.warranty_until),
            "replace_at": iso(a.replace_at), "disposed_at": iso(a.disposed_at), "disposal_method": a.disposal_method, "cost": a.cost, "currency": a.currency,
            "supplier": a.supplier, "invoice_no": a.invoice_no, "cost_center": a.cost_center, "asset_tag": a.asset_tag,
            "warranty_days": (wu - today).days if wu else None,
            "age_years": round((today - a.purchased_at.date()).days / 365.25, 1) if a.purchased_at else None}


def check(now: Optional[datetime] = None) -> Dict[str, int]:
    """Raises / closes itam.warranty_ending and itam.replace_due."""
    from services import soc
    now = now or datetime.utcnow()
    today = now.date()
    counts = {"warranty_ending": 0, "replace_due": 0}
    with SessionLocal() as db:
        rows = [(a.id, a.name or a.ip or a.key, stage_of(a), a.warranty_until, a.replace_at, a.state)
                for a in db.execute(select(Asset).where((Asset.warranty_until.is_not(None)) | (Asset.replace_at.is_not(None)))).scalars().all()]
    for aid, name, stage, wu, ra, state in rows:
        live = stage not in _OUT and state not in ("ignore", "replaced_by")
        days = (wu.date() - today).days if wu else None
        if live and days is not None and 0 <= days <= WARRANTY_WARN_DAYS:
            soc.raise_alert(rule="itam.warranty_ending", device=name, title="Warranty ending", severity="low", category="resource", fp_detail=str(aid),
                            detail={"message": f"{name}: the warranty ends on {wu.date().isoformat()} (in {days} days)", "description": "warranty"},
                            asset_id=aid, count=0, source="rules", now=now)
            counts["warranty_ending"] += 1
        else:
            soc.resolve(rule="itam.warranty_ending", device=name, fp_detail=str(aid), now=now)
        if live and ra and ra.date() <= today:
            soc.raise_alert(rule="itam.replace_due", device=name, title="Planned replacement due", severity="low", category="resource", fp_detail=str(aid),
                            detail={"message": f"{name}: planned to be replaced on {ra.date().isoformat()}", "description": "replacement"},
                            asset_id=aid, count=0, source="rules", now=now)
            counts["replace_due"] += 1
        else:
            soc.resolve(rule="itam.replace_due", device=name, fp_detail=str(aid), now=now)
    return counts


def summary(now: Optional[datetime] = None) -> Dict:
    """Counts per stage, warranties ending within 30 / ended, replacements due, and the purchase cost per currency (of the assets not disposed)."""
    now = now or datetime.utcnow()
    today = now.date()
    stages = {s: 0 for s in STAGES}
    cost: Dict[str, float] = {}
    w30 = w_out = due = with_data = 0
    with SessionLocal() as db:
        for a in db.execute(select(Asset)).scalars().all():
            st = stage_of(a)
            if a.state == "ignore":
                continue
            stages[st] += 1
            if any(getattr(a, f) is not None for f in ("purchased_at", "warranty_until", "cost", "supplier", "asset_tag", "lifecycle_stage")):
                with_data += 1
            if st in _OUT:
                if st == "retired" and a.cost:
                    cost[a.currency or "?"] = round(cost.get(a.currency or "?", 0) + a.cost, 2)
                continue
            if a.cost:
                cost[a.currency or "?"] = round(cost.get(a.currency or "?", 0) + a.cost, 2)
            if a.warranty_until:
                d = (a.warranty_until.date() - today).days
                if d < 0:
                    w_out += 1
                elif d <= WARRANTY_WARN_DAYS:
                    w30 += 1
            if a.replace_at and a.replace_at.date() <= today:
                due += 1
    return {"stages": stages, "warranty_30d": w30, "warranty_ended": w_out, "replace_due": due, "cost": cost, "with_data": with_data}


def forecast_items(now: Optional[datetime] = None, horizon: int = 90) -> List[Dict]:
    """Warranties ending and planned replacements within the horizon, for the forecasts view (services/forecasts.py)."""
    now = now or datetime.utcnow()
    out = []
    with SessionLocal() as db:
        for a in db.execute(select(Asset).where((Asset.warranty_until.is_not(None)) | (Asset.replace_at.is_not(None)))).scalars().all():
            if stage_of(a) in _OUT or a.state in ("ignore", "replaced_by"):
                continue
            name = a.name or a.ip or a.key
            for kind, d in (("warranty", a.warranty_until), ("replacement", a.replace_at)):
                if d is None:
                    continue
                days = round((d - now).total_seconds() / 86400, 1)
                if days <= horizon and days >= -30:
                    out.append({"kind": kind, "key": f"{kind}:{a.id}", "name": name, "where": name, "what": a.model or a.asset_tag, "asset_id": a.id,
                                "unit": None, "value": None, "per_day": None, "days": days, "date": d.isoformat() + "Z"})
    return out
