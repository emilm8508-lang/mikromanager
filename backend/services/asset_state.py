"""
Entries of devices that are gone (3.76, round 3 stage C of docs/plan-runda-3.md).

An entry whose address has had no sign of life for REMOVED_AFTER_DAYS (7 by default, data/asset_state.json) - no ARP entry, no MAC in
a bridge table, no bound DHCP lease, no ping or port answer, no successful check of a managed host - is "probably_removed":
  - its "not answering" alerts are closed and one low reminder "confirm the removal" is raised instead;
  - its vulnerabilities do not count in the risk;
  - the agent stops probing it (availability, TLS, coverage), except a ping once an hour - one answer brings it back.
Seen at sanmed: "R2-ĄP1" at 192.168.2.94 - nothing at the address any more, yet a "Device not answering" alert, an anomaly with 153
repeats and the agent's tries on about 30 ports.

Manual states (asset page, Central): decommissioned, replaced_by (with the asset that replaced it), ignore. Only deleting an entry by hand
removes its data; every state keeps the history.
"""
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Set

from sqlalchemy import select

from models.database import SessionLocal, Asset, SocAlert

REMOVED_AFTER_DAYS = 7
RECHECK_SEC = 3600                       # a probably-removed address is pinged once an hour
MANUAL = ("decommissioned", "replaced_by", "ignore")
INACTIVE = ("probably_removed",) + MANUAL
_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "asset_state.json")


def removed_after_days() -> int:
    try:
        with open(_PATH, encoding="utf-8") as f:
            v = int(json.load(f).get("removed_after_days", REMOVED_AFTER_DAYS))
            return v if 1 <= v <= 365 else REMOVED_AFTER_DAYS
    except (OSError, ValueError, TypeError, AttributeError):
        return REMOVED_AFTER_DAYS


def evaluate(db, a: Asset, alive_at: Optional[datetime], now: datetime, after: Optional[list] = None) -> Optional[str]:
    """Called for every saved entry (services/assets._save) with the newest sign of life the sources gave this time. Returns the change
    made ("probably_removed" / "back"), or None. The alerts it raises / closes go to `after` (run with run_after() once the caller has
    committed - a second writer inside the caller's transaction would lock SQLite); without `after` they run at once."""
    from services import identity
    if alive_at and (a.alive_at is None or alive_at > a.alive_at):
        a.alive_at = alive_at
    if a.state in MANUAL:
        return None
    fresh = a.alive_at is not None and a.alive_at >= now - timedelta(days=removed_after_days())
    if a.state == "probably_removed" and fresh:
        a.state, a.state_since = None, now
        identity.history(db, a.id, "state", "probably_removed", "in use", "sign of life", now)
        _later(after, ("resolve", a.id, a.name or a.ip, a.ip))
        return "back"
    if a.state is None and not fresh and a.alive_at is not None:
        a.state, a.state_since = "probably_removed", now
        identity.history(db, a.id, "state", "in use", "probably_removed", f"no sign of life for {removed_after_days()} days", now)
        _close_down_alerts(db, a, now)
        if a.asset_type in ("network", "server", "virtual") or a.role == "server" or a.criticality:
            _later(after, ("remind", a.id, a.name or a.ip, a.ip))       # a reminder only for what was watched (not every phone that left)
        return "probably_removed"
    return None


def _close_down_alerts(db, a: Asset, now: datetime) -> int:
    from services import soc
    n = 0
    for al in db.execute(select(SocAlert).where(SocAlert.status.in_(soc.OPEN), SocAlert.category == "availability",
                                                (SocAlert.asset_id == a.id) | (SocAlert.ip == a.ip))).scalars().all():
        al.status, al.closed_at, al.closed_by = "closed", now, "auto: probably_removed"
        n += 1
    return n


def _later(after: Optional[list], job: tuple) -> None:
    if after is None:
        run_after([job])
    else:
        after.append(job)


def run_after(jobs: list) -> None:
    """The reminders raised / closed by evaluate(), after the inventory's transaction is committed."""
    from services import soc
    for kind, aid, name, ip in jobs:
        try:
            if kind == "remind":
                soc.raise_alert(rule="asset.confirm_removal", device=name, ip=ip, title="Device probably removed - confirm", severity="low",
                                category="system", fp_detail=str(aid), count=0, asset_id=aid,
                                detail={"message": f"{name}: no ARP entry, lease, ping or check for {removed_after_days()} days",
                                        "advice": "mark it decommissioned or replaced (asset page / Central), or delete it; one sign of life brings it back"})
            else:
                soc.resolve(rule="asset.confirm_removal", device=name, fp_detail=str(aid))
        except Exception as e:
            print(f"[asset_state] {kind} {name}: {type(e).__name__}: {e}")


def set_state(asset_id: int, state: Optional[str], replaced_by: Optional[int] = None, who: str = "?") -> dict:
    """A manual state: decommissioned / replaced_by (with the replacing asset) / ignore, or None (in use again)."""
    from services import identity
    if state not in (None, "") + MANUAL:
        raise ValueError("state is decommissioned, replaced_by, ignore or empty")
    now = datetime.utcnow()
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if a is None:
            raise ValueError("asset not found")
        if state == "replaced_by":
            if not replaced_by or replaced_by == asset_id or db.get(Asset, replaced_by) is None:
                raise ValueError("replaced_by needs the asset that replaced it")
        old = a.state or "in use"
        a.state, a.state_since = (state or None), now
        a.replaced_by = replaced_by if state == "replaced_by" else None
        identity.history(db, a.id, "state", old, state or "in use", f"set by {who}", now)
        if state:
            _close_down_alerts(db, a, now)
        db.commit()
        name = a.name or a.ip
    if state:
        from services import soc
        soc.resolve(rule="asset.confirm_removal", device=name, fp_detail=str(asset_id))
    return {"ok": True, "state": state or None}


def inactive_ips() -> Set[str]:
    """The addresses of entries that are probably removed or set aside: not probed, scanned or alerted on."""
    with SessionLocal() as db:
        return {ip for (ip,) in db.execute(select(Asset.ip).where(Asset.state.in_(INACTIVE), Asset.ip.is_not(None))).all()}


def inactive_ids() -> Set[int]:
    with SessionLocal() as db:
        return {i for (i,) in db.execute(select(Asset.id).where(Asset.state.in_(INACTIVE))).all()}
