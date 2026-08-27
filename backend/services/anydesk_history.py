"""
Local AnyDesk connection history, reconstructed from trace files already
written by AnyDesk itself on this machine — NOT the AnyDesk REST API. That
API needs a Standard-or-above license; this user's account is Solo/Lite
(confirmed directly with them), so it isn't available. The AnyDesk portal
(my.anydesk.com) itself only shows the last 7 sessions, which is the
problem this module exists to solve: build a durable local record instead.

Two different local files are combined, because neither alone has both
"long retention" and "session duration":

- connection_trace.txt (default: %ProgramData%\\AnyDesk\\connection_trace.txt)
  — one line per connection attempt, MINUTE precision, no end time, but
  keeps MONTHS of history (confirmed on this user's machine: ~8 months in
  a 135 KB file — AnyDesk's own retention here is far longer than the
  verbose trace log below). This is the durable long-term source, and the
  only source for auth_method ("User"/"Passwd"/"Token") and rejections.
- ad_svc.trace / ad.trace (verbose service log, default under
  %ProgramData%\\AnyDesk\\ and %APPDATA%\\AnyDesk\\) — has exact
  (millisecond) "Received outgoing connection request for address X"
  .. "Stop monitoring X" pairs, giving a real duration, but only retains a
  few days before rotating out on this machine.

sync() merges both: every session starts from connection_trace.txt
(minute precision, no duration); if a matching ad_svc.trace pair is still
present for it (same cid, same minute), the row is upgraded in place to
millisecond-precision start + real end/duration. Re-running sync() is
idempotent and self-healing — a session synced today with only
connection_trace.txt data can still get its duration backfilled by a
later sync() run before ad_svc.trace rotates it away, because matching is
done against the already-stored row (by cid + minute), not by re-inserting.

Deliberately NOT wired into main.py's lifespan/background loop: this is a
personal tool for the one control machine the user runs AnyDesk from to
reach clients, not something every tenant agent has any use for (most
don't have AnyDesk installed at all). Sync only ever runs on demand, via
the API a human triggers from the "AnyDesk" tab.
"""
import os
import re
from datetime import datetime, timedelta
from typing import Optional

from collections import defaultdict

from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError

from models.database import SessionLocal, AnydeskSession, AnydeskCidLabel

CATEGORIES = {"billable", "training", "internal"}

# Overridable via env because AnyDesk's install mode (per-machine service vs
# per-user "portable") changes where these files live — the two ProgramData
# defaults match a standard Windows service install; APPDATA is the
# per-user frontend log, kept as a fallback for the verbose trace only.
CONNECTION_TRACE_PATH = os.environ.get(
    "MIKROTIK_ANYDESK_CONNECTION_TRACE_PATH",
    os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AnyDesk", "connection_trace.txt"),
)
_SERVICE_TRACE_CANDIDATES = [
    os.environ.get("MIKROTIK_ANYDESK_SERVICE_TRACE_PATH", "").strip(),
    os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AnyDesk", "ad_svc.trace"),
    os.path.join(os.environ.get("APPDATA", ""), "AnyDesk", "ad.trace"),
]

_CONN_LINE_RE = re.compile(
    r'^(Outgoing|Incoming)\s+(\d{4}-\d{2}-\d{2}),\s*(\d{2}:\d{2})\s+(\S+)\s+(\d+)\s+(\d+)\s*$'
)
_TRACE_TS_RE = re.compile(r'^\s*\S+\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\.\d+')
_TRACE_START_RE = re.compile(r'Received outgoing connection request for address (\d+)')
_TRACE_STOP_RE = re.compile(r'Stop monitoring (\d+)\.')


def _service_trace_path() -> Optional[str]:
    for p in _SERVICE_TRACE_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return None


def status() -> dict:
    svc_path = _service_trace_path()
    return {
        "connection_trace_path": CONNECTION_TRACE_PATH,
        "connection_trace_found": os.path.isfile(CONNECTION_TRACE_PATH),
        "service_trace_path": svc_path,
        "service_trace_found": svc_path is not None,
    }


def _parse_connection_trace(path: str) -> list[dict]:
    """Returns [{cid, started_at (minute precision), auth_method, rejected}].
    Skips any line that doesn't match the expected column layout instead of
    raising — a partial/locked file (AnyDesk still writing to it) must never
    abort the whole sync."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _CONN_LINE_RE.match(line.strip())
                if not m:
                    continue
                direction, date_s, time_s, method, cid, _cid2 = m.groups()
                if direction != "Outgoing":
                    continue  # incoming (someone else connecting to US) is out of scope here
                try:
                    started_at = datetime.strptime(f"{date_s} {time_s}", "%Y-%m-%d %H:%M")
                except ValueError:
                    continue
                rejected = method == "REJECTED"
                out.append({
                    "cid": cid,
                    "started_at": started_at,
                    "auth_method": None if rejected else method,
                    "rejected": rejected,
                })
    except OSError:
        pass
    return out


def _parse_service_trace(path: str) -> list[dict]:
    """Returns [{cid, started_at (second precision), ended_at, duration_sec}]
    by pairing "Received outgoing connection request" with the next "Stop
    monitoring" for the same cid. A start with no matching stop by end of
    file (session still open, or log rotated mid-session) is dropped rather
    than emitted with a guessed/zero duration."""
    out = []
    open_starts: dict[str, datetime] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ts_m = _TRACE_TS_RE.match(line)
                if not ts_m:
                    continue
                start_m = _TRACE_START_RE.search(line)
                if start_m:
                    try:
                        ts = datetime.strptime(f"{ts_m.group(1)} {ts_m.group(2)}", "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue
                    open_starts[start_m.group(1)] = ts
                    continue
                stop_m = _TRACE_STOP_RE.search(line)
                if stop_m:
                    cid = stop_m.group(1)
                    start_ts = open_starts.pop(cid, None)
                    if start_ts is None:
                        continue
                    try:
                        end_ts = datetime.strptime(f"{ts_m.group(1)} {ts_m.group(2)}", "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue
                    duration = int((end_ts - start_ts).total_seconds())
                    if duration < 0:
                        continue
                    out.append({"cid": cid, "started_at": start_ts, "ended_at": end_ts, "duration_sec": duration})
    except OSError:
        pass
    return out


def _upsert_session(db, cid: str, started_at: datetime, ended_at=None,
                     duration_sec=None, auth_method=None, rejected=False,
                     source="connection_trace") -> str:
    """Insert, or upgrade-in-place a row already synced for the same
    (cid, minute) — this is what makes sync() idempotent AND lets a
    duration discovered later (while ad_svc.trace still has it) backfill a
    row that was first synced from connection_trace.txt alone."""
    minute = started_at.replace(second=0, microsecond=0)
    existing = db.execute(
        select(AnydeskSession).where(
            AnydeskSession.cid == cid,
            AnydeskSession.started_at >= minute,
            AnydeskSession.started_at < minute + timedelta(minutes=1),
        )
    ).scalars().first()
    if existing:
        if started_at != minute and started_at != existing.started_at:
            existing.started_at = started_at  # upgrade to ms/second precision
        if ended_at is not None:
            existing.ended_at = ended_at
        if duration_sec is not None:
            existing.duration_sec = duration_sec
        if auth_method is not None:
            existing.auth_method = auth_method
        if rejected:
            existing.rejected = True
        if source != "connection_trace":
            existing.source = "merged" if existing.source != source else existing.source
        existing.synced_at = datetime.utcnow()
        return "updated"
    row = AnydeskSession(cid=cid, started_at=started_at, ended_at=ended_at,
                          duration_sec=duration_sec, auth_method=auth_method,
                          rejected=rejected, source=source)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return "skipped"
    return "inserted"


def sync() -> dict:
    conn_events = _parse_connection_trace(CONNECTION_TRACE_PATH)
    svc_path = _service_trace_path()
    svc_events = _parse_service_trace(svc_path) if svc_path else []

    # Index svc_events by (cid, minute) for matching against connection_trace
    # rows; FIFO per key in case the same cid reconnected more than once
    # within the same minute.
    svc_by_key: dict[tuple, list[dict]] = {}
    for ev in svc_events:
        key = (ev["cid"], ev["started_at"].replace(second=0, microsecond=0))
        svc_by_key.setdefault(key, []).append(ev)

    inserted = updated = skipped = 0
    with SessionLocal() as db:
        for ev in conn_events:
            key = (ev["cid"], ev["started_at"])
            match_list = svc_by_key.get(key)
            match = match_list.pop(0) if match_list else None
            if match:
                result = _upsert_session(
                    db, ev["cid"], match["started_at"], ended_at=match["ended_at"],
                    duration_sec=match["duration_sec"], auth_method=ev["auth_method"],
                    rejected=ev["rejected"], source="merged",
                )
            else:
                result = _upsert_session(
                    db, ev["cid"], ev["started_at"], auth_method=ev["auth_method"],
                    rejected=ev["rejected"], source="connection_trace",
                )
            if result == "inserted":
                inserted += 1
            elif result == "updated":
                updated += 1
            else:
                skipped += 1

        # Any ad_svc.trace pair left unmatched (connection_trace.txt line
        # missing/unparsed for it) still becomes a session — better a row
        # with no auth_method than silently losing a known session.
        for remaining in svc_by_key.values():
            for ev in remaining:
                result = _upsert_session(
                    db, ev["cid"], ev["started_at"], ended_at=ev["ended_at"],
                    duration_sec=ev["duration_sec"], source="ad_svc_trace",
                )
                if result == "inserted":
                    inserted += 1
                elif result == "updated":
                    updated += 1
                else:
                    skipped += 1

        db.commit()

    return {
        "inserted": inserted, "updated": updated, "skipped": skipped,
        "connection_trace_lines": len(conn_events), "service_trace_pairs": len(svc_events),
        **status(),
    }


def list_sessions(cid: Optional[str] = None, q: Optional[str] = None,
                   from_date: Optional[str] = None, to_date: Optional[str] = None,
                   limit: int = 1000) -> list[dict]:
    with SessionLocal() as db:
        labels = {row.cid: row.label for row in db.execute(select(AnydeskCidLabel)).scalars().all()}
        stmt = select(AnydeskSession)
        if cid:
            stmt = stmt.where(AnydeskSession.cid == cid)
        if from_date:
            stmt = stmt.where(AnydeskSession.started_at >= datetime.strptime(from_date, "%Y-%m-%d"))
        if to_date:
            stmt = stmt.where(AnydeskSession.started_at < datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1))
        stmt = stmt.order_by(AnydeskSession.started_at.desc()).limit(limit)
        rows = db.execute(stmt).scalars().all()

    ql = q.strip().lower() if q else None
    out = []
    for r in rows:
        label = labels.get(r.cid)
        if ql and ql not in r.cid.lower() and (not label or ql not in label.lower()):
            continue
        out.append({
            "id": r.id, "cid": r.cid, "label": label,
            "started_at": r.started_at.isoformat(),
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "duration_sec": r.duration_sec,
            "auth_method": r.auth_method, "rejected": r.rejected, "source": r.source,
            "category": r.category, "note": r.note,
        })
    return out


def classify(session_id: int, category: Optional[str], note: Optional[str] = None) -> dict:
    if category is not None and category not in CATEGORIES:
        raise ValueError(f"invalid category: {category!r}")
    with SessionLocal() as db:
        row = db.get(AnydeskSession, session_id)
        if not row:
            raise ValueError("session not found")
        row.category = category
        if note is not None:
            row.note = note
        db.commit()
        db.refresh(row)
        label = None
        lr = db.get(AnydeskCidLabel, row.cid)
        if lr:
            label = lr.label
        return {
            "id": row.id, "cid": row.cid, "label": label,
            "started_at": row.started_at.isoformat(),
            "ended_at": row.ended_at.isoformat() if row.ended_at else None,
            "duration_sec": row.duration_sec,
            "auth_method": row.auth_method, "rejected": row.rejected, "source": row.source,
            "category": row.category, "note": row.note,
        }


def summary(from_date: Optional[str] = None, to_date: Optional[str] = None) -> list[dict]:
    """One row per (client, month): total minutes rounded up to whole
    minutes per session (never truncated to zero for a short-but-real
    session — mirrors how AnyDesk-based billing is normally rounded), split
    across billable/training/internal/unclassified, plus a session count.
    Rejected connection attempts and sessions with no known duration
    (connection_trace.txt-only, ad_svc.trace already rotated past them)
    contribute to session_count for visibility but 0 minutes — there is no
    honest way to guess how long they lasted.

    "client" groups by AnydeskCidLabel.label when set, else falls back to
    the raw cid — no separate multi-cid-per-client concept yet; give
    several cids matching label text if you want them to roll up together."""
    with SessionLocal() as db:
        labels = {row.cid: row.label for row in db.execute(select(AnydeskCidLabel)).scalars().all()}
        stmt = select(AnydeskSession).where(AnydeskSession.rejected == False)  # noqa: E712
        if from_date:
            stmt = stmt.where(AnydeskSession.started_at >= datetime.strptime(from_date, "%Y-%m-%d"))
        if to_date:
            stmt = stmt.where(AnydeskSession.started_at < datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1))
        rows = db.execute(stmt).scalars().all()

    agg: dict[tuple, dict] = defaultdict(lambda: {
        "billable_minutes": 0, "training_minutes": 0, "internal_minutes": 0,
        "unclassified_minutes": 0, "session_count": 0,
    })
    for r in rows:
        client = labels.get(r.cid) or r.cid
        month = r.started_at.strftime("%Y-%m")
        entry = agg[(client, month)]
        entry["session_count"] += 1
        if r.duration_sec:
            minutes = max(1, -(-r.duration_sec // 60))  # ceil, min 1 minute for any real connection
            key = f"{r.category}_minutes" if r.category in CATEGORIES else "unclassified_minutes"
            entry[key] += minutes

    out = [{"client": client, "month": month, **vals} for (client, month), vals in agg.items()]
    out.sort(key=lambda x: (x["client"], x["month"]))
    return out


def list_labels() -> list[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(AnydeskCidLabel).order_by(AnydeskCidLabel.label)).scalars().all()
        return [{"cid": r.cid, "label": r.label} for r in rows]


def set_label(cid: str, label: str) -> dict:
    cid = cid.strip()
    label = label.strip()
    with SessionLocal() as db:
        existing = db.get(AnydeskCidLabel, cid)
        if existing:
            existing.label = label
            existing.updated_at = datetime.utcnow()
        else:
            db.add(AnydeskCidLabel(cid=cid, label=label))
        db.commit()
    return {"cid": cid, "label": label}


def delete_label(cid: str) -> dict:
    with SessionLocal() as db:
        db.execute(delete(AnydeskCidLabel).where(AnydeskCidLabel.cid == cid))
        db.commit()
    return {"deleted": cid}
