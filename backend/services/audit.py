"""
Local, insert-only audit log — "who did what", tied to the acting user's
identity from the session (local emergency account or an OVH account).

Written for every mutating request that reaches a protected handler (see
main.py's audit middleware). No function here ever updates or deletes a
row. Each entry is also queued via services/activity.py, which the next
uplink cycle forwards into OVH's existing activity_log table — a copy that
has already left this machine before anyone here could tamper with it,
reusing the existing forwarding pipeline rather than adding new OVH schema.
"""
from typing import Optional

from models.database import AuditLog, SessionLocal
from services import activity


def record(*, username: str, role: str, source: str, method: str, path: str,
           status_code: int, ip: Optional[str] = None) -> None:
    try:
        with SessionLocal() as db:
            db.add(AuditLog(
                username=username, role=role, source=source,
                method=method, path=path, status_code=status_code, ip=ip,
            ))
            db.commit()
    except Exception as e:
        print(f"[audit] local record error: {e}")

    try:
        activity.record(
            "audit_action", username=username, role=role, source=source,
            method=method, path=path, status_code=status_code,
        )
    except Exception as e:
        print(f"[audit] queue error: {e}")
