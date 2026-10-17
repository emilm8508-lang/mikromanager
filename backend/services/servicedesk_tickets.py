"""Outages -> ManageEngine ServiceDesk Plus tickets, opened and closed by the agent itself.

The alert events the agent already produces come in pairs - "it went down" / "it came back": the WAN interface of a router
(wan_down / wan_up), a watched Windows / Linux service (host_service_down / host_service_up) and a Dell server's iDRAC
(idrac_unreachable / idrac_reachable). For the rules the operator switched on (services/servicedesk_client.py settings):

  down  -> a ticket is planned; it is created only when the outage has lasted `delay_min` minutes (so a flapping link does not litter the
           help desk). An outage that ends before that never gets a ticket.
  up    -> the ticket is resolved and closed with a text saying how long it lasted ("Łączność wróciła po 1 h 4 min (awaria od ... do ...)").

The state of every outage lives in the database (ServiceDeskTicket), so a restart of the agent loses nothing, a failed call to the help
desk is retried with a back-off, and one outage never makes two tickets. The help desk is on the client's own network, which is why this runs
in the agent and not in Central."""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import select

from models.database import SessionLocal, ServiceDeskTicket
from services import servicedesk_client as sd

TICK_SEC = 30
# rule -> (event that opens, event that closes)
RULES: Dict[str, tuple] = {
    "wan": ("wan_down", "wan_up"),
    "service": ("host_service_down", "host_service_up"),
    "idrac": ("idrac_unreachable", "idrac_reachable"),
}
_OPEN_STATES = ("pending", "open", "recovering")
_lock = asyncio.Lock()


def _parse(v) -> datetime:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()


def _local(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")


def fmt_duration(sec: float) -> str:
    sec = max(0, int(sec))
    if sec < 60:
        return f"{sec} s"
    m = sec // 60
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} h {m} min" if m else f"{h} h"
    d, h = divmod(h, 24)
    return f"{d} d {h} h" if h else f"{d} d"


def _describe(rule: str, ev: dict) -> Optional[dict]:
    """{"key", "what", "subject_what", "detail"} of the thing an event is about, or None when the event lacks what identifies it."""
    if rule == "wan":
        dev, iface = ev.get("device_name"), ev.get("iface")
        if ev.get("device_id") is None or not iface:
            return None
        return {"key": f"{ev['device_id']}:{iface}", "what": f"Łącze WAN {dev} ({iface})",
                "detail": f"Interfejs WAN {iface} na routerze {dev} przestał działać."}
    if rule == "service":
        host, svc = ev.get("device_name"), ev.get("service") or ev.get("service_name")
        if not host or not svc:
            return None
        return {"key": f"{ev.get('platform')}:{host}:{ev.get('service_name') or svc}", "what": f"Usługa {svc} na {host}",
                "detail": f"Monitorowana usługa {svc} na hoście {host} ma stan inny niż oczekiwany ({ev.get('state') or '?'}, oczekiwano: {ev.get('expected') or '?'})."}
    if rule == "idrac":
        name = ev.get("server_name")
        if ev.get("server_id") is None:
            return None
        return {"key": str(ev["server_id"]), "what": f"iDRAC serwera {name}",
                "detail": f"Kontroler iDRAC serwera {name} jest niedostępny" + (f" ({ev['error']})." if ev.get("error") else ".")}
    return None


def process_events(events: List[dict], tenant: str = "") -> int:
    """Feeds the alert events of one uplink cycle into the outage state. Returns how many rows changed. Cheap and database-only."""
    if not sd.is_configured():
        return 0
    rules = sd._config["rules"]
    by_event = {}
    for rule, (down, up) in RULES.items():
        if rules.get(rule, {}).get("enabled"):
            by_event[down] = (rule, True)
            by_event[up] = (rule, False)
    changed = 0
    with SessionLocal() as db:
        for ev in events or []:
            hit = by_event.get(ev.get("type"))
            if not hit:
                continue
            rule, is_down = hit
            d = _describe(rule, ev)
            if not d:
                continue
            at = _parse(ev.get("detected_at"))
            row = db.execute(select(ServiceDeskTicket).where(ServiceDeskTicket.rule == rule, ServiceDeskTicket.key == d["key"],
                                                              ServiceDeskTicket.state.in_(_OPEN_STATES))).scalars().first()
            if is_down:
                if row is None:
                    delay = int(rules[rule].get("delay_min") or 0)
                    db.add(ServiceDeskTicket(
                        rule=rule, key=d["key"], state="pending", what=d["what"], down_at=at, open_after=at + timedelta(minutes=delay),
                        subject=f"Awaria: {d['what']}" + (f" - {tenant}" if tenant else ""),
                        description=f"{d['detail']}\nWykryto automatycznie przez MikroManager{(' (klient ' + tenant + ')') if tenant else ''}.\n"
                                    f"Początek awarii: {_local(at)}.\nZgłoszenie zostanie rozwiązane i zamknięte automatycznie, gdy awaria ustąpi."))
                    db.flush()                                          # a second event of the same outage in this batch must find the row
                    changed += 1
                elif row.state == "recovering":
                    row.state, row.up_at = "open", None                 # it went down again before the ticket was closed: the same ticket stays
                    changed += 1
            elif row is not None and row.state in ("pending", "open"):
                row.up_at = at
                row.state = "cancelled" if row.state == "pending" else "recovering"     # before the delay: no ticket was ever made
                changed += 1
        db.commit()
    return changed


def _ticket_fields() -> dict:
    t = sd._config["ticket"]
    return {"request_type": t.get("request_type") or "Incident", "priority": t.get("priority") or None,
            "urgency": t.get("urgency") or None, "category": t.get("category") or None}


def _closing_text(row: ServiceDeskTicket) -> str:
    dur = fmt_duration((row.up_at - row.down_at).total_seconds())
    back = {"wan": "Łączność wróciła", "service": "Usługa działa ponownie", "idrac": "Kontroler iDRAC jest ponownie dostępny"}.get(row.rule, "Problem ustąpił")
    return f"{row.what}: {back} po {dur} (awaria od {_local(row.down_at)} do {_local(row.up_at)}). Zamknięte automatycznie przez MikroManager."


def _backoff(row: ServiceDeskTicket, now: datetime, err: str) -> None:
    row.attempts = (row.attempts or 0) + 1
    row.last_error = str(err)[:500]
    row.open_after = now + timedelta(minutes=min(30, 2 ** min(row.attempts, 5)))


async def tick() -> dict:
    """Creates the tickets that are due and closes the ones whose outage ended. Safe to call at any time; one pass at a time."""
    if not sd.is_configured():
        return {"created": 0, "closed": 0}
    created = closed = 0
    async with _lock:
        now = datetime.utcnow()
        with SessionLocal() as db:
            due = db.execute(select(ServiceDeskTicket).where(ServiceDeskTicket.state.in_(("pending", "recovering")),
                                                             (ServiceDeskTicket.open_after.is_(None)) | (ServiceDeskTicket.open_after <= now))).scalars().all()
            for row in due:
                if row.state == "pending":
                    if not sd._config["rules"].get(row.rule, {}).get("enabled"):
                        row.state = "cancelled"                      # the rule was switched off while it waited
                        continue
                    r = await sd.create_ticket(row.subject or row.what or "MikroManager", row.description or "", **_ticket_fields())
                    if r.get("ok") and r.get("id"):
                        row.state, row.sdp_id, row.sdp_display_id, row.last_error = "open", str(r["id"]), str(r.get("display_id") or r["id"]), None
                        created += 1
                    else:
                        _backoff(row, now, r.get("error") or "the help desk did not create the ticket")
                elif row.state == "recovering":
                    text = _closing_text(row)
                    if sd._config["close_on_recovery"]:
                        r = await sd.close_ticket(row.sdp_id, text)
                    else:
                        n = await sd._call("POST", f"requests/{row.sdp_id}/notes", {"request_note": {"description": text, "show_to_requester": True, "notify_technician": False}})
                        r = {"ok": n["ok"], "closed": False, "error": n.get("error"), "steps": []}
                    if r["ok"]:
                        row.state, row.closed_at, row.last_error = "closed", datetime.utcnow(), None
                        row.note = text if r.get("closed") or not sd._config["close_on_recovery"] else f"{text} (zgłoszenie zostawione jako Resolved: {r.get('error') or 'zamknięcie odrzucone'})"
                        closed += 1
                    else:
                        _backoff(row, now, r.get("error") or "the help desk did not accept the closing")
            db.commit()
    return {"created": created, "closed": closed}


def list_tickets(limit: int = 50) -> List[dict]:
    with SessionLocal() as db:
        rows = db.execute(select(ServiceDeskTicket).order_by(ServiceDeskTicket.id.desc()).limit(max(1, min(limit, 200)))).scalars().all()
        return [{"id": r.id, "rule": r.rule, "state": r.state, "what": r.what, "subject": r.subject, "down_at": r.down_at.isoformat() + "Z",
                 "up_at": r.up_at.isoformat() + "Z" if r.up_at else None, "closed_at": r.closed_at.isoformat() + "Z" if r.closed_at else None,
                 "sdp_display_id": r.sdp_display_id, "attempts": r.attempts, "last_error": r.last_error, "note": r.note} for r in rows]


async def test_ticket() -> dict:
    """Makes a ticket and closes it again - proves, against this very help desk, that creating and closing work with the saved fields."""
    if not sd.is_configured():
        return {"ok": False, "error": "not configured"}
    c = await sd.create_ticket("[MikroManager] Zgłoszenie testowe - proszę zignorować",
                               "Test integracji MikroManager: zgłoszenie założone i od razu zamknięte automatycznie.", **_ticket_fields())
    if not c.get("ok"):
        return {"ok": False, "stage": "create", "error": c.get("error")}
    r = await sd.close_ticket(str(c["id"]), "Test integracji MikroManager zakończony - zgłoszenie zamknięte automatycznie.")
    return {"ok": r["ok"], "stage": "close", "created": c.get("display_id") or c.get("id"), "closed": r.get("closed"), "steps": r.get("steps"), "error": r.get("error")}


# ── loop ────────────────────────────────────────────────────────────────────

_task: Optional[asyncio.Task] = None


async def _loop():
    await asyncio.sleep(45)
    while True:
        try:
            r = await tick()
            if r["created"] or r["closed"]:
                print(f"[servicedesk_tickets] created {r['created']}, closed {r['closed']}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[servicedesk_tickets] error: {e}")
        await asyncio.sleep(TICK_SEC)


def start():
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())


def stop():
    global _task
    if _task and not _task.done():
        _task.cancel()
    _task = None
