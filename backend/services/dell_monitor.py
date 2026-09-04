"""
Dell server (iDRAC) health monitoring orchestration — ties DellServer rows
to whichever access method applies (services/idrac_client.py's Redfish
client over the network if idrac_ip is set, else services/dell_local.py's
WinRM-into-the-companion-Windows-host fallback), persists results, and
emits alert_events on a health transition — same self-dedup pattern as
services/resource_monitor.py/tunnel_monitor.py: state keyed by
(server_id, component) with the LAST known health, an event fires only on
an actual change (not every poll), and state is never pruned just because
one poll failed.

Runs on its own slow loop (DELL_CHECK_MIN, default 30 min) — like Linux/
Windows resource checks, both access paths here are non-trivial cost
(several Redfish round-trips, or a full WinRM session), not something to
run on the 2-minute snapshot cadence.
"""
import asyncio
import json
import os
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select

from models.database import (
    SessionLocal, DellServer, DellServerSelEntry, Credential, VulnHost, VulnService, WindowsHost,
)
from services.crypto import decrypt
from services import idrac_client
from services import dell_local
from services import windows_manage
from services import activity

DELL_CHECK_MIN = int(os.environ.get("MIKROTIK_DELL_CHECK_MIN", "30"))

_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "dell_state.json")

_loop_task: Optional[asyncio.Task] = None

# Redfish uses "https://ip:port" as a base URL — iDRAC's web UI is
# virtually always TLS-only.
_REDFISH_SCHEME = "https"


def _load_state() -> dict:
    if not os.path.exists(_STATE_PATH):
        return {}
    try:
        with open(_STATE_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
    try:
        with open(_STATE_PATH, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[dell_monitor] state persist error: {e}")


async def check_server(server_id: int) -> dict:
    """Runs one server's health check via whichever method(s) apply, and
    persists the result. Prefers the network Redfish path when idrac_ip is
    set (cheaper, doesn't depend on the companion host being reachable),
    falling back to the WinRM local path only if Redfish fails or isn't
    configured — mirrors every other "try the better method, fall back"
    pattern already in this codebase (REST→API→SNMP for Mikrotik, etc.)."""
    with SessionLocal() as db:
        server = db.get(DellServer, server_id)
        if not server:
            return {"ok": False, "error": "server not found"}
        idrac_ip, idrac_port = server.idrac_ip, server.idrac_port
        windows_host_id = server.windows_host_id
        credential_id = server.credential_id
        # Legacy rows predate the vendor column and were only ever
        # created by Dell-specific discovery/add flows — safe to treat
        # NULL as "dell" here (mirrors the DB migration's own backfill).
        vendor = server.vendor or "dell"

    result = None
    if idrac_ip:
        username = password = None
        if credential_id:
            with SessionLocal() as db:
                cred = db.get(Credential, credential_id)
                if cred:
                    try:
                        username, password = cred.username, decrypt(cred.password_enc)
                    except Exception:
                        username = password = None
        if not username:
            if vendor == "dell":
                # Dell's well-known factory default — offered so a freshly
                # discovered/added server is checkable immediately even
                # before the operator gets around to assigning a real
                # credential (the user explicitly asked for this).
                username, password = "root", "calvin"
            elif vendor == "fujitsu":
                # Fujitsu iRMC's well-known factory default (S4/S5) — same
                # "offer a default so a freshly discovered server is
                # checkable immediately" reasoning as Dell's root/calvin;
                # unverified against the user's actual iRMC firmware yet,
                # same caveat Dell's default had before real-world testing.
                username, password = "admin", "admin"
            # else (hp/lenovo/unknown): deliberately NO default attempted.
            # HP's iLO5+ generates a random per-unit password printed on
            # the server itself — there is no safe universal value to try,
            # and guessing risks tripping that vendor's account lockout.
        if username:
            base_url = f"{_REDFISH_SCHEME}://{idrac_ip}:{idrac_port}"
            try:
                health = await idrac_client.collect_health(base_url, username, password)
            except Exception as e:
                health = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            if health.get("ok"):
                result = {**health, "access_method": "redfish"}
            else:
                result = health  # keep the error around in case local fallback also fails
        else:
            result = {"ok": False, "error": f"brak przypisanego poświadczenia — ten producent "
                                             f"({vendor}) nie ma bezpiecznego domyślnego hasła, "
                                             f"przypisz własne w edycji serwera"}

    # Local WinRM fallback (iSM/RACADM/OMSA) is Dell-specific software —
    # never attempted for other vendors, where it would only waste a
    # round-trip and always report "not found" (that local path for
    # HP/Fujitsu/Lenovo isn't built yet — network Redfish only, for now).
    if (not result or not result.get("ok")) and windows_host_id and vendor == "dell":
        try:
            local_health = await dell_local.collect_local_health(windows_host_id)
        except Exception as e:
            local_health = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if local_health.get("ok"):
            result = local_health
        elif not result:
            result = local_health

    if not result:
        result = {"ok": False, "error": "neither idrac_ip nor a companion Windows host is configured"}

    now = datetime.utcnow()
    with SessionLocal() as db:
        server = db.get(DellServer, server_id)
        if not server:
            return {"ok": False, "error": "server not found"}
        server.last_check_at = now
        if result.get("ok"):
            server.last_status = "ok"
            server.last_error = None
            server.access_method = result.get("access_method")
            server.health_rollup = result.get("health_rollup")
            server.service_tag = result.get("service_tag") or server.service_tag
            server.model = result.get("model") or server.model
            server.bios_version = result.get("bios_version") or server.bios_version
            server.power_state = result.get("power_state") or server.power_state
            server.components_json = json.dumps(result.get("components") or {})
        else:
            server.last_status = "error"
            server.last_error = result.get("error")
        db.commit()

        if result.get("ok"):
            _persist_sel_entries(db, server_id, result.get("sel_entries") or [])
            db.commit()

    return result


def _persist_sel_entries(db, server_id: int, entries: list) -> None:
    for e in entries:
        logged_at = None
        if e.get("logged_at"):
            try:
                logged_at = datetime.fromisoformat(str(e["logged_at"]).replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                logged_at = None
        existing = db.execute(
            select(DellServerSelEntry).where(
                DellServerSelEntry.server_id == server_id,
                DellServerSelEntry.message == (e.get("message") or ""),
                DellServerSelEntry.logged_at == logged_at,
            )
        ).scalar_one_or_none()
        if existing:
            continue
        db.add(DellServerSelEntry(
            server_id=server_id, severity=e.get("severity"),
            message=e.get("message") or "", logged_at=logged_at,
        ))


_HEALTH_ORDER = {"Critical": 0, "Warning": 1, "OK": 2}


def _worse(a: Optional[str], b: Optional[str]) -> bool:
    """True if b is a genuine degradation from a (both known, b ranks
    worse) — used to decide whether a transition is alert-worthy."""
    if a not in _HEALTH_ORDER or b not in _HEALTH_ORDER:
        return False
    return _HEALTH_ORDER[b] < _HEALTH_ORDER[a]


async def collect_dell_events() -> List[dict]:
    """Called every snapshot cycle (~2 min) from uplink.py, same as
    resource_monitor.collect_resource_events() — cheap DB read + diff
    against last-known state, no new connections here. The actual
    (expensive) health check runs on its own slow loop below."""
    state = _load_state()
    events: List[dict] = []
    now_iso = datetime.utcnow().isoformat()

    with SessionLocal() as db:
        servers = db.execute(select(DellServer)).scalars().all()
        for s in servers:
            identity = s.name or s.service_tag or s.idrac_ip or f"dell-{s.id}"
            key = f"dell:{s.id}:health"
            prev = state.get(key)
            current = s.health_rollup
            if current and prev and current != prev and _worse(prev, current):
                events.append({
                    "type": "idrac_health_degraded", "server_id": s.id, "server_name": identity,
                    "previous": prev, "current": current, "count": 1, "detected_at": now_iso,
                })
                try:
                    activity.record("idrac_health_degraded", server_name=identity,
                                    previous=prev, current=current)
                except Exception as e:
                    print(f"[dell_monitor] activity record error: {e}")
            if current:
                state[key] = current

    _save_state(state)
    return events


async def refresh_all_servers() -> dict:
    """Called from this module's own slow loop (DELL_CHECK_MIN, default 30
    min) — one server at a time, mirrors linux_manage.py/windows_manage.py's
    refresh_managed_hosts_resources()."""
    with SessionLocal() as db:
        ids = [s.id for s in db.execute(select(DellServer)).scalars().all()]
    checked = 0
    for server_id in ids:
        try:
            result = await check_server(server_id)
            if result.get("ok"):
                checked += 1
        except Exception as e:
            print(f"[dell_monitor] check error for server {server_id}: {e}")
    return {"checked": checked, "total": len(ids)}


async def _loop():
    delay = 90  # first run shortly after startup, mirrors resource_monitor.py's own loop
    while True:
        try:
            await asyncio.sleep(delay)
            delay = DELL_CHECK_MIN * 60
            await refresh_all_servers()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[dell_monitor] loop error: {e}")


def start():
    global _loop_task
    if _loop_task is None or _loop_task.done():
        loop = asyncio.get_event_loop()
        _loop_task = loop.create_task(_loop())


def stop():
    global _loop_task
    if _loop_task and not _loop_task.done():
        _loop_task.cancel()
        _loop_task = None


def _emit(on_event, event: dict) -> None:
    """Local mirror of vuln_scan._emit — kept here instead of importing
    vuln_scan at module level to avoid a circular import (vuln_scan.py's
    own run_scan() lazily imports THIS module to trigger discovery at the
    end of its weekly pass, symmetric to how it already does for
    linux_manage/windows_manage)."""
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception as e:
        print(f"[dell_monitor] on_event callback error: {e}")


async def discover_network_servers(on_event=None) -> dict:
    """Finds ANY Redfish-capable BMC reachable directly over the network —
    Dell iDRAC, HP iLO, Fujitsu iRMC, or anything else conformant
    (confirmed by the user to have HP+Fujitsu servers alongside Dell) —
    reuses the vuln scanner's OWN port-443 findings (VulnHost/VulnService,
    already collected by its regular weekly pass) instead of running a
    second port scan. A bare "port 443 open" is much too common a signal
    on its own (any HTTPS server matches, RouterOS's WebFig included) —
    idrac_client.probe_redfish_root() confirms the host actually speaks
    Redfish (checks for the RedfishVersion key on the service root,
    typically unauthenticated) before it's registered, and its vendor
    hint (also read unauthenticated, no credential-guessing/lockout-risk
    involved) is stored so check_server() knows whether a default
    credential is safe to try later.

    Registration itself doesn't require a WORKING credential — it only
    confirms the host IS a BMC. If the default credential (or whatever is
    later assigned) turns out wrong, that surfaces exactly like it
    already does for a manually-added server: a clear "could not reach
    Redfish ..." error on the server's own card, not a failure to
    discover it in the first place."""
    with SessionLocal() as db:
        candidate_ips = list(db.execute(
            select(VulnHost.ip)
            .join(VulnService, VulnService.host_id == VulnHost.id)
            .where(VulnService.port == 443)
        ).scalars().all())
        known_idrac_ips = {
            ip for ip in db.execute(
                select(DellServer.idrac_ip).where(DellServer.idrac_ip.isnot(None))
            ).scalars().all()
        }

    new_ips = [ip for ip in candidate_ips if ip not in known_idrac_ips]
    _emit(on_event, {"type": "phase", "phase": "dell_network_discovery", "total": len(new_ips)})
    discovered = 0
    for idx, ip in enumerate(new_ips, 1):
        try:
            probe = await idrac_client.probe_redfish_root(ip, 443)
        except Exception as e:
            probe = {"is_redfish": False, "vendor_hint": None}
            print(f"[dell_monitor] redfish probe error for {ip}: {e}")
        _emit(on_event, {"type": "progress", "phase": "dell_network_discovery",
                         "completed": idx, "total": len(new_ips), "ip": ip})
        if not probe["is_redfish"]:
            continue
        vendor = idrac_client.normalize_vendor(probe.get("vendor_hint"))
        with SessionLocal() as db:
            if db.execute(select(DellServer).where(DellServer.idrac_ip == ip)).scalar_one_or_none():
                continue  # discovered concurrently, skip
            server = DellServer(name=None, idrac_ip=ip, idrac_port=443, vendor=vendor)
            db.add(server)
            try:
                db.commit()
                discovered += 1
            except Exception as e:
                db.rollback()
                print(f"[dell_monitor] failed to register discovered BMC {ip}: {e}")
    return {"discovered": discovered, "candidates": len(new_ips)}


async def discover_local_servers(on_event=None) -> dict:
    """Finds Dell servers whose iDRAC has NO routable address, only
    reachable locally via WinRM into the companion Windows host (see
    services/dell_local.py's docstring) — tries every known WindowsHost
    not already linked to a DellServer AND not a virtual machine (a VM
    can never have its own physical iDRAC — confirmed live: several
    Windows hosts at one site turned out to be Hyper-V guests, wasting a
    WinRM+iSM/RACADM round trip and producing a confusing "not found"
    note every single scan for something that will never succeed). Uses
    the shared WinRM credential already configured for Windows management
    (windows_manage's own settings) — never a separate credential, same
    reuse as dell_local.py itself already does for the manual/single-
    server path."""
    with SessionLocal() as db:
        linked_host_ids = {
            hid for hid in db.execute(
                select(DellServer.windows_host_id).where(DellServer.windows_host_id.isnot(None))
            ).scalars().all()
        }
        candidates = db.execute(select(WindowsHost)).scalars().all()
        candidate_ids = [
            (h.id, h.hostname or h.ip) for h in candidates
            if h.id not in linked_host_ids and not windows_manage.is_virtual_model(h.system_model)
        ]

    _emit(on_event, {"type": "phase", "phase": "dell_local_discovery", "total": len(candidate_ids)})
    discovered = 0
    for idx, (host_id, label) in enumerate(candidate_ids, 1):
        try:
            health = await dell_local.collect_local_health(host_id)
        except Exception as e:
            health = {"ok": False, "error": str(e)}
        _emit(on_event, {"type": "progress", "phase": "dell_local_discovery",
                         "completed": idx, "total": len(candidate_ids), "ip": label,
                         "detail": health.get("error")})
        if not health.get("ok"):
            continue
        with SessionLocal() as db:
            if db.execute(
                select(DellServer).where(DellServer.windows_host_id == host_id)
            ).scalar_one_or_none():
                continue  # discovered concurrently, skip
            server = DellServer(
                name=label, idrac_ip=None, idrac_port=443, windows_host_id=host_id,
                access_method=health.get("access_method"),
                health_rollup=health.get("health_rollup"),
                service_tag=health.get("service_tag"), model=health.get("model"),
                bios_version=health.get("bios_version"), power_state=health.get("power_state"),
                components_json=json.dumps(health.get("components") or {}),
                last_status="ok", last_check_at=datetime.utcnow(),
            )
            db.add(server)
            try:
                db.commit()
                discovered += 1
            except Exception as e:
                db.rollback()
                print(f"[dell_monitor] failed to register discovered local server on host {host_id}: {e}")
    return {"discovered": discovered, "candidates": len(candidate_ids)}


async def discover_servers(on_event=None) -> dict:
    """Combined entry point (POST /api/dell/discover) — mirrors
    linux_manage.py/windows_manage.py's own discover_*_hosts(): a single
    button ("Skanuj w poszukiwaniu serwerów Dell") that covers both access
    paths, matching the "one place, click to scan" consolidation already
    applied to Mikrotik/Linux/Windows discovery earlier in this project."""
    network_result = await discover_network_servers(on_event=on_event)
    local_result = await discover_local_servers(on_event=on_event)
    return {
        "discovered": network_result["discovered"] + local_result["discovered"],
        "network": network_result, "local": local_result,
    }


# ── CRUD ─────────────────────────────────────────────────────────────────

def _server_to_dict(s: DellServer) -> dict:
    return {
        "id": s.id, "name": s.name, "vendor": s.vendor, "idrac_ip": s.idrac_ip, "idrac_port": s.idrac_port,
        "windows_host_id": s.windows_host_id, "credential_id": s.credential_id,
        "access_method": s.access_method,
        "last_check_at": s.last_check_at.isoformat() if s.last_check_at else None,
        "last_status": s.last_status, "last_error": s.last_error,
        "health_rollup": s.health_rollup, "service_tag": s.service_tag,
        "model": s.model, "bios_version": s.bios_version, "power_state": s.power_state,
        "components": json.loads(s.components_json) if s.components_json else {},
    }


def list_servers() -> list:
    with SessionLocal() as db:
        servers = db.execute(select(DellServer).order_by(DellServer.id)).scalars().all()
        return [_server_to_dict(s) for s in servers]


def public_summary() -> list:
    """Redacted summary for the snapshot's plaintext envelope — per the
    user's explicit ask ("w centrali powinna być możliwość podglądu
    ogólnego stanu serwerów... nie muszą to być dane bieżące"): name,
    overall health, per-component health, power state, last check time.
    Never the raw error text, iDRAC IP, or credential — mirrors
    linux_manage.public_summary()/windows_manage.public_summary() exactly.
    Refreshes on this module's own DELL_CHECK_MIN cadence (default 30
    min), comfortably inside the "even hourly is fine" the user allowed
    for, so no separate throttling needed here."""
    with SessionLocal() as db:
        servers = db.execute(select(DellServer)).scalars().all()
        return [{
            "id": s.id, "name": s.name or s.service_tag or s.idrac_ip, "vendor": s.vendor,
            "model": s.model, "health_rollup": s.health_rollup,
            "power_state": s.power_state,
            "components": json.loads(s.components_json) if s.components_json else {},
            "last_check_at": s.last_check_at.isoformat() if s.last_check_at else None,
            "last_status": s.last_status,
        } for s in servers]


def add_server(name: Optional[str], idrac_ip: Optional[str], idrac_port: int,
               windows_host_id: Optional[int], credential_id: Optional[int],
               vendor: Optional[str] = None) -> dict:
    if not idrac_ip and not windows_host_id:
        return {"error": "podaj adres iDRAC albo powiąż z hostem Windows (albo oba)"}
    with SessionLocal() as db:
        server = DellServer(
            name=name or None, idrac_ip=idrac_ip or None, idrac_port=idrac_port or 443,
            windows_host_id=windows_host_id, credential_id=credential_id,
            vendor=vendor or "dell",
        )
        db.add(server)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            return {"error": f"nie udało się dodać (zduplikowany adres iDRAC?): {e}"}
        db.refresh(server)
        return _server_to_dict(server)


def update_server(server_id: int, **fields) -> dict:
    with SessionLocal() as db:
        server = db.get(DellServer, server_id)
        if not server:
            return {"error": "not found"}
        for k, v in fields.items():
            if hasattr(server, k):
                setattr(server, k, v)
        db.commit()
        db.refresh(server)
        return _server_to_dict(server)


def delete_server(server_id: int) -> dict:
    with SessionLocal() as db:
        server = db.get(DellServer, server_id)
        if not server:
            return {"error": "not found"}
        db.delete(server)
        db.commit()
        return {"ok": True}


def list_sel_entries(server_id: int, limit: int = 50) -> list:
    with SessionLocal() as db:
        rows = db.execute(
            select(DellServerSelEntry).where(DellServerSelEntry.server_id == server_id)
            .order_by(DellServerSelEntry.logged_at.desc().nullslast(), DellServerSelEntry.id.desc())
            .limit(limit)
        ).scalars().all()
        return [{
            "id": r.id, "severity": r.severity, "message": r.message,
            "logged_at": r.logged_at.isoformat() if r.logged_at else None,
        } for r in rows]
