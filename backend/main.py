import sys
import os
import asyncio

# Ensure backend package root is on path when run directly
sys.path.insert(0, os.path.dirname(__file__))

# Windows: force ProactorEventLoop (IOCP-based, no FD_SETSIZE 512 limit).
# Without this, scanner concurrent socket count can hit select() limit and
# crash with "too many file descriptors in select()".
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except AttributeError:
        pass

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from contextlib import asynccontextmanager

from models.database import init_db
from api import devices, credentials, logs, scanner, system, auth, audit as audit_api, vuln_scan as vuln_api, linux_manage as linux_api, windows_manage as windows_api, inventory as inventory_api, compliance as compliance_api, anydesk_history as anydesk_api, dell_servers as dell_api, hyperv as hyperv_api, host_monitor as hostmon_api, host_services as hostsvc_api, fleet as fleet_api, security_summary as secsum_api, assets as assets_api, racks as racks_api, netmap as netmap_api, traffic as traffic_api, soc as soc_api, onsite as onsite_api, availability as availability_api, services as services_api
from api.auth import require_login
from services import refresher
from services import uplink
from services import vuln_scan
from services import agent_backup
from services import supply_chain
from services import updater as updater_svc
from services import audit as audit_svc
from services import resource_monitor
from services import dell_monitor
from services import host_monitor
from services import host_services
from services import fleet_schedule
from services import hyperv_manage
from services import hyperv_actions
from services import assets as assets_svc, asset_scan as asset_scan_svc, lan_sweep as lan_sweep_svc, servicedesk_tickets, exploit_intel, availability


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Apply any in-app-triggered restore (api/system.py's POST /backup/restore)
    # BEFORE init_db() ever opens data/mikrotik.db — see agent_backup.py's
    # apply_staged_restore_if_present() docstring for why this ordering matters.
    restore_result = agent_backup.apply_staged_restore_if_present()
    if restore_result:
        print(f"[startup] backup restore: {restore_result}")
    init_db()
    from services import fs_perms
    fs_perms.harden_data_dir(os.path.join(os.path.dirname(__file__), "data"))     # keys readable by the agent's account only
    from services import host_identity
    try:
        from services import pkg_hygiene
        pkg_hygiene.remove_impacket_examples()                                      # antivirus-flagged example scripts of the optional impacket package
    except Exception as e:
        print(f"[startup] package hygiene skipped: {e}")
    host_identity.startup_merge()                                                   # one entry per machine, also for the pairs left by an address change
    try:
        vuln_scan.cleanup_hosts()                                                   # hosts of ranges that are gone, and the phantoms of an antivirus mail proxy
    except Exception as e:
        print(f"[startup] host cleanup skipped: {e}")
    refresher.start()
    uplink.start()
    vuln_scan.start()
    agent_backup.start()
    supply_chain.start()
    updater_svc.start_auto_update()
    resource_monitor.start()
    dell_monitor.start()
    host_monitor.start()
    host_services.start()
    fleet_schedule.start()
    hyperv_actions.mark_interrupted()
    hyperv_manage.start()
    assets_svc.start()
    servicedesk_tickets.start()
    exploit_intel.start()
    availability.start()
    asset_scan_svc.start()
    lan_sweep_svc.start()
    try:
        yield
    finally:
        refresher.stop()
        uplink.stop()
        vuln_scan.stop()
        agent_backup.stop()
        supply_chain.stop()
        updater_svc.stop_auto_update()
        resource_monitor.stop()
        dell_monitor.stop()
        host_monitor.stop()
        host_services.stop()
        fleet_schedule.stop()
        hyperv_manage.stop()
        assets_svc.stop()
        servicedesk_tickets.stop()
        exploit_intel.stop()
        availability.stop()
        asset_scan_svc.stop()
        lan_sweep_svc.stop()


# The interactive API docs / schema would hand an unauthenticated visitor the full map of the API: off unless asked for.
_DOCS = os.environ.get("MIKROMANAGER_API_DOCS", "0") == "1"
app = FastAPI(title="Mikrotik Manager", version="1.0.0", lifespan=lifespan,
              docs_url="/docs" if _DOCS else None, redoc_url="/redoc" if _DOCS else None, openapi_url="/openapi.json" if _DOCS else None)

app.add_middleware(
    CORSMiddleware,
    # Allow both default (8888) and legacy (8000) ports so existing deployments
    # keep working even after mixed upgrade of frontend/backend.
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8888",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)  # public: login must work before a session exists

_protected = [Depends(require_login)]
app.include_router(devices.router, dependencies=_protected)
app.include_router(credentials.router, dependencies=_protected)
app.include_router(logs.router, dependencies=_protected)
app.include_router(scanner.router, dependencies=_protected)
app.include_router(system.router, dependencies=_protected)
app.include_router(vuln_api.router, dependencies=_protected)
app.include_router(linux_api.router, dependencies=_protected)
app.include_router(windows_api.router, dependencies=_protected)
app.include_router(hyperv_api.router, dependencies=_protected)
app.include_router(secsum_api.router, dependencies=_protected)
app.include_router(assets_api.router, dependencies=_protected)
app.include_router(racks_api.router, dependencies=_protected)
app.include_router(netmap_api.router, dependencies=_protected)
app.include_router(traffic_api.router, dependencies=_protected)
app.include_router(soc_api.router, dependencies=_protected)
app.include_router(availability_api.router, dependencies=_protected)
app.include_router(services_api.router, dependencies=_protected)
app.include_router(onsite_api.router)           # its own check: a session or the shared key (see api/onsite.py)
app.include_router(inventory_api.router, dependencies=_protected)
app.include_router(compliance_api.router, dependencies=_protected)
app.include_router(audit_api.router, dependencies=_protected)
app.include_router(anydesk_api.router, dependencies=_protected)
app.include_router(dell_api.router, dependencies=_protected)
app.include_router(hostmon_api.router, dependencies=_protected)
app.include_router(hostsvc_api.router, dependencies=_protected)
app.include_router(fleet_api.router, dependencies=_protected)


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    if not (_DOCS and request.url.path in ("/docs", "/redoc")):         # the docs pages load their UI from a CDN
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")        # API answers hold inventory, logs, findings
    return response


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log every mutating request that reached an authenticated handler —
    "who did what". require_login stashes the session on request.state
    (same request object, so it's visible here after call_next returns).
    Skips /api/auth entirely: login attempts have their own throttle/
    lockout trail and don't have a session before they succeed anyway."""
    response = await call_next(request)
    try:
        path = request.url.path
        if (request.method in ("POST", "PUT", "PATCH", "DELETE")
                and path.startswith("/api/") and not path.startswith("/api/auth")):
            session = getattr(request.state, "session", None)
            if session:
                audit_svc.record(
                    username=session.get("username") or "?",
                    role=session.get("role") or "?",
                    source=session.get("source") or "?",
                    method=request.method, path=path,
                    status_code=response.status_code,
                    ip=request.client.host if request.client else None,
                )
    except Exception:
        pass
    return response


@app.get("/api/health")
async def health():
    return {"status": "ok"}


# Serve built frontend if available. Registered LAST — its catch-all route
# would otherwise shadow every /api/* route defined after it.
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        # Read the whole file into memory rather than FileResponse's
        # stat-then-stream pattern: Content-Length there is computed from
        # os.stat() BEFORE the file is actually opened and read, so if
        # anything changes the file's size in that window — a self-update
        # rebuilding dist/, antivirus scanning it, anything — the browser
        # gets a header promising N bytes but a body of a different size.
        # Confirmed on a real agent as net::ERR_CONTENT_LENGTH_MISMATCH,
        # and survived two other fixes targeting specific causes of that
        # window (atomic dist swap, a dedicated scan thread pool) — so
        # instead of chasing the exact interference mechanism, this makes
        # the two values structurally impossible to disagree: they're both
        # derived from the exact same read, in memory, all at once. The
        # file is tiny (a bare SPA shell, well under 1KB), so the brief
        # synchronous read here is not a meaningful cost.
        index = os.path.join(FRONTEND_DIST, "index.html")
        with open(index, "rb") as f:
            content = f.read()
        return Response(content=content, media_type="text/html")
