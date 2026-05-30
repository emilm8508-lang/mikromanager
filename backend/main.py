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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from models.database import init_db
from api import devices, credentials, logs, scanner, system
from services import refresher
from services import uplink


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    refresher.start()
    uplink.start()
    try:
        yield
    finally:
        refresher.stop()
        uplink.stop()


app = FastAPI(title="Mikrotik Manager", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router)
app.include_router(credentials.router)
app.include_router(logs.router)
app.include_router(scanner.router)
app.include_router(system.router)

# Serve built frontend if available
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        index = os.path.join(FRONTEND_DIST, "index.html")
        return FileResponse(index)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
