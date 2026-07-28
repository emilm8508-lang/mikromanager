"""
Mikrotik Manager — launcher.
Starts FastAPI backend and opens the browser.
In dev mode (--dev) also starts Vite dev server on 5173 and enables --reload.

Port is configurable via env var MIKROMANAGER_PORT (default 8000). Set it in
systemd unit / NSSM environment when default port is taken (e.g. by check_mk).
Command-line flag --port also works and takes precedence over env var.
"""
import subprocess
import sys
import os
import time
import webbrowser
import threading
import argparse

BASE = os.path.dirname(__file__)
BACKEND = os.path.join(BASE, "backend")
FRONTEND = os.path.join(BASE, "frontend")

DEFAULT_PORT = int(os.environ.get("MIKROMANAGER_PORT", "8000"))
DEFAULT_HOST = os.environ.get("MIKROMANAGER_HOST", "0.0.0.0")


def run_backend(port: int, host: str, dev: bool = False):
    env = os.environ.copy()
    env["PYTHONPATH"] = BACKEND

    cmd = [sys.executable, "-m", "uvicorn", "main:app",
           "--host", host, "--port", str(port),
           "--loop", "asyncio"]  # ensures ProactorEventLoop on Windows (no FD limit)
    if dev:
        cmd.append("--reload")  # reload uses watchfiles+selector; only enable in dev

    return subprocess.Popen(cmd, cwd=BACKEND, env=env)


def run_frontend_dev():
    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    return subprocess.Popen([npm, "run", "dev"], cwd=FRONTEND)


def open_browser(url: str, delay: float = 2.0):
    def _open():
        time.sleep(delay)
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", action="store_true",
                        help="Start Vite dev server + uvicorn --reload")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Backend port (default {DEFAULT_PORT}, env MIKROMANAGER_PORT)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"Backend host (default {DEFAULT_HOST}, env MIKROMANAGER_HOST)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser tab on startup")
    args = parser.parse_args()

    procs = []
    try:
        print(f"Starting Mikrotik Manager backend on {args.host}:{args.port}...")
        procs.append(run_backend(port=args.port, host=args.host, dev=args.dev))

        url = f"http://localhost:{args.port if not args.dev else 5173}"
        if args.dev:
            print("Starting Vite dev server...")
            procs.append(run_frontend_dev())
            open_browser("http://localhost:5173", delay=3.0)
        elif not args.no_browser:
            open_browser(f"http://localhost:{args.port}", delay=2.5)
        print(f"Opening {url}")

        print("Press Ctrl+C to stop.\n")
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\nStopping...")
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
