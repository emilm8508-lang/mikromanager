"""
Mikrotik Manager — launcher.
Starts FastAPI backend and opens the browser.
In dev mode (--dev) also starts Vite dev server on 5173 and enables --reload.

Port is configurable via env var MIKROMANAGER_PORT (default 8888). Set it in
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

DEFAULT_PORT = int(os.environ.get("MIKROMANAGER_PORT", "8888"))
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


_MAX_RESTARTS_IN_WINDOW = 5
_RESTART_WINDOW_SEC = 60


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

    frontend_proc = None
    browser_opened = False
    restart_times = []

    try:
        if args.dev:
            print("Starting Vite dev server...")
            frontend_proc = run_frontend_dev()

        while True:
            print(f"Starting Mikrotik Manager backend on {args.host}:{args.port}...")
            backend_proc = run_backend(port=args.port, host=args.host, dev=args.dev)

            if not browser_opened:
                url = f"http://localhost:{args.port if not args.dev else 5173}"
                if args.dev:
                    open_browser("http://localhost:5173", delay=3.0)
                elif not args.no_browser:
                    open_browser(f"http://localhost:{args.port}", delay=2.5)
                print(f"Opening {url}")
                print("Press Ctrl+C to stop.\n")
                browser_opened = True

            exit_code = backend_proc.wait()

            now = time.time()
            restart_times.append(now)
            del restart_times[:-_MAX_RESTARTS_IN_WINDOW - 1]
            if len(restart_times) > _MAX_RESTARTS_IN_WINDOW and \
                    now - restart_times[0] < _RESTART_WINDOW_SEC:
                print(f"Backend exited {len(restart_times)}x in under "
                      f"{_RESTART_WINDOW_SEC}s (last exit code {exit_code}) — "
                      "giving up to avoid a crash loop. Check the logs.")
                break

            print(f"Backend exited (code {exit_code}) — restarting in 2s "
                  "(self-update or remote restart)...")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopping...")
        backend_proc.terminate()
    finally:
        if frontend_proc:
            frontend_proc.terminate()


if __name__ == "__main__":
    main()
