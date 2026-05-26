"""
Mikrotik Manager — launcher.
Starts FastAPI backend on port 8000 and opens the browser.
In dev mode (--dev) also starts Vite dev server on 5173.
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


def run_backend():
    env = os.environ.copy()
    env["PYTHONPATH"] = BACKEND
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"],
        cwd=BACKEND,
        env=env,
    )


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
    parser.add_argument("--dev", action="store_true", help="Start Vite dev server alongside backend")
    args = parser.parse_args()

    procs = []
    try:
        print("Starting Mikrotik Manager backend...")
        procs.append(run_backend())

        if args.dev:
            print("Starting Vite dev server...")
            procs.append(run_frontend_dev())
            open_browser("http://localhost:5173", delay=3.0)
            print("Opening http://localhost:5173")
        else:
            open_browser("http://localhost:8000", delay=2.5)
            print("Opening http://localhost:8000")

        print("Press Ctrl+C to stop.\n")
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\nStopping...")
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
