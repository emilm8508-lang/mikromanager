"""
One-time setup: installs Python deps and npm packages, builds frontend.
"""
import subprocess
import sys
import os

BASE = os.path.dirname(__file__)
BACKEND = os.path.join(BASE, "backend")
FRONTEND = os.path.join(BASE, "frontend")
npm = "npm.cmd" if sys.platform == "win32" else "npm"


def run(cmd, cwd=None):
    print(f"  > {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=cwd)


print("\n=== Mikrotik Manager Setup ===\n")

print("[1/3] Installing Python dependencies...")
run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=BACKEND)

print("\n[2/3] Installing npm dependencies...")
run([npm, "install"], cwd=FRONTEND)

print("\n[3/3] Building frontend...")
run([npm, "run", "build"], cwd=FRONTEND)

print("\n=== Setup complete! ===")
print("Run:  python run.py          (production — serves built frontend)")
print("Run:  python run.py --dev    (development — hot reload on both sides)")
