"""Best-effort lock-down of the files that hold the agent's secrets (backend/data/.key, .session_secret, ...).

Whoever can read `.key` can decrypt every stored credential, and whoever can read `.session_secret` can forge a login cookie, so
they should be readable by the account the agent runs as (and administrators / the system) only - not by every local user.
POSIX: mode 0600. Windows: the inherited permissions are removed and only the current account, SYSTEM and Administrators are
granted (SIDs, so it works on any Windows language). Failures are ignored: this is a hardening step, never a reason not to start."""
import os
import subprocess
import sys

_SECRET_FILES = (".key", ".session_secret", "central_proxy.json")


def restrict(path: str) -> bool:
    """True if the file is now restricted to the owner (and, on Windows, SYSTEM / Administrators)."""
    if not os.path.exists(path):
        return False
    try:
        if sys.platform == "win32":
            user = os.environ.get("USERNAME") or ""
            grants = ["*S-1-5-18:(F)", "*S-1-5-32-544:(F)"] + ([f"{user}:(F)"] if user else [])
            args = ["icacls", path, "/inheritance:r"]
            for g in grants:
                args += ["/grant:r", g]
            r = subprocess.run(args, capture_output=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return r.returncode == 0
        os.chmod(path, 0o600)
        return True
    except Exception:
        return False


def harden_data_dir(data_dir: str) -> dict:
    """Restricts the secret files that exist in `data_dir`; returns {file: ok}."""
    return {name: restrict(os.path.join(data_dir, name)) for name in _SECRET_FILES if os.path.exists(os.path.join(data_dir, name))}
