"""
Local authentication — password + mandatory TOTP MFA.

Deliberately 100% local: password hash, TOTP secret and session signing key
all live under backend/data/ on this machine. Login must keep working even
if the OVH central server or its database is unreachable, so nothing here
makes a network call or depends on central being up.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import time
from typing import Optional

import pyotp
import qrcode
import qrcode.image.svg

SESSION_COOKIE = "mm_session"
SESSION_TTL_SEC = 7 * 24 * 3600  # 7 days

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_SESSION_SECRET_PATH = os.path.join(_DATA_DIR, ".session_secret")

_PBKDF2_ITERATIONS = 260_000


# Cached after the first successful read — this file practically never
# changes during normal operation (created once, read forever after), but
# _get_session_secret() used to re-open it from disk on EVERY single
# authenticated request (verify_session_token() calls it fresh every time).
# Under heavy disk I/O elsewhere in the process (a network scan writing
# lots of data, antivirus real-time-scanning the file, any transient OS-
# level hiccup), that repeated read could fail — and verify_session_token()'s
# broad except-Exception treats a failed read exactly like a genuinely
# invalid signature, producing a real 401 on an otherwise-valid session.
# Confirmed on a real agent: a request failed with 401 immediately after a
# previous request on the SAME session succeeded, no reload in between,
# right as a network scan was running. Caching removes almost all of that
# exposure — after the first read (typically at first login), this never
# touches disk again for the life of the process.
_session_secret_cache: Optional[bytes] = None


def _get_session_secret() -> bytes:
    global _session_secret_cache
    if _session_secret_cache is not None:
        return _session_secret_cache
    os.makedirs(_DATA_DIR, exist_ok=True)
    if os.path.exists(_SESSION_SECRET_PATH):
        with open(_SESSION_SECRET_PATH, "rb") as f:
            _session_secret_cache = f.read()
        return _session_secret_cache
    key = secrets.token_bytes(32)
    with open(_SESSION_SECRET_PATH, "wb") as f:
        f.write(key)
    _session_secret_cache = key
    return key


# ── Password hashing (PBKDF2-HMAC-SHA256, stdlib only) ───────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_b64, hash_b64 = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ── TOTP (MFA) — RFC 6238, works fully offline in any authenticator app ─────

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def is_valid_totp_secret(secret: str) -> bool:
    """Accepts a caller-supplied secret (e.g. copied from another agent so
    the same authenticator entry works for both) — just needs to be valid
    base32 that pyotp can actually generate codes from."""
    secret = (secret or "").strip().upper()
    if not secret:
        return False
    try:
        pyotp.TOTP(secret).now()
        return True
    except Exception:
        return False


def totp_provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MikroManager")


def totp_qr_svg_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/svg+xml;base64,{b64}"


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


# ── Session tokens (HMAC-signed cookie value, stdlib only) ──────────────────
# Carries identity + role so `require_login` can do RBAC and callers can
# know who's logged in and via which source — a local emergency account
# always has role="admin"; an OVH-sourced session carries whatever role the
# central account was assigned. Not a JWT (no need for a standard format
# here, this token is only ever produced/consumed by this same process).

def create_session_token(*, source: str, username: str, role: str, account_id: Optional[int] = None) -> str:
    payload = {
        "source": source,       # "local" | "ovh"
        "username": username,
        "role": role,           # "admin" | "viewer"
        "account_id": account_id,
        "exp": int(time.time()) + SESSION_TTL_SEC,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(_get_session_secret(), payload_json.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload_json.encode()).decode() + "." + sig


def verify_session_token(token: str) -> Optional[dict]:
    try:
        payload_b64, sig = token.split(".", 1)
        payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        expected_sig = hmac.new(_get_session_secret(), payload_json.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return None
        payload = json.loads(payload_json)
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        if payload.get("source") not in ("local", "ovh") or payload.get("role") not in ("admin", "viewer"):
            return None
        return payload
    except Exception:
        return None


# ── Brute-force throttle (in-memory, per-process) ────────────────────────────
# Not persisted across restarts — acceptable since a restart is already a
# meaningful barrier (requires filesystem/process access to this machine).

_MAX_ATTEMPTS = 5
_LOCKOUT_SEC = 60
_failed_attempts: dict = {}  # key -> (count, locked_until)


def check_throttle(key: str) -> Optional[int]:
    """Returns seconds remaining if locked out, else None."""
    entry = _failed_attempts.get(key)
    if not entry:
        return None
    count, locked_until = entry
    remaining = int(locked_until - time.time())
    return remaining if remaining > 0 else None


def record_failure(key: str) -> None:
    count, _ = _failed_attempts.get(key, (0, 0))
    count += 1
    locked_until = time.time() + _LOCKOUT_SEC if count >= _MAX_ATTEMPTS else 0
    _failed_attempts[key] = (count, locked_until)


def record_success(key: str) -> None:
    _failed_attempts.pop(key, None)
