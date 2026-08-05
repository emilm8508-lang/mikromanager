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


def _get_session_secret() -> bytes:
    os.makedirs(_DATA_DIR, exist_ok=True)
    if os.path.exists(_SESSION_SECRET_PATH):
        with open(_SESSION_SECRET_PATH, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(_SESSION_SECRET_PATH, "wb") as f:
        f.write(key)
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

def create_session_token(account_id: int) -> str:
    payload = f"{account_id}:{int(time.time()) + SESSION_TTL_SEC}"
    sig = hmac.new(_get_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload.encode()).decode() + "." + sig


def verify_session_token(token: str) -> Optional[int]:
    try:
        payload_b64, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        expected_sig = hmac.new(_get_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return None
        account_id_str, expiry_str = payload.split(":")
        if int(expiry_str) < int(time.time()):
            return None
        return int(account_id_str)
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
