import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import BaseModel

from models.database import AppAccount, get_db
from services import auth as auth_svc

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_SECURE = os.environ.get("MIKROMANAGER_COOKIE_SECURE", "0") == "1"


def _set_session_cookie(response: Response, account_id: int) -> None:
    response.set_cookie(
        auth_svc.SESSION_COOKIE,
        auth_svc.create_session_token(account_id),
        max_age=auth_svc.SESSION_TTL_SEC,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def require_login(request: Request) -> int:
    """FastAPI dependency — raises 401 unless a valid session cookie is present.
    Applied to every router except /api/auth and /api/health."""
    token = request.cookies.get(auth_svc.SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "not authenticated")
    account_id = auth_svc.verify_session_token(token)
    if account_id is None:
        raise HTTPException(401, "session expired or invalid")
    return account_id


def _get_account(db: Session) -> AppAccount | None:
    return db.execute(select(AppAccount)).scalars().first()


@router.get("/status")
async def status(db: Session = Depends(get_db)):
    account = _get_account(db)
    return {
        "configured": account is not None and account.mfa_enabled,
        "mfa_setup_pending": account is not None and not account.mfa_enabled,
    }


class SetupIn(BaseModel):
    username: str
    password: str
    # Optional: reuse the TOTP secret from another agent instance so the same
    # account (username + password + authenticator entry) works unchanged
    # across every site you manage, instead of scanning a new QR code and
    # juggling a separate authenticator entry per agent. Leave empty to
    # generate a fresh one (the default, single-agent case).
    totp_secret: Optional[str] = None


@router.post("/setup")
async def setup(data: SetupIn, db: Session = Depends(get_db)):
    """Create the single local account. Only works while none exists yet."""
    if _get_account(db) is not None:
        raise HTTPException(409, "account already configured")
    if len(data.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    username = data.username.strip()
    if not username:
        raise HTTPException(400, "username required")

    if data.totp_secret:
        secret = data.totp_secret.strip().upper()
        if not auth_svc.is_valid_totp_secret(secret):
            raise HTTPException(400, "invalid TOTP secret — must be a valid base32 key")
    else:
        secret = auth_svc.generate_totp_secret()

    from services.crypto import encrypt
    account = AppAccount(
        username=username,
        password_hash=auth_svc.hash_password(data.password),
        totp_secret_enc=encrypt(secret),
        mfa_enabled=False,
    )
    db.add(account)
    db.commit()

    uri = auth_svc.totp_provisioning_uri(secret, username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg_data_uri": auth_svc.totp_qr_svg_data_uri(uri),
    }


class SetupResumeIn(BaseModel):
    username: str
    password: str


@router.post("/setup/resume")
async def setup_resume(data: SetupResumeIn, db: Session = Depends(get_db)):
    """Re-fetch the QR/secret for an account whose MFA confirmation was
    interrupted (e.g. browser closed before scanning). Requires the password
    again so the TOTP secret isn't handed out to anyone who merely reaches
    this endpoint during the short pre-confirmation window."""
    account = _get_account(db)
    if account is None:
        raise HTTPException(404, "no account configured — call /setup first")
    if account.mfa_enabled:
        raise HTTPException(400, "MFA already enabled — use /login")

    throttle_key = f"resume:{account.username.lower()}"
    locked_for = auth_svc.check_throttle(throttle_key)
    if locked_for is not None:
        raise HTTPException(429, f"too many failed attempts — try again in {locked_for}s")
    if (
        data.username.strip().lower() != account.username.lower()
        or not auth_svc.verify_password(data.password, account.password_hash)
    ):
        auth_svc.record_failure(throttle_key)
        raise HTTPException(401, "invalid username or password")
    auth_svc.record_success(throttle_key)

    from services.crypto import decrypt
    secret = decrypt(account.totp_secret_enc)
    uri = auth_svc.totp_provisioning_uri(secret, account.username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg_data_uri": auth_svc.totp_qr_svg_data_uri(uri),
    }


class SetupRegenerateIn(BaseModel):
    username: str
    password: str
    # Optional: set the secret to this EXACT value instead of generating a
    # random one — for re-entering the correct secret when it was mistyped
    # the first time (e.g. the same shared secret used across other agents
    # via /setup's 'reuse existing secret' field — a random new one here
    # would fix login on this agent but break the "same account everywhere"
    # reuse, since it'd no longer match what's on the other agents).
    # Leave empty to fall back to a fresh random secret.
    totp_secret: Optional[str] = None


@router.post("/setup/regenerate")
async def setup_regenerate(data: SetupRegenerateIn, db: Session = Depends(get_db)):
    """Like /setup/resume, but REPLACES the current (never-confirmed) secret
    instead of just re-showing it — either with a specific value you provide
    (typically: the correct secret, re-typed, after the first attempt had a
    typo) or, if none is given, a fresh random one. Same password check +
    throttle as resume."""
    account = _get_account(db)
    if account is None:
        raise HTTPException(404, "no account configured — call /setup first")
    if account.mfa_enabled:
        raise HTTPException(400, "MFA already enabled — use /totp-secret/regenerate instead")

    throttle_key = f"resume:{account.username.lower()}"
    locked_for = auth_svc.check_throttle(throttle_key)
    if locked_for is not None:
        raise HTTPException(429, f"too many failed attempts — try again in {locked_for}s")
    if (
        data.username.strip().lower() != account.username.lower()
        or not auth_svc.verify_password(data.password, account.password_hash)
    ):
        auth_svc.record_failure(throttle_key)
        raise HTTPException(401, "invalid username or password")
    auth_svc.record_success(throttle_key)

    if data.totp_secret:
        secret = data.totp_secret.strip().upper()
        if not auth_svc.is_valid_totp_secret(secret):
            raise HTTPException(400, "invalid TOTP secret — must be a valid base32 key")
    else:
        secret = auth_svc.generate_totp_secret()

    from services.crypto import encrypt
    account.totp_secret_enc = encrypt(secret)
    db.commit()

    uri = auth_svc.totp_provisioning_uri(secret, account.username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg_data_uri": auth_svc.totp_qr_svg_data_uri(uri),
    }


class MfaConfirmIn(BaseModel):
    code: str


@router.post("/mfa/confirm")
async def mfa_confirm(data: MfaConfirmIn, response: Response, db: Session = Depends(get_db)):
    """Second step of setup: prove the TOTP secret was scanned correctly.
    Enables MFA and logs the user in immediately."""
    account = _get_account(db)
    if account is None:
        raise HTTPException(404, "no account configured — call /setup first")
    if account.mfa_enabled:
        raise HTTPException(400, "MFA already enabled — use /login")

    from services.crypto import decrypt
    secret = decrypt(account.totp_secret_enc)
    if not auth_svc.verify_totp(secret, data.code):
        raise HTTPException(401, "invalid code")

    account.mfa_enabled = True
    db.commit()
    _set_session_cookie(response, account.id)
    return {"ok": True}


class LoginIn(BaseModel):
    username: str
    password: str
    totp_code: str


@router.post("/login")
async def login(data: LoginIn, response: Response, db: Session = Depends(get_db)):
    account = _get_account(db)
    if account is None:
        raise HTTPException(404, "no account configured — call /setup first")

    throttle_key = account.username.lower()
    locked_for = auth_svc.check_throttle(throttle_key)
    if locked_for is not None:
        raise HTTPException(429, f"too many failed attempts — try again in {locked_for}s")

    valid = (
        data.username.strip().lower() == account.username.lower()
        and auth_svc.verify_password(data.password, account.password_hash)
    )
    if valid and not account.mfa_enabled:
        # Setup was interrupted before MFA confirmation — don't allow a
        # password-only login, but tell the frontend to resume setup.
        raise HTTPException(409, "MFA setup incomplete — finish scanning the QR code")
    if valid and account.mfa_enabled:
        from services.crypto import decrypt
        secret = decrypt(account.totp_secret_enc)
        valid = auth_svc.verify_totp(secret, data.totp_code)

    if not valid:
        auth_svc.record_failure(throttle_key)
        raise HTTPException(401, "invalid username, password, or code")

    auth_svc.record_success(throttle_key)
    _set_session_cookie(response, account.id)
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth_svc.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(account_id: int = Depends(require_login), db: Session = Depends(get_db)):
    account = db.get(AppAccount, account_id)
    if account is None:
        raise HTTPException(401, "not authenticated")
    return {"username": account.username}


@router.get("/totp-secret")
async def get_totp_secret(account_id: int = Depends(require_login), db: Session = Depends(get_db)):
    """Export the current account's TOTP secret/QR — for copying this exact
    account (same authenticator entry) onto another agent via /setup's
    'reuse existing secret' field. Requires an active session, unlike
    /setup/resume which only works before MFA is confirmed."""
    account = db.get(AppAccount, account_id)
    if account is None:
        raise HTTPException(401, "not authenticated")

    from services.crypto import decrypt
    secret = decrypt(account.totp_secret_enc)
    uri = auth_svc.totp_provisioning_uri(secret, account.username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg_data_uri": auth_svc.totp_qr_svg_data_uri(uri),
    }


class TotpRegenerateIn(BaseModel):
    # Optional: set the secret to this EXACT value (e.g. re-typing the
    # shared secret used on your other agents) instead of a random one.
    totp_secret: Optional[str] = None


@router.post("/totp-secret/regenerate")
async def regenerate_totp_secret(data: TotpRegenerateIn = TotpRegenerateIn(),
                                 account_id: int = Depends(require_login), db: Session = Depends(get_db)):
    """Replace the current TOTP secret — with a specific value you provide,
    or (if none given) a fresh random one. For changing authenticator apps,
    or recovering from having scanned/typed it wrong the first time. Takes
    effect immediately (this is an authenticated action, same trust level as
    GET /totp-secret above); the old authenticator entry stops working the
    moment this returns, so the frontend must show the new QR right away and
    make clear the old one is now dead."""
    account = db.get(AppAccount, account_id)
    if account is None:
        raise HTTPException(401, "not authenticated")

    if data.totp_secret:
        secret = data.totp_secret.strip().upper()
        if not auth_svc.is_valid_totp_secret(secret):
            raise HTTPException(400, "invalid TOTP secret — must be a valid base32 key")
    else:
        secret = auth_svc.generate_totp_secret()

    from services.crypto import encrypt
    account.totp_secret_enc = encrypt(secret)
    db.commit()

    uri = auth_svc.totp_provisioning_uri(secret, account.username)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg_data_uri": auth_svc.totp_qr_svg_data_uri(uri),
    }
