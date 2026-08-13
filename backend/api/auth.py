import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import BaseModel

from models.database import AppAccount, get_db
from services import auth as auth_svc
from services import ovh_auth, uplink

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_SECURE = os.environ.get("MIKROMANAGER_COOKIE_SECURE", "0") == "1"


def _set_session_cookie(response: Response, *, source: str, username: str,
                         role: str, account_id: Optional[int] = None) -> None:
    response.set_cookie(
        auth_svc.SESSION_COOKIE,
        auth_svc.create_session_token(source=source, username=username, role=role, account_id=account_id),
        max_age=auth_svc.SESSION_TTL_SEC,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def require_login(request: Request) -> dict:
    """FastAPI dependency — raises 401 unless a valid session cookie is
    present, returns the session payload ({source, username, role,
    account_id}). Also enforces a simple, global RBAC rule here (rather than
    touching every handler in every router): a "viewer" role may only GET —
    any mutating request is rejected. Applied to every router except
    /api/auth and /api/health. The local emergency account is always
    role="admin", so it's never affected by this check."""
    token = request.cookies.get(auth_svc.SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "not authenticated")
    session = auth_svc.verify_session_token(token)
    if session is None:
        raise HTTPException(401, "session expired or invalid")
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and session.get("role") == "viewer":
        raise HTTPException(403, "read-only account — this action requires an admin role")
    request.state.session = session  # read by main.py's audit middleware
    return session


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
    _set_session_cookie(response, source="local", username=account.username, role="admin", account_id=account.id)
    return {"ok": True}


class LoginIn(BaseModel):
    username: str
    password: str
    totp_code: str


def _local_login(data: LoginIn, response: Response, db: Session) -> dict:
    """The local emergency account's login check — unchanged from before this
    feature existed. Deliberately makes no network call (see services/auth.py's
    module docstring): must keep working even if OVH/its DB is unreachable."""
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
    _set_session_cookie(response, source="local", username=account.username, role="admin", account_id=account.id)
    return {"ok": True, "source": "local", "username": account.username, "role": "admin"}


@router.post("/login")
async def login(data: LoginIn, response: Response, db: Session = Depends(get_db)):
    """OVH-primary login: if central is configured, try it first. Only fall
    back to the local emergency account when OVH is unreachable or has no
    accounts provisioned yet — a clean credential/scope rejection from a
    reachable OVH is a hard failure, never silently retried locally (that
    would be confusing and would mask a real permissions problem)."""
    if uplink.is_configured():
        try:
            result = await ovh_auth.login(data.username, data.password, data.totp_code)
            _set_session_cookie(response, source="ovh", username=result["username"], role=result["role"])
            return {"ok": True, "source": "ovh", "username": result["username"], "role": result["role"],
                    "allowed_tenants": result.get("allowed_tenants")}
        except ovh_auth.OvhLoginRejected as e:
            if e.status == 429:
                raise HTTPException(429, "too many failed attempts — try again shortly")
            if e.error == "tenant_not_allowed":
                raise HTTPException(403, "this account does not have access to this agent's tenant")
            raise HTTPException(401, "invalid username, password, or code")
        except (ovh_auth.OvhNotProvisioned, ovh_auth.OvhUnreachable):
            pass  # fall through to the local emergency account below

    return _local_login(data, response, db)


@router.post("/login/local")
async def login_local(data: LoginIn, response: Response, db: Session = Depends(get_db)):
    """Deliberate, explicit use of the local emergency account — for when an
    operator wants to bypass OVH on purpose (e.g. their central account was
    deactivated), not just when OVH happens to be unreachable."""
    return _local_login(data, response, db)


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(auth_svc.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(session: dict = Depends(require_login), db: Session = Depends(get_db)):
    if session.get("source") == "local":
        account = db.get(AppAccount, session.get("account_id"))
        if account is None:
            raise HTTPException(401, "not authenticated")
    return {"username": session["username"], "role": session["role"], "source": session["source"]}


def _require_local_session(session: dict) -> None:
    if session.get("source") != "local":
        raise HTTPException(400, "not applicable to an OVH-authenticated session — manage TOTP for central "
                                  "accounts from the Central \"Users\" panel instead")


@router.get("/totp-secret")
async def get_totp_secret(session: dict = Depends(require_login), db: Session = Depends(get_db)):
    """Export the current account's TOTP secret/QR — for copying this exact
    account (same authenticator entry) onto another agent via /setup's
    'reuse existing secret' field. Requires an active session, unlike
    /setup/resume which only works before MFA is confirmed. Only meaningful
    for the local emergency account — OVH accounts manage their own TOTP via
    the central "Users" panel/`me_totp_confirm`."""
    _require_local_session(session)
    account = db.get(AppAccount, session.get("account_id"))
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
                                 session: dict = Depends(require_login), db: Session = Depends(get_db)):
    """Replace the current TOTP secret — with a specific value you provide,
    or (if none given) a fresh random one. For changing authenticator apps,
    or recovering from having scanned/typed it wrong the first time. Takes
    effect immediately (this is an authenticated action, same trust level as
    GET /totp-secret above); the old authenticator entry stops working the
    moment this returns, so the frontend must show the new QR right away and
    make clear the old one is now dead. Only meaningful for the local
    emergency account, same as GET /totp-secret above."""
    _require_local_session(session)
    account = db.get(AppAccount, session.get("account_id"))
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
