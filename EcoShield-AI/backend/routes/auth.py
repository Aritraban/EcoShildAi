"""Authentication & account routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models.entities import AuditLog, Role, Severity, User
from backend.models.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MFACodeRequest,
    ProfileOut,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserOut,
)
from backend.security import deps as auth_deps
from backend.security.audit import write_audit
from backend.security.cookies import clear_refresh_cookie, set_refresh_cookie
from backend.security.login_guard import evaluate_login, register_failed_login, reset_failed_logins
from backend.security.password import check_password_strength, hash_password, needs_rehash, verify_password
from backend.security.rate_limit import check_rate_limit
from backend.security.tokens import (
    TokenError,
    create_access_token,
    decode_token,
    generate_url_safe_token,
    hash_token,
)
from backend.security import totp
from backend.services import auth_service
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/auth", tags=["auth"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    check_rate_limit(request, scope="auth", limit=settings.rate_limit_auth, window=settings.rate_limit_window_seconds)

    strength = check_password_strength(payload.password)
    if not strength.ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"message": "Weak password", "feedback": strength.feedback})

    if auth_service.email_exists(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    if auth_service.username_exists(db, payload.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "This username is taken")

    user = auth_service.register_user(db, payload)
    ctx = build_client_context(request)
    write_audit(
        db,
        event="REGISTER",
        user_id=user.id,
        ip_address=ctx.ip_address,
        device_info=ctx.user_agent[:512],
        result="SUCCESS",
        details={"email": user.email, "username": user.username},
    )
    # In a real deployment an email with the verification token is sent here.
    return user


@router.post("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.email_verify_token == token)).scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired verification token")
    user.is_email_verified = True
    user.email_verify_token = None
    db.commit()
    write_audit(db, event="EMAIL_VERIFIED", user_id=user.id, result="SUCCESS")
    return {"message": "Email verified"}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    check_rate_limit(request, scope="auth", limit=settings.rate_limit_auth, window=settings.rate_limit_window_seconds)
    ctx = build_client_context(request)

    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()

    # Account lockout check (deterministic).
    if user and user.is_locked:
        evaluate_login(db, user=user, ctx=ctx, success=False, failure_reason="ACCOUNT_LOCKED")
        raise HTTPException(
            status.HTTP_423_LOCKED,
            f"Account temporarily locked. Try again after {settings.lockout_minutes} minutes.",
        )
    if user and not user.is_active:
        evaluate_login(db, user=user, ctx=ctx, success=False, failure_reason="ACCOUNT_DISABLED")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account is disabled")

    verified_user = None
    if user and verify_password(payload.password, user.password_hash):
        # Transparent hash upgrade (bcrypt -> argon2 or parameter change).
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(payload.password)
            db.commit()
        verified_user = user

    if verified_user is None:
        if user:
            register_failed_login(db, user)
        evaluate_login(db, user=user, ctx=ctx, success=False, failure_reason="INVALID_CREDENTIALS")
        # Generic message: do not reveal whether the email exists.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    # Successful password check -> run risk evaluation (AI + deterministic rules).
    reset_failed_logins(db, verified_user)
    decision = evaluate_login(db, user=verified_user, ctx=ctx, success=True)

    if decision.action == "BLOCK":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Login blocked by security policy")

    access_token, refresh_token, expires_in, session = auth_service.issue_tokens(db, verified_user, ctx)

    requires_mfa = bool(verified_user.mfa_enabled) or decision.action == "MFA_REQUIRED"
    if requires_mfa:
        session.is_mfa_verified = False
        db.commit()

    max_age = settings.refresh_token_expire_days * 24 * 3600
    set_refresh_cookie(response, refresh_token, max_age)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=expires_in,
        requires_mfa=requires_mfa,
        role=verified_user.role,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
def verify_mfa(payload: MFACodeRequest, request: Request, response: Response, user: User = Depends(auth_deps.get_current_user), db: Session = Depends(get_db)):
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enabled for this account")
    if not totp.verify_code(user.mfa_secret, payload.code):
        write_audit(db, event="MFA_FAILURE", user_id=user.id, result="FAILURE", risk_level=Severity.MEDIUM)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code")

    # Mark the active session as MFA-verified and re-issue an access token.
    ctx = build_client_context(request)
    sid = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            sid = decode_token(auth.split(" ", 1)[1].strip(), expected_type="access").get("sid")
        except TokenError:
            sid = None
    from backend.models.entities import UserSession

    session = db.execute(select(UserSession).where(UserSession.sid == sid)).scalar_one_or_none() if sid else None
    if session:
        session.is_mfa_verified = True
        db.commit()

    access_token, expires_in = create_access_token(user.id, user.role.value, sid)
    write_audit(db, event="MFA_SUCCESS", user_id=user.id, ip_address=ctx.ip_address, result="SUCCESS")
    return TokenResponse(
        access_token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=expires_in,
        requires_mfa=False,
        role=user.role,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("ecoshield_refresh")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")
    try:
        payload = decode_token(token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user = db.get(User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session")

    sid = payload.get("sid")
    from backend.models.entities import UserSession

    session = db.execute(select(UserSession).where(UserSession.sid == sid)).scalar_one_or_none() if sid else None
    if not session or session.revoked or session.expires_at < _now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or revoked")
    # Bind the refresh cookie to the stored session hash (prevents token substitution).
    if session.token_hash != hash_token(token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session")

    access_token, expires_in = create_access_token(user.id, user.role.value, sid)
    session.last_seen_at = _now()
    db.commit()
    return TokenResponse(
        access_token=access_token,
        refresh_token="",
        token_type="bearer",
        expires_in=expires_in,
        requires_mfa=False,
        role=user.role,
    )


@router.post("/logout")
def logout(request: Request, response: Response, user: User = Depends(auth_deps.get_current_user), db: Session = Depends(get_db)):
    # Server-side logout: revoke all refresh sessions for the user.
    auth_service.revoke_all_sessions(db, user.id)
    ctx = build_client_context(request)
    write_audit(db, event="LOGOUT", user_id=user.id, ip_address=ctx.ip_address, result="SUCCESS")
    clear_refresh_cookie(response)
    return {"message": "Logged out"}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    check_rate_limit(request, scope="auth", limit=settings.rate_limit_auth, window=settings.rate_limit_window_seconds)
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    # Always return the same message to prevent user enumeration.
    generic = {"message": "If an account exists for that email, a reset link has been sent."}
    if not user:
        return generic

    raw_token = generate_url_safe_token(32)
    user.password_reset_token = hash_token(raw_token)
    user.password_reset_expires = _now() + timedelta(minutes=30)
    db.commit()
    write_audit(db, event="PASSWORD_RESET_REQUESTED", user_id=user.id, result="SUCCESS")
    # In production this token is emailed; in dev we log it for testing.
    if settings.environment != "production":
        generic["dev_reset_token"] = raw_token
    return generic


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    strength = check_password_strength(payload.new_password)
    if not strength.ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"message": "Weak password", "feedback": strength.feedback})

    token_hash = hash_token(payload.token)
    user = db.execute(select(User).where(User.password_reset_token == token_hash)).scalar_one_or_none()
    if not user or not user.password_reset_expires or user.password_reset_expires < _now():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")

    user.password_hash = hash_password(payload.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()
    auth_service.revoke_all_sessions(db, user.id)
    write_audit(db, event="PASSWORD_RESET", user_id=user.id, result="SUCCESS", risk_level=Severity.MEDIUM)
    return {"message": "Password has been reset. Please sign in again."}


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, user: User = Depends(auth_deps.get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    strength = check_password_strength(payload.new_password)
    if not strength.ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"message": "Weak password", "feedback": strength.feedback})

    user.password_hash = hash_password(payload.new_password)
    db.commit()
    ctx = build_client_context(request)
    write_audit(db, event="PASSWORD_CHANGE", user_id=user.id, ip_address=ctx.ip_address, result="SUCCESS", risk_level=Severity.MEDIUM)
    return {"message": "Password updated"}


@router.post("/password-strength")
def password_strength(password: str):
    result = check_password_strength(password)
    return {"score": result.score, "ok": result.ok, "feedback": result.feedback}


@router.post("/mfa/enable")
def enable_mfa(request: Request, user: User = Depends(auth_deps.get_current_user), db: Session = Depends(get_db)):
    secret = totp.generate_secret()
    user.mfa_secret = secret
    user.mfa_enabled = True
    db.commit()
    write_audit(db, event="MFA_ENABLED", user_id=user.id, result="SUCCESS")
    return {
        "secret": secret,
        "provisioning_uri": totp.provisioning_uri(secret, user.email),
        "message": "Scan with an authenticator app, then confirm with a 6-digit code.",
    }


@router.post("/mfa/disable")
def disable_mfa(user: User = Depends(auth_deps.get_current_user), db: Session = Depends(get_db)):
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    write_audit(db, event="MFA_DISABLED", user_id=user.id, result="SUCCESS", risk_level=Severity.MEDIUM)
    return {"message": "MFA disabled"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(auth_deps.get_current_user)):
    return user
