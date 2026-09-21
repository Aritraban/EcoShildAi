"""Deterministic login security guard.

This is the authority for security *decisions*. The AI anomaly detector
(``ai/anomaly.py``) contributes an advisory risk score and explainable reasons,
but hard, deterministic rules below always run and can raise risk independently.
This satisfies the requirement: "Do not make security decisions solely from AI
predictions."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.ai.anomaly import detector
from backend.config import settings
from backend.models.entities import LoginEvent, Role, Severity, User
from backend.security.audit import write_audit
from backend.security.events import (
    create_notification,
    record_login_event,
    record_security_event,
    risk_to_severity,
)
from backend.utils.request_context import ClientContext


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LoginDecision:
    risk_score: int
    severity: Severity
    action: str  # ALLOW | MFA_REQUIRED | BLOCK
    reasons: List[str] = field(default_factory=list)
    ai_model: str = "baseline"


IMPOSSIBLE_TRAVEL_HOURS = 3.0


def _recent_failures_for_user(db: Session, user_id: int, minutes: int = 30) -> int:
    since = _now() - timedelta(minutes=minutes)
    return int(
        db.execute(
            select(func.count(LoginEvent.id)).where(
                LoginEvent.user_id == user_id,
                LoginEvent.success.is_(False),
                LoginEvent.created_at >= since,
            )
        ).scalar_one()
    )


def _ip_failure_count(db: Session, ip: str, minutes: int = 10) -> int:
    since = _now() - timedelta(minutes=minutes)
    return int(
        db.execute(
            select(func.count(LoginEvent.id)).where(
                LoginEvent.ip_address == ip,
                LoginEvent.success.is_(False),
                LoginEvent.created_at >= since,
            )
        ).scalar_one()
    )


def _last_success(db: Session, user_id: int) -> Optional[LoginEvent]:
    return db.execute(
        select(LoginEvent)
        .where(LoginEvent.user_id == user_id, LoginEvent.success.is_(True))
        .order_by(LoginEvent.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def evaluate_login(
    db: Session,
    *,
    user: Optional[User],
    ctx: ClientContext,
    success: bool,
    failure_reason: Optional[str] = None,
) -> LoginDecision:
    """Score a login attempt, persist events, and decide on an action."""
    user_id = user.id if user else None
    history = []
    if user_id is not None:
        history = (
            db.execute(
                select(LoginEvent)
                .where(LoginEvent.user_id == user_id)
                .order_by(LoginEvent.created_at.desc())
                .limit(50)
            )
            .scalars()
            .all()
        )

    recent_failures = _recent_failures_for_user(db, user_id) if user_id else 0

    attempt = {
        "timestamp": _now(),
        "hour": _now().hour,
        "country": ctx.country,
        "device_type": ctx.device_type,
        "browser": ctx.browser,
        "recent_failures": recent_failures,
    }

    # --- AI advisory signal (explainable) ---
    ai = detector.score(attempt, history)
    reasons = list(ai.reasons)
    risk = ai.risk_score

    # --- Deterministic hard rules (always applied) ---
    if not success:
        risk = max(risk, 40)
        if failure_reason:
            reasons.append(f"Authentication failed: {failure_reason}")

    ip_failures = _ip_failure_count(db, ctx.ip_address)
    if ip_failures >= settings.max_failed_logins:
        risk = max(risk, 85)
        reasons.append(f"{ip_failures} failed attempts from this IP in the last 10 minutes (brute-force pattern)")

    last = _last_success(db, user_id) if user_id else None
    if last and success and last.country and last.created_at:
        prev_country = (last.country or "").upper()
        if prev_country != ctx.country.upper() and prev_country not in ("LOCAL", "UNKNOWN"):
            hours = (_now() - (last.created_at if last.created_at.tzinfo else last.created_at.replace(tzinfo=timezone.utc))).total_seconds() / 3600.0
            if 0 <= hours <= IMPOSSIBLE_TRAVEL_HOURS:
                risk = max(risk, 90)
                reasons.append(
                    f"Impossible travel: {prev_country} -> {ctx.country} within {hours:.1f}h"
                )

    risk = max(0, min(100, risk))
    severity = risk_to_severity(risk)

    # --- Decide action (deterministic) ---
    action = "ALLOW"
    if not success:
        action = "BLOCK" if risk >= 71 else "ALLOW"
    else:
        if risk >= 71:
            action = "MFA_REQUIRED"
        elif risk >= 31 and user and user.mfa_enabled:
            action = "MFA_REQUIRED"

    # --- Persist login event ---
    record_login_event(
        db,
        user_id=user_id,
        email=user.email if user else None,
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        device_type=ctx.device_type,
        browser=ctx.browser,
        country=ctx.country,
        success=success,
        risk_score=risk,
        failure_reason=failure_reason,
    )

    # --- Escalate to a security event + notification for high risk ---
    if risk >= 71:
        record_security_event(
            db,
            event_type="Suspicious Login",
            reason="; ".join(reasons) or "High-risk login behaviour",
            risk_score=risk,
            user_id=user_id,
            action=action,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            metadata={"ai_model": ai.model_used, "features": ai.features, "country": ctx.country},
        )
        if user:
            create_notification(
                db,
                user=user,
                title="Security alert: suspicious sign-in",
                message=(
                    f"We detected a {'failed ' if not success else ''}sign-in from {ctx.country} "
                    f"({ctx.browser} on {ctx.device_type}). Reasons: {'; '.join(reasons)}."
                ),
                severity=severity,
            )

    write_audit(
        db,
        event="LOGIN_SUCCESS" if success else "LOGIN_FAILURE",
        user_id=user_id,
        ip_address=ctx.ip_address,
        device_info=ctx.user_agent[:512],
        result="SUCCESS" if success else "FAILURE",
        risk_level=severity,
        details={"risk_score": risk, "action": action, "reasons": reasons, "ai_model": ai.model_used},
    )

    return LoginDecision(risk_score=risk, severity=severity, action=action, reasons=reasons, ai_model=ai.model_used)


def register_failed_login(db: Session, user: User) -> bool:
    """Increment the failure counter and lock the account past the threshold.

    Returns True if the account was locked.
    """
    user.failed_login_count = (user.failed_login_count or 0) + 1
    locked = False
    if user.failed_login_count >= settings.max_failed_logins:
        user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
        locked = True
        record_security_event(
            db,
            event_type="Account Lockout",
            reason=f"Locked after {settings.max_failed_logins} consecutive failed logins",
            risk_score=75,
            user_id=user.id,
            action="ACCOUNT_LOCKED",
        )
        create_notification(
            db,
            user=user,
            title="Account temporarily locked",
            message=(
                f"Too many failed sign-in attempts. Your account is locked for "
                f"{settings.lockout_minutes} minutes for your protection."
            ),
            severity=Severity.HIGH,
        )
    db.commit()
    return locked


def reset_failed_logins(db: Session, user: User) -> None:
    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None
        db.commit()
