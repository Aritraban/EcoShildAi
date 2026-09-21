"""User-facing Security Center routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import LoginEvent, SecurityEvent, Severity, User
from backend.models.schemas import LoginEventOut, SecurityEventOut, SecurityReportRequest
from backend.security.audit import write_audit
from backend.security.deps import get_current_user
from backend.security.events import record_security_event
from backend.services import security_service
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/events")
def my_security_events(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.user_id == user.id)
            .order_by(SecurityEvent.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )
    return {"events": [SecurityEventOut.model_validate(e) for e in events]}


@router.get("/login-history")
def my_login_history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    events = list(
        db.execute(
            select(LoginEvent)
            .where(LoginEvent.user_id == user.id)
            .order_by(LoginEvent.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )
    return {"logins": [LoginEventOut.model_validate(e) for e in events]}


@router.get("/status")
def my_security_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    failed = int(
        db.execute(
            select(func.count(LoginEvent.id)).where(LoginEvent.user_id == user.id, LoginEvent.success.is_(False))
        ).scalar_one()
    )
    alerts = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.user_id == user.id, SecurityEvent.resolved.is_(False)
            )
        ).scalar_one()
    )
    high = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.user_id == user.id, SecurityEvent.severity.in_([Severity.HIGH, Severity.CRITICAL])
            )
        ).scalar_one()
    )
    locked = user.is_locked
    return {
        "account_status": "LOCKED" if locked else ("PROTECTED" if alerts == 0 else "ATTENTION"),
        "mfa_enabled": user.mfa_enabled,
        "email_verified": user.is_email_verified,
        "failed_logins": failed,
        "open_alerts": alerts,
        "high_risk_events": high,
        "last_login_at": user.last_login_at,
    }


@router.post("/report")
def report_suspicious(payload: SecurityReportRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ctx = build_client_context(request)
    event = record_security_event(
        db,
        event_type=f"User Report: {payload.event_type}"[:80],
        reason=payload.description,
        risk_score=60,
        user_id=user.id,
        action="USER_REPORTED",
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        metadata={"target_user_id": payload.target_user_id},
    )
    write_audit(
        db,
        event="SECURITY_REPORT",
        user_id=user.id,
        ip_address=ctx.ip_address,
        result="SUCCESS",
        risk_level=Severity.MEDIUM,
        details={"security_event_id": event.id},
    )
    return {"message": "Report received. Our security team will review it.", "event_id": event.id}
