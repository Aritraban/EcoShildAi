"""Security monitoring service backing the admin dashboard."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from backend.models.entities import (
    AuditLog,
    LoginEvent,
    SecurityEvent,
    Severity,
    User,
    UserSession,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def admin_stats(db: Session) -> Dict:
    total_users = int(db.execute(select(func.count(User.id))).scalar_one())
    now = _now()
    from backend.utils.timeutil import as_aware

    all_sessions = db.execute(select(UserSession).where(UserSession.revoked.is_(False))).scalars().all()
    active_sessions = sum(1 for s in all_sessions if (as_aware(s.expires_at) or now) > now)
    failed_logins = int(
        db.execute(select(func.count(LoginEvent.id)).where(LoginEvent.success.is_(False))).scalar_one()
    )
    suspicious_logins = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(SecurityEvent.event_type == "Suspicious Login")
        ).scalar_one()
    )
    high_risk = int(
        db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity.in_([Severity.HIGH, Severity.CRITICAL])
            )
        ).scalar_one()
    )
    blocked_ips = int(
        db.execute(
            select(func.count(distinct(SecurityEvent.ip_address))).where(
                SecurityEvent.severity.in_([Severity.HIGH, Severity.CRITICAL]),
                SecurityEvent.resolved.is_(False),
                SecurityEvent.ip_address.is_not(None),
            )
        ).scalar_one()
    )
    unresolved_alerts = int(
        db.execute(select(func.count(SecurityEvent.id)).where(SecurityEvent.resolved.is_(False))).scalar_one()
    )

    recent_logs = list(
        db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(15)).scalars().all()
    )

    # Overall posture.
    if high_risk >= 5 or unresolved_alerts >= 10:
        status = "ELEVATED"
    elif unresolved_alerts > 0:
        status = "MONITORING"
    else:
        status = "PROTECTED"

    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "failed_logins": failed_logins,
        "suspicious_logins": suspicious_logins,
        "high_risk_events": high_risk,
        "blocked_ips": blocked_ips,
        "security_alerts": unresolved_alerts,
        "recent_audit_logs": recent_logs,
        "system_status": status,
    }


def recent_security_events(db: Session, limit: int = 50, severity: Severity | None = None) -> List[SecurityEvent]:
    q = select(SecurityEvent)
    if severity is not None:
        q = q.where(SecurityEvent.severity == severity)
    q = q.order_by(SecurityEvent.created_at.desc()).limit(limit)
    return list(db.execute(q).scalars().all())


def recent_login_events(db: Session, limit: int = 50) -> List[LoginEvent]:
    return list(
        db.execute(select(LoginEvent).order_by(LoginEvent.created_at.desc()).limit(limit)).scalars().all()
    )


def recent_audit_logs(db: Session, limit: int = 100) -> List[AuditLog]:
    return list(db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).scalars().all())
