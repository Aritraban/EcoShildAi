"""Admin & Security-Admin routes (Role-Based Access Control enforced)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import EmissionFactor, Role, SecurityEvent, Severity, User, UserSession
from backend.models.schemas import EmissionFactorOut, EmissionFactorUpdate, SecurityEventOut
from backend.security.audit import verify_chain, write_audit
from backend.security.deps import require_admin, require_security_admin, require_staff
from backend.security.events import record_security_event
from backend.services import security_service
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/admin", tags=["admin"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------- Stats --------------------------------- #
@router.get("/stats")
def stats(admin: User = Depends(require_staff), db: Session = Depends(get_db)):
    return security_service.admin_stats(db)


# --------------------------- User management --------------------------- #
class UserAdminUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    return {
        "users": [
            {
                "id": u.id,
                "email": u.email,
                "username": u.username,
                "role": u.role.value,
                "is_active": u.is_active,
                "is_email_verified": u.is_email_verified,
                "locked_until": u.locked_until,
                "created_at": u.created_at,
                "last_login_at": u.last_login_at,
            }
            for u in users
        ]
    }


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserAdminUpdate, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.id == admin.id and payload.is_active is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot deactivate your own account")

    if payload.role is not None:
        target.role = payload.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
    db.commit()
    ctx = build_client_context(request)
    write_audit(
        db, event="ADMIN_USER_UPDATE", user_id=admin.id, ip_address=ctx.ip_address, result="SUCCESS",
        risk_level=Severity.MEDIUM, details={"target": user_id, "changes": payload.model_dump(exclude_unset=True, mode="json")},
    )
    return {"message": "User updated", "id": target.id}


# ------------------------ Emission factor admin ------------------------ #
@router.get("/emission-factors")
def list_factors(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    factors = db.execute(select(EmissionFactor).order_by(EmissionFactor.category, EmissionFactor.key)).scalars().all()
    return {"factors": [EmissionFactorOut.model_validate(f) for f in factors]}


@router.put("/emission-factors/{factor_id}")
def update_factor(factor_id: int, payload: EmissionFactorUpdate, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    factor = db.get(EmissionFactor, factor_id)
    if not factor:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emission factor not found")
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(factor, field, value)
    factor.updated_by = admin.id
    db.commit()
    db.refresh(factor)
    ctx = build_client_context(request)
    write_audit(
        db, event="EMISSION_FACTOR_UPDATE", user_id=admin.id, ip_address=ctx.ip_address, result="SUCCESS",
        details={"factor_id": factor_id, "key": factor.key, "value": factor.value},
    )
    return factor


# --------------------- Security event management ----------------------- #
@router.get("/security/events")
def security_events(severity: Severity | None = None, admin: User = Depends(require_staff), db: Session = Depends(get_db)):
    events = security_service.recent_security_events(db, limit=100, severity=severity)
    return {"events": [SecurityEventOut.model_validate(e) for e in events]}


@router.post("/security/events/{event_id}/resolve")
def resolve_event(event_id: int, request: Request, admin: User = Depends(require_security_admin), db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if not event:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    event.resolved = True
    db.commit()
    ctx = build_client_context(request)
    write_audit(
        db, event="SECURITY_EVENT_RESOLVED", user_id=admin.id, ip_address=ctx.ip_address, result="SUCCESS",
        details={"event_id": event_id},
    )
    return {"message": "Event marked resolved"}


class BlockRequest(BaseModel):
    minutes: int = Field(30, ge=1, le=10080)
    reason: str = Field("Temporary block by security admin", max_length=500)


@router.post("/security/block/{user_id}")
def block_user(user_id: int, payload: BlockRequest, request: Request, admin: User = Depends(require_security_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    target.locked_until = _now() + timedelta(minutes=payload.minutes)
    # Revoke active sessions.
    for s in db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars().all():
        s.revoked = True
    db.commit()
    record_security_event(
        db, event_type="Account Blocked", reason=payload.reason, risk_score=80,
        user_id=user_id, action="TEMP_BLOCK",
    )
    ctx = build_client_context(request)
    write_audit(
        db, event="ADMIN_BLOCK_USER", user_id=admin.id, ip_address=ctx.ip_address, result="SUCCESS",
        risk_level=Severity.HIGH, details={"target": user_id, "minutes": payload.minutes},
    )
    return {"message": f"User blocked for {payload.minutes} minutes"}


@router.post("/security/unblock/{user_id}")
def unblock_user(user_id: int, request: Request, admin: User = Depends(require_security_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    target.locked_until = None
    target.failed_login_count = 0
    db.commit()
    ctx = build_client_context(request)
    write_audit(db, event="ADMIN_UNBLOCK_USER", user_id=admin.id, ip_address=ctx.ip_address, result="SUCCESS", details={"target": user_id})
    return {"message": "User unblocked"}


# ----------------------------- Audit logs ------------------------------ #
@router.get("/audit-logs")
def audit_logs(limit: int = 100, admin: User = Depends(require_staff), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    logs = security_service.recent_audit_logs(db, limit=limit)
    return {"logs": logs}


@router.get("/audit-verify")
def audit_verify(admin: User = Depends(require_security_admin), db: Session = Depends(get_db)):
    ok, broken_id = verify_chain(db)
    return {"chain_valid": ok, "first_broken_id": broken_id}
