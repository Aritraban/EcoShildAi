"""Profile, privacy (export/delete), and notification routes."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import (
    CarbonPrediction,
    CarbonRecord,
    LoginEvent,
    Notification,
    Recommendation,
    User,
    UserProfile,
    UserSession,
)
from backend.models.schemas import ProfileOut, ProfileUpdate
from backend.security.audit import write_audit
from backend.security.deps import get_current_user
from backend.services import auth_service
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/profile", tags=["profile"])


@router.get("", response_model=ProfileOut)
def get_profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.execute(select(UserProfile).where(UserProfile.user_id == user.id)).scalar_one_or_none()
    if profile is None:
        profile = UserProfile(user_id=user.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)
    return profile


@router.put("", response_model=ProfileOut)
def update_profile(payload: ProfileUpdate, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.execute(select(UserProfile).where(UserProfile.user_id == user.id)).scalar_one_or_none()
    if profile is None:
        profile = UserProfile(user_id=user.id)
        db.add(profile)
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(profile, field, value)
    db.commit()
    db.refresh(profile)
    ctx = build_client_context(request)
    write_audit(db, event="PROFILE_UPDATE", user_id=user.id, ip_address=ctx.ip_address, result="SUCCESS")
    return profile


@router.get("/notifications")
def list_notifications(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notes = list(
        db.execute(
            select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(50)
        )
        .scalars()
        .all()
    )
    return {
        "notifications": [
            {
                "id": n.id,
                "type": n.type,
                "title": n.title,
                "message": n.message,
                "severity": n.severity.value if hasattr(n.severity, "value") else str(n.severity),
                "read": n.read,
                "created_at": n.created_at,
            }
            for n in notes
        ]
    }


@router.post("/notifications/{note_id}/read")
def mark_read(note_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.get(Notification, note_id)
    if not note or note.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    note.read = True
    db.commit()
    return {"message": "Marked as read"}


@router.get("/export")
def export_data(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """User data export (privacy-by-design / data portability).

    Excludes secrets: password hashes, tokens, and MFA secrets are never included.
    """
    ctx = build_client_context(request)
    profile = db.execute(select(UserProfile).where(UserProfile.user_id == user.id)).scalar_one_or_none()
    records = db.execute(select(CarbonRecord).where(CarbonRecord.user_id == user.id)).scalars().all()
    predictions = db.execute(select(CarbonPrediction).where(CarbonPrediction.user_id == user.id)).scalars().all()
    recommendations = db.execute(select(Recommendation).where(Recommendation.user_id == user.id)).scalars().all()

    payload = {
        "account": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role.value,
            "created_at": user.created_at.isoformat(),
        },
        "profile": {
            "full_name": profile.full_name if profile else None,
            "country": profile.country if profile else None,
            "city": profile.city if profile else None,
            "timezone": profile.timezone if profile else None,
        },
        "carbon_records": [
            {
                "id": r.id,
                "period": r.period.value if hasattr(r.period, "value") else str(r.period),
                "reference_date": (r.reference_date or r.created_at).isoformat(),
                "total_co2e": r.total_co2e,
                "transport_co2e": r.transport_co2e,
                "energy_co2e": r.energy_co2e,
                "food_co2e": r.food_co2e,
                "shopping_co2e": r.shopping_co2e,
                "waste_co2e": r.waste_co2e,
            }
            for r in records
        ],
        "predictions": [
            {
                "predicted_next_month": p.predicted_next_month,
                "predicted_annual": p.predicted_annual,
                "created_at": p.created_at.isoformat(),
            }
            for p in predictions
        ],
        "recommendations": [{"title": rec.title, "category": rec.category} for rec in recommendations],
    }
    write_audit(db, event="DATA_EXPORT", user_id=user.id, ip_address=ctx.ip_address, result="SUCCESS")
    return payload


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Account deletion (right to be forgotten). Cascades remove related data."""
    ctx = build_client_context(request)
    user_id = user.id
    write_audit(db, event="ACCOUNT_DELETION", user_id=user_id, ip_address=ctx.ip_address, result="SUCCESS")
    # Sessions/login events reference the user; delete sessions first, then user.
    for s in db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars().all():
        db.delete(s)
    db.delete(user)
    db.commit()
    return None
