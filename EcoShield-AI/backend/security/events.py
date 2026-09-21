"""Helpers to record login events, security events and user notifications."""
from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.orm import Session

from backend.models.entities import (
    LoginEvent,
    Notification,
    SecurityEvent,
    Severity,
    User,
)


def record_login_event(
    db: Session,
    *,
    user_id: Optional[int],
    email: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str],
    device_type: Optional[str],
    browser: Optional[str],
    country: Optional[str],
    success: bool,
    risk_score: int = 0,
    failure_reason: Optional[str] = None,
    commit: bool = True,
) -> LoginEvent:
    event = LoginEvent(
        user_id=user_id,
        email=(email or "")[:255] or None,
        ip_address=(ip_address or "")[:64] or None,
        user_agent=(user_agent or "")[:512] or None,
        device_type=(device_type or "")[:32] or None,
        browser=(browser or "")[:64] or None,
        country=(country or "")[:80] or None,
        success=success,
        risk_score=max(0, min(100, int(risk_score))),
        failure_reason=(failure_reason or "")[:120] or None,
    )
    db.add(event)
    if commit:
        db.commit()
        db.refresh(event)
    else:
        db.flush()
    return event


def risk_to_severity(risk_score: int) -> Severity:
    if risk_score >= 85:
        return Severity.CRITICAL
    if risk_score >= 71:
        return Severity.HIGH
    if risk_score >= 31:
        return Severity.MEDIUM
    return Severity.LOW


def record_security_event(
    db: Session,
    *,
    event_type: str,
    reason: str,
    risk_score: int,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    commit: bool = True,
) -> SecurityEvent:
    event = SecurityEvent(
        user_id=user_id,
        event_type=event_type[:80],
        severity=risk_to_severity(risk_score),
        risk_score=max(0, min(100, int(risk_score))),
        reason=reason[:2000],
        action=(action or "")[:60] or None,
        ip_address=(ip_address or "")[:64] or None,
        user_agent=(user_agent or "")[:512] or None,
        metadata_json=json.dumps(metadata or {}, default=str),
    )
    db.add(event)
    if commit:
        db.commit()
        db.refresh(event)
    else:
        db.flush()
    return event


def create_notification(
    db: Session,
    *,
    user: User,
    title: str,
    message: str,
    severity: Severity = Severity.LOW,
    type_: str = "SECURITY",
    commit: bool = True,
) -> Notification:
    note = Notification(
        user_id=user.id,
        type=type_[:40],
        title=title[:160],
        message=message[:2000],
        severity=severity,
    )
    db.add(note)
    if commit:
        db.commit()
        db.refresh(note)
    else:
        db.flush()
    return note
