"""Tamper-evident audit logging.

Every entry stores ``prev_hash`` and an ``integrity_hash`` computed over the
entry contents chained to the previous entry. Modifying or deleting a row breaks
the chain, which ``verify_chain`` detects. Logs are append-only: the API never
exposes an update or delete path for them.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.entities import AuditLog, Severity


def _compute_hash(entry: dict[str, Any]) -> str:
    canonical = json.dumps(entry, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash(db: Session) -> Optional[str]:
    last = db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    return last.integrity_hash if last else None


def write_audit(
    db: Session,
    event: str,
    *,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    device_info: Optional[str] = None,
    result: str = "SUCCESS",
    risk_level: Severity = Severity.LOW,
    details: Optional[dict[str, Any]] = None,
    commit: bool = True,
) -> AuditLog:
    """Append an audit entry and chain its integrity hash to the previous one."""
    details_json = json.dumps(details or {}, default=str)
    prev_hash = _last_hash(db)

    log = AuditLog(
        user_id=user_id,
        event=event[:80],
        ip_address=(ip_address or "")[:64] or None,
        device_info=(device_info or "")[:512] or None,
        result=result[:20],
        risk_level=risk_level,
        details_json=details_json,
        prev_hash=prev_hash,
        integrity_hash="",  # placeholder, filled below
    )

    payload = {
        "event": log.event,
        "user_id": log.user_id,
        "ip_address": log.ip_address,
        "device_info": log.device_info,
        "result": log.result,
        "risk_level": log.risk_level.value if isinstance(log.risk_level, Severity) else log.risk_level,
        "details_json": details_json,
        "prev_hash": prev_hash,
    }
    log.integrity_hash = _compute_hash(payload)

    db.add(log)
    if commit:
        db.commit()
        db.refresh(log)
    else:
        db.flush()
    return log


def verify_chain(db: Session) -> tuple[bool, Optional[int]]:
    """Recompute the hash chain. Returns (ok, first_broken_id)."""
    logs = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    prev: Optional[str] = None
    for log in logs:
        payload = {
            "event": log.event,
            "user_id": log.user_id,
            "ip_address": log.ip_address,
            "device_info": log.device_info,
            "result": log.result,
            "risk_level": log.risk_level.value if isinstance(log.risk_level, Severity) else log.risk_level,
            "details_json": log.details_json,
            "prev_hash": prev,
        }
        expected = _compute_hash(payload)
        if expected != log.integrity_hash or log.prev_hash != prev:
            return False, log.id
        prev = log.integrity_hash
    return True, None
