"""Authentication service: registration, session lifecycle, token issuance."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models.entities import Role, User, UserProfile, UserSession
from backend.models.schemas import RegisterRequest
from backend.security.password import hash_password
from backend.security.tokens import (
    create_access_token,
    create_refresh_token,
    generate_url_safe_token,
    hash_token,
)
from backend.utils.request_context import ClientContext


def _now() -> datetime:
    return datetime.now(timezone.utc)


def email_exists(db: Session, email: str) -> bool:
    return db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none() is not None


def username_exists(db: Session, username: str) -> bool:
    return db.execute(select(User).where(User.username == username)).scalar_one_or_none() is not None


def register_user(db: Session, data: RegisterRequest) -> User:
    user = User(
        email=data.email.lower(),
        username=data.username,
        password_hash=hash_password(data.password),
        role=Role.USER,
        email_verify_token=generate_url_safe_token(24),
    )
    db.add(user)
    db.flush()
    db.add(
        UserProfile(
            user_id=user.id,
            full_name=data.full_name,
            country=data.country,
            city=data.city,
        )
    )
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, email: str, password: str) -> Optional[User]:
    from backend.security.password import verify_password

    user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def issue_tokens(db: Session, user: User, ctx: ClientContext) -> Tuple[str, str, int, UserSession]:
    """Create a server-side session and return access+refresh tokens."""
    sid = uuid.uuid4().hex
    refresh_raw, refresh_hash, expires_at = create_refresh_token(user.id, sid)
    access_token, expires_in = create_access_token(user.id, user.role.value, sid)

    session = UserSession(
        user_id=user.id,
        sid=sid,
        token_hash=refresh_hash,
        ip_address=ctx.ip_address[:64],
        user_agent=ctx.user_agent[:512],
        device_type=ctx.device_type[:32],
        expires_at=expires_at,
        last_seen_at=_now(),
    )
    db.add(session)
    user.last_login_at = _now()
    db.commit()
    db.refresh(session)
    return access_token, refresh_raw, expires_in, session


def revoke_all_sessions(db: Session, user_id: int) -> int:
    sessions = db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars().all()
    for s in sessions:
        s.revoked = True
    db.commit()
    return len(sessions)


def purge_expired_sessions(db: Session) -> int:
    from backend.utils.timeutil import as_aware

    now = _now()
    all_sessions = db.execute(select(UserSession)).scalars().all()
    count = 0
    for s in all_sessions:
        exp = as_aware(s.expires_at)
        if exp is None or exp < now:
            db.delete(s)
            count += 1
    db.commit()
    return count
