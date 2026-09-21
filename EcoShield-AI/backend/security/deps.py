"""FastAPI dependencies for authentication and Role-Based Access Control."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.entities import Role, User, UserSession
from backend.security.tokens import TokenError, decode_token
from backend.utils.timeutil import as_aware

# auto_error=False so we can return a clean 401 instead of FastAPI's default body.
bearer_scheme = HTTPBearer(auto_error=False)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    user_id = int(payload.get("sub", 0))
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account is inactive or unknown")
    if user.is_locked:
        raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked")

    # Bind the token to a live, non-revoked, non-expired session (server-side logout).
    sid = payload.get("sid")
    session = db.execute(
        select(UserSession).where(UserSession.sid == sid)
    ).scalar_one_or_none() if sid else None
    if session is None or session.revoked or as_aware(session.expires_at) < _now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired or revoked")

    session.last_seen_at = _now()
    db.commit()
    request.state.user_id = user.id
    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    return user


def require_roles(*roles: Role):
    """Dependency factory enforcing that the caller has one of ``roles``."""
    allowed: Iterable[Role] = roles

    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "You do not have permission to perform this action",
            )
        return user

    return _checker


# Convenience dependencies
require_admin = require_roles(Role.ADMIN)
require_security_admin = require_roles(Role.SECURITY_ADMIN)
require_staff = require_roles(Role.ADMIN, Role.SECURITY_ADMIN)
