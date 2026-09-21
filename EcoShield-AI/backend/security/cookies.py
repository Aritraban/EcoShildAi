"""Secure cookie helpers and CSRF (double-submit) protection.

- The refresh token lives in an HttpOnly, SameSite cookie (not readable by JS),
  which mitigates XSS token theft.
- A separate non-HttpOnly CSRF cookie carries a random token that the frontend
  must echo back in the ``X-CSRF-Token`` header on unsafe methods (double-submit
  pattern), which mitigates CSRF.
"""
from __future__ import annotations

import secrets

from fastapi import Request, Response

from backend.config import settings

REFRESH_COOKIE = "ecoshield_refresh"
CSRF_COOKIE = "ecoshield_csrf"
CSRF_HEADER = "x-csrf-token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def set_refresh_cookie(response: Response, refresh_token: str, max_age: int) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path=f"{settings.api_prefix}/auth",
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path=f"{settings.api_prefix}/auth",
    )


def ensure_csrf_cookie(request: Request, response: Response) -> str:
    """Return the current CSRF token, setting the cookie if absent."""
    token = request.cookies.get(CSRF_COOKIE)
    if not token:
        token = secrets.token_urlsafe(32)
    set_csrf_cookie(response, token)
    return token


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        max_age=60 * 60 * 8,
        httponly=False,  # JS must read it to echo in the header
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def validate_csrf(request: Request) -> bool:
    """Double-submit check for unsafe methods."""
    if request.method not in UNSAFE_METHODS:
        return True
    cookie_token = request.cookies.get(CSRF_COOKIE)
    header_token = request.headers.get(CSRF_HEADER)
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)
