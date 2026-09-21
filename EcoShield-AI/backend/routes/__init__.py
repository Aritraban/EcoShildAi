"""Aggregate all API routers under a single versioned router."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.routes import admin, ai, auth, carbon, dashboard, profile, security
from backend.security.cookies import CSRF_COOKIE, set_csrf_cookie

api_router = APIRouter()


@api_router.get("/csrf-token", include_in_schema=False)
def csrf_token(request: Request):
    """Issues/refreshes the CSRF cookie and returns the token for the SPA to echo."""
    token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
    response = JSONResponse({"csrf_token": token})
    set_csrf_cookie(response, token)
    return response


@api_router.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "EcoShield AI API"}


for _r in (auth.router, carbon.router, dashboard.router, ai.router, security.router, admin.router, profile.router):
    api_router.include_router(_r)
