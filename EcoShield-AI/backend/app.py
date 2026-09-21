"""EcoShield AI - FastAPI application entrypoint.

Run from the project root:
    uvicorn backend.app:app --reload
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.config import settings
from backend.database import SessionLocal, init_db
from backend.routes import api_router
from backend.security.cookies import CSRF_HEADER, UNSAFE_METHODS, validate_csrf
from backend.security.rate_limit import limiter
from backend.services import auth_service
from backend.services.seed import seed_all

logging.basicConfig(level=logging.INFO if not settings.debug else logging.DEBUG)
logger = logging.getLogger("ecoshield")

FRONTEND_DIR = (Path(__file__).resolve().parent.parent / "frontend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    init_db()
    with SessionLocal() as db:
        include_demo = settings.environment != "production"
        result = seed_all(db, include_demo=include_demo)
        logger.info(
            "Seed complete: %s factors, staff ready%s",
            result["factors_inserted"],
            ", demo user ready" if result.get("demo_user") else "",
        )
        auth_service.purge_expired_sessions(db)
    yield
    # --- Shutdown ---
    logger.info("Shutting down EcoShield AI")


app = FastAPI(
    title="EcoShield AI",
    description="AI-powered carbon footprint & cybersecurity monitoring platform.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
)

# ------------------------------- CORS ---------------------------------- #
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", CSRF_HEADER],
)


# ------------------- Security / CSRF / rate-limit middleware ------------ #
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path

    # Global rate limiting for API traffic (defence against excessive requests).
    if path.startswith(settings.api_prefix):
        ip = request.client.host if request.client else "unknown"
        result = limiter.hit(f"global:{ip}", settings.rate_limit_default, settings.rate_limit_window_seconds)
        if not result.allowed:
            return JSONResponse(
                {"detail": "Too many requests. Please slow down."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(result.retry_after)},
            )

        # CSRF double-submit validation on unsafe methods.
        if request.method in UNSAFE_METHODS and not validate_csrf(request):
            return JSONResponse(
                {"detail": "CSRF validation failed. Refresh the page and retry."},
                status_code=status.HTTP_403_FORBIDDEN,
            )

    response = await call_next(request)

    # Security headers on every response.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "connect-src 'self'; font-src 'self' data: https://fonts.gstatic.com; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if settings.cookie_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# --------------------------- Error handling ----------------------------- #
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Never leak internal detail; pass through only safe HTTP semantics.
    detail = exc.detail if isinstance(exc.detail, (str, dict, list)) else "Request failed"
    return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None) or {})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return field names and messages, but never the offending raw values.
    errors = []
    for err in exc.errors():
        errors.append({"field": ".".join(str(x) for x in err.get("loc", [])[1:]), "message": err.get("msg", "Invalid value")})
    return JSONResponse({"detail": "Validation failed", "errors": errors}, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Log internally; return a generic message externally.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ------------------------------- Routes --------------------------------- #
app.include_router(api_router, prefix=settings.api_prefix)

# Serve the static frontend (SPA) at the root when present.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=settings.debug)
