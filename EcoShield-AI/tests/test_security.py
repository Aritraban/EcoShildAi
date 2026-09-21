"""Security tests: CSRF, headers, injection, XSS, rate limiting, audit integrity.

These use safe, non-destructive checks - they verify that defences work rather
than performing real attacks.
"""
from __future__ import annotations

from conftest import auth_headers, csrf, login


def test_csrf_blocks_unsafe_request_without_token(client):
    # No X-CSRF-Token header -> rejected by the double-submit middleware.
    r = client.post("/api/auth/login", json={"email": "user@ecoshield.app", "password": "EcoShield#User1"})
    assert r.status_code == 403
    assert "CSRF" in r.json()["detail"]


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in {k.lower() for k in r.headers.keys()}


def test_sql_injection_attempt_is_harmless(client):
    # Parameterised queries: this must not authenticate or error out abnormally.
    r = client.post(
        "/api/auth/login",
        json={"email": "admin@ecoshield.app", "password": "' OR '1'='1"},
        headers=csrf(client),
    )
    assert r.status_code == 401


def test_xss_sanitisation_helpers():
    from backend.utils.sanitize import sanitize_text, strip_tags

    assert "&lt;script&gt;" in sanitize_text("<script>alert(1)</script>")
    assert "<" not in strip_tags("<img src=x onerror=alert(1)>")


def test_username_pattern_blocks_script_injection(client):
    r = client.post(
        "/api/auth/register",
        json={"email": "xss@ecoshield.app", "username": "<script>", "password": "StrongPass1"},
        headers=csrf(client),
    )
    assert r.status_code == 422  # rejected by the username pattern validator


def test_rate_limiting_on_auth(client):
    from backend.config import settings

    h = csrf(client)
    statuses = []
    for i in range(settings.rate_limit_auth + 4):
        r = client.post("/api/auth/login", json={"email": f"nobody{i}@ecoshield.app", "password": "x"}, headers=h)
        statuses.append(r.status_code)
    assert 429 in statuses


def test_brute_force_creates_security_event(client, admin_headers):
    from backend.config import settings

    h = csrf(client)
    for _ in range(settings.max_failed_logins + 1):
        client.post("/api/auth/login", json={"email": "target@ecoshield.app", "password": "bad"}, headers=h)
    events = client.get("/api/admin/security/events", headers=admin_headers).json()["events"]
    assert any(e["event_type"] == "Suspicious Login" for e in events)


def test_audit_chain_detects_tampering(client, secadmin_headers):
    from backend.database import SessionLocal
    from backend.models.entities import AuditLog
    from backend.security.audit import verify_chain
    from sqlalchemy import select

    with SessionLocal() as db:
        ok, _ = verify_chain(db)
        assert ok is True

        # Simulate tampering by altering a stored detail without recomputing the hash.
        log = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one()
        log.details_json = '{"tampered": true}'
        db.commit()

    with SessionLocal() as db:
        ok, broken_id = verify_chain(db)
        assert ok is False
        assert broken_id is not None


def test_error_does_not_leak_internals(client):
    r = client.get("/api/carbon/history")  # missing auth
    assert r.status_code == 401
    assert "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()
