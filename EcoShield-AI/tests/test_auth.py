"""Authentication, account protection and RBAC tests."""
from __future__ import annotations

from conftest import auth_headers, csrf, login


def test_register_and_login_flow(client):
    h = csrf(client)
    r = client.post(
        "/api/auth/register",
        json={"email": "newuser@ecoshield.app", "username": "newuser", "password": "StrongPass1", "full_name": "New User"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "USER"

    r = client.post("/api/auth/login", json={"email": "newuser@ecoshield.app", "password": "StrongPass1"}, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] and body["token_type"] == "bearer"

    me = client.get("/api/auth/me", headers=auth_headers(client, body["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "newuser@ecoshield.app"


def test_weak_password_rejected(client):
    h = csrf(client)
    r = client.post(
        "/api/auth/register",
        json={"email": "weak@ecoshield.app", "username": "weakuser", "password": "abc"},
        headers=h,
    )
    assert r.status_code in (400, 422)


def test_duplicate_email_rejected(client):
    h = csrf(client)
    payload = {"email": "dup@ecoshield.app", "username": "dupuser", "password": "StrongPass1"}
    assert client.post("/api/auth/register", json=payload, headers=h).status_code == 201
    r = client.post("/api/auth/register", json={**payload, "username": "dupuser2"}, headers=h)
    assert r.status_code == 409


def test_invalid_login_generic_message(client):
    r = client.post(
        "/api/auth/login",
        json={"email": "user@ecoshield.app", "password": "WrongPassword1"},
        headers=csrf(client),
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_account_lockout_after_repeated_failures(client):
    from backend.config import settings

    h = csrf(client)
    for _ in range(settings.max_failed_logins):
        client.post("/api/auth/login", json={"email": "user@ecoshield.app", "password": "bad"}, headers=h)
    # Even the correct password is refused while locked.
    r = client.post("/api/auth/login", json={"email": "user@ecoshield.app", "password": "EcoShield#User1"}, headers=h)
    assert r.status_code == 423


def test_unauthenticated_access_denied(client):
    assert client.get("/api/dashboard").status_code == 401


def test_rbac_user_cannot_access_admin(client, user_headers):
    assert client.get("/api/admin/stats", headers=user_headers).status_code == 403


def test_rbac_admin_cannot_access_security_admin_only(client, admin_headers):
    # audit-verify is restricted to SECURITY_ADMIN.
    assert client.get("/api/admin/audit-verify", headers=admin_headers).status_code == 403


def test_security_admin_can_verify_audit_chain(client, secadmin_headers):
    r = client.get("/api/admin/audit-verify", headers=secadmin_headers)
    assert r.status_code == 200
    assert r.json()["chain_valid"] is True


def test_logout_revokes_session(client):
    token = login(client, "user@ecoshield.app", "EcoShield#User1")
    h = auth_headers(client, token)
    assert client.get("/api/dashboard", headers=h).status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    # Token bound to a now-revoked session must be rejected.
    assert client.get("/api/dashboard", headers=h).status_code == 401


def test_password_change_requires_current(client, user_headers):
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "wrong", "new_password": "AnotherStrong1"},
        headers=user_headers,
    )
    assert r.status_code == 401
