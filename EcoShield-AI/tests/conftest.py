"""Shared pytest fixtures.

Uses a throwaway SQLite database, resets the in-memory rate limiter between
tests, and provides helpers for CSRF + authentication so security controls stay
active during testing (we test *with* the guards on, not around them).
"""
from __future__ import annotations

import os

# Configure the test database BEFORE importing the app/engine.
os.environ.setdefault("ECOSHIELD_DATABASE_URL", "sqlite:///./test_ecoshield.db")
os.environ.setdefault("ECOSHIELD_ENVIRONMENT", "development")
os.environ.setdefault("ECOSHIELD_DEBUG", "true")

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from backend.app import app
    from backend.database import Base, engine
    from backend.security.rate_limit import limiter

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    limiter.reset()

    with TestClient(app) as c:
        yield c

    limiter.reset()
    Base.metadata.drop_all(engine)


def csrf(client: TestClient) -> dict:
    token = client.get("/api/csrf-token").json()["csrf_token"]
    return {"X-CSRF-Token": token}


def login(client: TestClient, email: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"email": email, "password": password}, headers=csrf(client))
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth_headers(client: TestClient, token: str) -> dict:
    h = csrf(client)
    h["Authorization"] = f"Bearer {token}"
    return h


@pytest.fixture()
def user_headers(client):
    token = login(client, "user@ecoshield.app", "EcoShield#User1")
    return auth_headers(client, token)


@pytest.fixture()
def admin_headers(client):
    token = login(client, "admin@ecoshield.app", "EcoShield#Admin1")
    return auth_headers(client, token)


@pytest.fixture()
def secadmin_headers(client):
    token = login(client, "security@ecoshield.app", "EcoShield#Sec1")
    return auth_headers(client, token)
