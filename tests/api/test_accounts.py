"""Registration, password verification, isolation and privilege boundaries."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from qrypton.api import accounts
from qrypton.api.app import app


@pytest.fixture
def auth(tmp_path, monkeypatch):
    path = tmp_path / "accounts.db"
    monkeypatch.setenv("QRYPTON_AUTH_DB", str(path))
    monkeypatch.setenv("QRYPTON_ALLOW_SIGNUP", "true")
    accounts._attempts.clear()
    return TestClient(app), path


def test_registration_signin_and_hashed_storage(auth):
    client, path = auth
    body = {"email": "Person@Example.com", "password": "long unique test passphrase"}
    created = client.post("/api/v1/auth/signup", json=body)
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    assert created.json()["email"] == "person@example.com"
    assert created.json()["role"] == "Viewer"
    with sqlite3.connect(path) as db:
        salt, stored = db.execute("SELECT salt,password_hash FROM accounts").fetchone()
    assert len(salt) == len(stored) == 32
    assert body["password"].encode() not in path.read_bytes()
    login = client.post("/api/v1/auth/signin", json=body)
    assert login.status_code == 200
    assert login.json()["subject"] == created.json()["subject"]
    assert login.json()["access_token"] != created.json()["access_token"]
    headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    assert client.get("/api/v1/session", headers=headers).json()["role"] == "Viewer"
    assert client.post("/api/v1/auth/signup", json=body).status_code == 409


def test_wrong_password_and_unknown_account_share_error(auth):
    client, _ = auth
    body = {"email": "person@example.com", "password": "a valid test passphrase"}
    assert client.post("/api/v1/auth/signup", json=body).status_code == 201
    wrong = client.post("/api/v1/auth/signin", json={**body, "password": "wrong"})
    missing = client.post("/api/v1/auth/signin", json={**body, "email": "missing@example.com"})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()


def test_validation_disabled_signup_and_no_role_injection(auth, monkeypatch):
    client, _ = auth
    body = {"email": "person@example.com", "password": "a valid test passphrase"}
    for patch in ({"password": "short"}, {"email": "invalid"}, {"role": "Security Engineer"}):
        assert client.post("/api/v1/auth/signup", json={**body, **patch}).status_code == 422
    monkeypatch.setenv("QRYPTON_ALLOW_SIGNUP", "false")
    assert client.post("/api/v1/auth/signup", json=body).status_code == 403


def test_account_is_tenant_scoped(auth, monkeypatch):
    client, _ = auth
    body = {"email": "person@example.com", "password": "a valid test passphrase"}
    assert client.post("/api/v1/auth/signup", json=body).status_code == 201
    monkeypatch.setenv("QRYPTON_TENANT_ID", "another-tenant")
    assert client.post("/api/v1/auth/signin", json=body).status_code == 401


def test_rate_limit_does_not_trust_forwarded_ip(auth, monkeypatch):
    client, _ = auth
    monkeypatch.setattr(accounts, "_hash", lambda *_: b"x" * 32)
    body = {"email": "missing@example.com", "password": "wrong"}
    for index in range(10):
        assert (
            client.post(
                "/api/v1/auth/signin", json=body, headers={"X-Forwarded-For": f"192.0.2.{index}"}
            ).status_code
            == 401
        )
    response = client.post("/api/v1/auth/signin", json=body)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"
