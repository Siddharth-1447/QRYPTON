"""Provider login validates PKCE/state and never trusts browser role claims."""

import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from qrypton.api import oauth
from qrypton.api.access import _sessions
from qrypton.api.app import app


@pytest.fixture(autouse=True)
def clear_auth_state(monkeypatch):
    oauth._pending.clear()
    oauth._handoffs.clear()
    _sessions.clear()
    monkeypatch.delenv("QRYPTON_OAUTH_ROLES", raising=False)
    for provider in oauth.ENDPOINTS:
        for suffix in ("CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI"):
            monkeypatch.delenv(f"QRYPTON_OAUTH_{provider.upper()}_{suffix}", raising=False)


def configure(monkeypatch, provider):
    prefix = f"QRYPTON_OAUTH_{provider.upper()}"
    monkeypatch.setenv(prefix + "_CLIENT_ID", "test-client")
    monkeypatch.setenv(prefix + "_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv(
        prefix + "_REDIRECT_URI", f"http://localhost:8000/api/v1/auth/{provider}/callback"
    )


@pytest.mark.parametrize("provider", ["google", "github", "gitlab"])
def test_provider_flow_bound_to_browser_and_single_use(monkeypatch, provider):
    configure(monkeypatch, provider)
    verifier = "v" * 64
    client = TestClient(app)
    response = client.post(
        f"/api/v1/auth/{provider}/start",
        json={
            "origin": "http://localhost:3000",
            "challenge": oauth.challenge(verifier),
        },
    )
    assert response.status_code == 200
    query = parse_qs(urlsplit(response.json()["url"]).query)
    assert query["code_challenge_method"] == ["S256"]
    state = query["state"][0]
    assert query["code_challenge"][0] == oauth.challenge(oauth._pending[state].verifier)
    calls = []

    def provider_api(url, data=None, token=""):
        calls.append((url, data, token))
        if data:
            assert data["code_verifier"]
            assert data["client_secret"] == "test-secret"
            return {"access_token": "test-provider-token"}
        assert token == "test-provider-token"
        return {"id": 42, "sub": "42", "email": "analyst@example.test", "email_verified": True}

    monkeypatch.setattr(oauth, "_request", provider_api)
    callback = client.get(
        f"/api/v1/auth/{provider}/callback?state={state}&code=provider-code", follow_redirects=False
    )
    assert callback.status_code == 303
    handoff = parse_qs(urlsplit(callback.headers["location"]).fragment)["auth_code"][0]
    assert (
        client.get(f"/api/v1/auth/{provider}/callback?state={state}&code=replay").status_code == 400
    )
    body = {"code": handoff, "verifier": "x" * 64, "origin": "http://localhost:3000"}
    assert client.post("/api/v1/auth/exchange", json=body).status_code == 401
    body["verifier"] = verifier
    session = client.post("/api/v1/auth/exchange", json=body)
    assert session.status_code == 200
    assert session.json()["role"] == "Viewer"
    assert session.json()["subject"] == f"{provider}:42"
    assert session.json()["email"] == "analyst@example.test"
    token = session.json()["access_token"]
    assert client.get("/api/v1/session", headers={"Authorization": f"Bearer {token}"}).json() == {
        "subject": f"{provider}:42",
        "role": "Viewer",
    }
    assert client.post("/api/v1/auth/exchange", json=body).status_code == 401
    assert len(calls) == 2
    for digest, (_, actor) in list(_sessions.items()):
        _sessions[digest] = (time.time() - 1, actor)
    assert (
        client.get("/api/v1/session", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


def test_missing_config_invalid_state_and_untrusted_redirect(monkeypatch):
    client = TestClient(app)
    assert client.get("/api/v1/auth/providers").json()["providers"] == {
        "google": False,
        "github": False,
        "gitlab": False,
    }
    body = {"origin": "https://attacker.invalid", "challenge": oauth.challenge("v" * 64)}
    assert client.post("/api/v1/auth/google/start", json=body).status_code == 503
    configure(monkeypatch, "google")
    assert client.post("/api/v1/auth/google/start", json=body).status_code == 400
    assert client.get("/api/v1/auth/google/callback?state=unknown&code=code").status_code == 400


def test_expired_or_denied_provider_authorization(monkeypatch):
    configure(monkeypatch, "github")
    client = TestClient(app)
    body = {"origin": "http://localhost:3000", "challenge": oauth.challenge("v" * 64)}
    response = client.post("/api/v1/auth/github/start", json=body)
    state = parse_qs(urlsplit(response.json()["url"]).query)["state"][0]
    assert (
        client.get(f"/api/v1/auth/google/callback?state={state}&code=wrong-provider").status_code
        == 400
    )
    denied = client.get(
        f"/api/v1/auth/github/callback?state={state}&error=access_denied", follow_redirects=False
    )
    assert denied.status_code == 303
    assert "auth_error=" in denied.headers["location"]
    assert oauth._handoffs == {}
    response = client.post("/api/v1/auth/github/start", json=body)
    state = parse_qs(urlsplit(response.json()["url"]).query)["state"][0]
    pending = oauth._pending[state]
    oauth._pending[state] = oauth.Pending(
        0, pending.provider, pending.origin, pending.browser_challenge, pending.verifier
    )
    assert client.get(f"/api/v1/auth/github/callback?state={state}&code=expired").status_code == 400
