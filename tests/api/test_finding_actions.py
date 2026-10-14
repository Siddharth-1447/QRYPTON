"""Ticket creation, CI comment data and export previews use persisted tenant data."""

from __future__ import annotations

import hashlib
import json
import secrets

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.storage.sqlite import SqliteRunStore
from tests.ui.conftest import create_sample_run

TENANT = "tenant_" + "a" * 52
RUN = "run_" + "b" * 52
FINDING = "finding_" + "b" * 52
TICKET = f"/api/v1/scans/{RUN}/findings/{FINDING}/ticket"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    path = tmp_path / "actions.db"
    store = SqliteRunStore(path)
    store.finalize_run(create_sample_run(TENANT, RUN))
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    tokens = {role: secrets.token_urlsafe(32) for role in ("Viewer", "Developer", "CI Publisher")}
    monkeypatch.setenv(
        "QRYPTON_ACCESS_TOKENS",
        json.dumps(
            {
                hashlib.sha256(token.encode()).hexdigest(): {"subject": role, "role": role}
                for role, token in tokens.items()
            }
        ),
    )
    return TestClient(app), {
        role: {"Authorization": f"Bearer {token}"} for role, token in tokens.items()
    }


def test_ticket_draft_and_export_preview_are_truthful(workspace):
    client, headers = workspace
    draft = client.get(TICKET).json()
    assert draft["mode"] == "copy"
    assert "RSA" in draft["title"]
    assert "Replace RSA-1024 with ML-KEM-768" in draft["body"]
    assert "Mosca: X+Y=7" in draft["body"]
    assert "**Evidence location:**" in draft["body"]
    assert "**Evidence location:** Not recorded" in draft["body"]
    assert client.post(TICKET, headers=headers["Viewer"]).status_code == 403
    assert client.post(TICKET, headers=headers["Developer"]).status_code == 409
    preview = client.get(f"/api/v1/scans/{RUN}/export-preview").json()
    assert preview["finding_count"] == 2
    assert preview["risk_summary"]["critical"] == 1
    assert preview["risk_summary"]["high"] == 1
    assert preview["cbom_available"] is True
    assert client.get(f"/api/v1/scans/{'run_' + 'c' * 52}/export-preview").status_code == 404


def test_github_ticket_creation_is_authorized_and_idempotent(workspace, monkeypatch):
    client, headers = workspace
    monkeypatch.setenv("QRYPTON_GITHUB_ISSUES_REPO", "example/crypto-app")
    monkeypatch.setenv("QRYPTON_GITHUB_ISSUES_TOKEN", "server-secret-only")
    requests = []

    class Upstream:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, maximum):
            assert maximum == 65536
            return b'{"html_url":"https://github.com/example/crypto-app/issues/17"}'

    def open_issue(request, timeout):
        assert timeout == 10
        assert request.full_url == "https://api.github.com/repos/example/crypto-app/issues"
        assert request.get_header("Authorization") == "Bearer server-secret-only"
        payload = json.loads(request.data)
        assert "ML-KEM-768" in payload["body"]
        assert "server-secret-only" not in payload["body"]
        requests.append(request)
        return Upstream()

    monkeypatch.setattr("qrypton.api.actions._open_github", open_issue)
    assert client.post(TICKET, headers=headers["Viewer"]).status_code == 403
    first = client.post(TICKET, headers=headers["Developer"])
    assert first.status_code == 200, first.text
    assert first.json() == {
        "url": "https://github.com/example/crypto-app/issues/17",
        "created": True,
    }
    assert client.post(TICKET, headers=headers["Developer"]).json()["created"] is False
    assert len(requests) == 1
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "c" * 52)
    assert client.post(TICKET, headers=headers["Developer"]).status_code == 404


def test_ci_introduced_findings_are_validated_and_decorated(workspace):
    client, headers = workspace
    endpoint = "/api/v1/integrations/ci-results"
    body = {
        "provider": "GitHub Actions",
        "external_id": "44",
        "repository": "example/crypto-app",
        "title": "Crypto policy",
        "ref": "refs/pull/17/head",
        "result": "failure",
        "url": "https://github.com/example/crypto-app/actions/runs/44",
        "completed_at": "2026-10-10T10:00:00Z",
        "run_id": RUN,
        "introduced_finding_ids": [FINDING],
        "gate_effect": "blocks",
    }
    assert client.post(endpoint, headers=headers["Viewer"], json=body).status_code == 403
    assert (
        client.post(
            endpoint,
            headers=headers["CI Publisher"],
            json={**body, "introduced_finding_ids": ["finding_" + "z" * 52]},
        ).status_code
        == 422
    )
    assert client.post(endpoint, headers=headers["CI Publisher"], json=body).status_code == 201
    entry = client.get(endpoint).json()[0]
    assert entry["gate_effect"] == "blocks"
    assert entry["introduced"][0]["severity"] == "critical"
    assert FINDING in entry["introduced"][0]["href"]
