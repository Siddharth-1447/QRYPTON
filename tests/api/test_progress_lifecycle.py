"""Server authorization, state-machine concurrency, bounded undo and snapshot integrity."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.storage.sqlite import SqliteRunStore
from tests.ui.conftest import create_sample_run

TENANT = "tenant_" + "a" * 52
RUN = "run_" + "b" * 52
FINDING = "finding_" + "b" * 52
ENDPOINT = f"/api/v1/scans/{RUN}/findings/{FINDING}/status"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    path = tmp_path / "progress.db"
    store = SqliteRunStore(path)
    store.finalize_run(create_sample_run(TENANT, RUN))
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    tokens = {
        role: secrets.token_urlsafe(32)
        for role in ("Viewer", "Security Engineer", "Developer", "Executive", "CI Publisher")
    }
    monkeypatch.setenv(
        "QRYPTON_ACCESS_TOKENS",
        json.dumps(
            {
                hashlib.sha256(token.encode()).hexdigest(): {"subject": role, "role": role}
                for role, token in tokens.items()
            }
        ),
    )
    return (
        TestClient(app),
        path,
        {role: {"Authorization": f"Bearer {token}"} for role, token in tokens.items()},
    )


def test_roles_are_enforced_on_all_mutation_paths(workspace):
    client, _, headers = workspace
    for role in ("Viewer", "Developer", "Executive", "CI Publisher"):
        assert client.get("/api/v1/session", headers=headers[role]).json()["role"] == role
        assert (
            client.patch(
                ENDPOINT,
                headers=headers[role],
                json={
                    "status": "Reviewed",
                    "version": 0,
                },
            ).status_code
            == 403
        )
        assert (
            client.patch(
                "/api/v1/inventory/actions",
                headers=headers[role],
                json={
                    "run_id": RUN,
                    "finding_ids": [FINDING],
                    "action": "status",
                    "status": "accepted",
                },
            ).status_code
            == 403
        )
    assert (
        client.patch(
            ENDPOINT,
            headers={"X-Role": "Security Engineer"},
            json={
                "status": "Reviewed",
                "version": 0,
            },
        ).status_code
        == 403
    )
    assert (
        client.get("/api/v1/session", headers={"Authorization": "Bearer fake"}).status_code == 401
    )
    assert (
        client.patch(
            "/api/v1/inventory/actions",
            headers=headers["Security Engineer"],
            json={
                "run_id": RUN,
                "finding_ids": [FINDING],
                "action": "status",
                "status": "accepted",
            },
        ).status_code
        == 410
    )


def test_lifecycle_undo_and_read_models_do_not_mutate_snapshot(workspace):
    client, path, headers = workspace
    engineer = headers["Security Engineer"]
    with sqlite3.connect(path) as db:
        snapshot = db.execute("SELECT result_json,cbom FROM qrypton_runs").fetchone()
    assert client.get(ENDPOINT).json() == {"status": "New", "reason": "", "version": 0}
    assert (
        client.patch(
            ENDPOINT,
            headers=engineer,
            json={
                "status": "Closed",
                "version": 0,
            },
        ).status_code
        == 422
    )
    changed = client.patch(
        ENDPOINT,
        headers=engineer,
        json={
            "status": "Reviewed",
            "version": 0,
        },
    ).json()
    undo = f"/api/v1/finding-status/undo/{changed['undo_token']}"
    assert client.post(undo, headers=headers["Viewer"]).status_code == 403
    reverted = client.post(undo, headers=engineer)
    assert reverted.status_code == 200
    assert reverted.json()["status"] == "New"
    assert reverted.json()["version"] == 2
    assert client.post(undo, headers=engineer).status_code == 409
    assert (
        client.patch(
            ENDPOINT,
            headers=engineer,
            json={
                "status": "Reviewed",
                "version": 0,
            },
        ).status_code
        == 409
    )
    for version, status in enumerate(
        [
            "Reviewed",
            "Accepted for Migration",
            "In Progress",
            "Mitigated",
            "Verified",
            "Closed",
        ],
        start=2,
    ):
        response = client.patch(
            ENDPOINT, headers=engineer, json={"status": status, "version": version}
        )
        assert response.status_code == 200, response.text
    inventory = client.get(f"/api/v1/inventory?run_id={RUN}").json()
    assert next(f for f in inventory if f["finding_id"] == FINDING)["migration_status"] == "Closed"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT result_json,cbom FROM qrypton_runs").fetchone() == snapshot
        assert db.execute("SELECT count(*) FROM lifecycle_events").fetchone()[0] == 7


def test_risk_acceptance_reason_expiration_and_conflict(workspace, monkeypatch):
    client, _, headers = workspace
    engineer = headers["Security Engineer"]
    assert (
        client.patch(
            ENDPOINT,
            headers=engineer,
            json={
                "status": "Risk Accepted",
                "version": 0,
                "reason": "   ",
            },
        ).status_code
        == 422
    )
    accepted = client.patch(
        ENDPOINT,
        headers=engineer,
        json={
            "status": "Risk Accepted",
            "version": 0,
            "reason": "Legacy partner contract ends in June",
        },
    ).json()
    assert client.get(ENDPOINT).json()["reason"] == "Legacy partner contract ends in June"
    monkeypatch.setattr(
        "qrypton.api.progress.time.time", lambda: accepted["undo_expires_at"] + 0.01
    )
    assert (
        client.post(
            f"/api/v1/finding-status/undo/{accepted['undo_token']}", headers=engineer
        ).status_code
        == 409
    )


def test_subsequent_update_blocks_undo_and_scope_is_checked(workspace, monkeypatch):
    client, _, headers = workspace
    engineer = headers["Security Engineer"]
    first = client.patch(
        ENDPOINT, headers=engineer, json={"status": "Reviewed", "version": 0}
    ).json()
    assert (
        client.patch(
            ENDPOINT,
            headers=engineer,
            json={
                "status": "Accepted for Migration",
                "version": 1,
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/finding-status/undo/{first['undo_token']}", headers=engineer
        ).status_code
        == 409
    )
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "c" * 52)
    assert client.get(ENDPOINT).status_code == 404
    assert (
        client.post(
            f"/api/v1/finding-status/undo/{first['undo_token']}", headers=engineer
        ).status_code
        == 404
    )


def test_finalized_run_cannot_be_overwritten(workspace):
    _, path, _ = workspace
    store = SqliteRunStore(path)
    original = store.get_run(tenant_id=TENANT, run_id=RUN)
    with pytest.raises(ValueError, match="immutable"):
        store.finalize_run(original.model_copy(update={"findings": ()}))
    store.finalize_run(original)
    assert store.get_run(tenant_id=TENANT, run_id=RUN).findings == original.findings
    store.close()


def test_ci_feed_is_publisher_gated_tenant_scoped_and_idempotent(workspace, monkeypatch):
    client, _, headers = workspace
    endpoint = "/api/v1/integrations/ci-results"
    report = {
        "provider": "GitHub Actions",
        "external_id": "run-42",
        "repository": "example/crypto-app",
        "title": "PQC migration checks",
        "ref": "refs/pull/17/head",
        "result": "success",
        "url": "https://github.com/example/crypto-app/actions/runs/42",
        "completed_at": "2026-10-10T10:00:00Z",
        "run_id": RUN,
    }
    for role in ("Viewer", "Developer", "Executive", "Security Engineer"):
        assert client.post(endpoint, headers=headers[role], json=report).status_code == 403
    publisher = headers["CI Publisher"]
    assert (
        client.post(
            endpoint, headers=publisher, json={**report, "url": "http://example.com"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint, headers=publisher, json={**report, "run_id": "run_" + "c" * 52}
        ).status_code
        == 404
    )
    created = client.post(endpoint, headers=publisher, json=report)
    assert created.status_code == 201, created.text
    assert client.post(endpoint, headers=publisher, json=report).status_code == 201
    assert (
        client.post(endpoint, headers=publisher, json={**report, "result": "failure"}).status_code
        == 409
    )
    feed = client.get(endpoint, headers=headers["Developer"])
    assert feed.status_code == 200
    assert len(feed.json()) == 1
    assert feed.json()[0]["title"] == "PQC migration checks"
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "c" * 52)
    assert client.get(endpoint).json() == []
    assert client.post(endpoint, headers=publisher, json=report).status_code == 404
