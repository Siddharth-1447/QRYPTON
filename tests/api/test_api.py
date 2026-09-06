"""Unit and integration tests for FastAPI backend."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.storage.sqlite import SqliteRunStore
from tests.ui.conftest import create_sample_run

client = TestClient(app)


@pytest.fixture
def populated_sqlite_store(tmp_path: Path) -> tuple[SqliteRunStore, str, str]:
    db_path = tmp_path / "test_api_qrypton.sqlite3"
    store = SqliteRunStore(db_path)
    tenant_id = f"tenant_{'a' * 52}"
    run_id = f"run_{'a' * 52}"
    store.finalize_run(create_sample_run(tenant_id, run_id))
    return store, tenant_id, run_id


def test_root_redirect() -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/docs"


def test_api_health() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "QRYPTON Cryptographic Inventory API"


def test_api_inventory_with_mock_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    response = client.get("/api/v1/inventory")
    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) >= 5
    assert any("RSA" in str(item.get("algorithm_name")) for item in items)


def test_api_posture_with_mock_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    response = client.get("/api/v1/posture")
    assert response.status_code == 200
    posture = response.json()
    assert posture["total_findings"] >= 5
    assert posture["critical_findings_count"] >= 1
    assert posture["run_status"] == "completed"


def test_api_with_populated_sqlite_store(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    monkeypatch.setenv("QRYPTON_DB", str(store._path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant_id)

    # Test inventory
    resp_inv = client.get(f"/api/v1/inventory?tenant_id={tenant_id}&run_id={run_id}")
    assert resp_inv.status_code == 200
    items = resp_inv.json()
    assert len(items) == 2

    # Test posture
    resp_post = client.get(f"/api/v1/posture?tenant_id={tenant_id}&run_id={run_id}")
    assert resp_post.status_code == 200
    posture = resp_post.json()
    assert posture["total_findings"] == 2
    assert posture["critical_findings_count"] == 1


def test_cors_headers() -> None:
    response = client.options(
        "/api/v1/inventory",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
