"""Unit and integration tests for FastAPI backend."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import ScanRequest, _build_request, app
from qrypton.contracts.enums import Criticality, ObservationState
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


def test_api_inventory_never_returns_mock_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    response = client.get("/api/v1/inventory")
    assert response.status_code == 503


def test_api_posture_never_returns_mock_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    response = client.get("/api/v1/posture")
    assert response.status_code == 503


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


def test_dashboard_snapshot_and_scan_history_pagination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "dashboard.sqlite3"
    tenant_id = f"tenant_{'a' * 52}"
    store = SqliteRunStore(db_path)
    run_ids = [f"run_{letter * 52}" for letter in "bcdefg"]
    for run_id in run_ids:
        store.finalize_run(create_sample_run(tenant_id, run_id))
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(db_path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant_id)

    history = client.get("/api/v1/scans?limit=5&offset=5")
    assert history.status_code == 200
    assert history.headers["x-total-count"] == "6"
    assert len(history.json()) == 1
    assert history.json()[0]["scan_id"] == run_ids[0]

    snapshot = client.get(f"/api/v1/dashboard?run_id={run_ids[-1]}")
    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["posture"]["total_findings"] == len(body["inventory"])
    assert {item["finding_id"] for item in body["mosca"]} == {
        item["finding_id"] for item in body["inventory"]
    }


def test_unregistered_queued_scan_is_not_failed_by_polling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "orphaned.sqlite3"
    tenant_id = f"tenant_{'a' * 52}"
    run_id = f"run_{'b' * 52}"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE qrypton_runs (tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, "
            "status TEXT NOT NULL, result_json TEXT, cbom BLOB, "
            "PRIMARY KEY (tenant_id, run_id))"
        )
        connection.execute(
            "INSERT INTO qrypton_runs(tenant_id, run_id, status) VALUES (?, ?, 'queued')",
            (tenant_id, run_id),
        )
    monkeypatch.setenv("QRYPTON_DB", str(db_path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant_id)

    response = client.get(f"/api/v1/scans/{run_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "QUEUED"
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT status FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone() == ("queued",)


def _scan_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "target_type": "source_repo",
        "repository": "https://github.com/org/payments-core",
        "environment": "production",
        "business_criticality": "critical",
        "data_lifetime": 7,
        "migration_time": 4,
        "crqc_horizon": 8,
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize("criticality", ["critical", "high"])
def test_explicit_business_criticality_is_preserved(tmp_path: Path, criticality: str) -> None:
    repository = tmp_path / "explicit-context"
    repository.mkdir()
    request = ScanRequest(
        **_scan_payload(repository=str(repository), business_criticality=criticality)
    )
    run_request, _ = _build_request(request)
    assert run_request.business_context is not None
    observed = run_request.business_context.criticality
    assert observed.state is ObservationState.OBSERVED
    assert observed.value is Criticality(criticality)


def test_missing_business_criticality_is_unknown_and_explained(tmp_path: Path) -> None:
    repository = tmp_path / "missing-context"
    repository.mkdir()
    request = ScanRequest(
        **_scan_payload(
            repository=str(repository), business_criticality=None, data_sensitivity=None
        )
    )
    run_request, _ = _build_request(request)
    assert run_request.business_context is not None
    observed = run_request.business_context.criticality
    assert observed.state is ObservationState.UNKNOWN
    assert observed.value is None
    assert "needs" in (observed.rationale or "").casefold()


def test_create_and_get_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    source_dir = tmp_path / "payments-core"
    source_dir.mkdir()
    (source_dir / "crypto.py").write_bytes(b"import hashlib\nhashlib.sha256(b'x')\n")
    response = client.post(
        "/api/v1/scans",
        json=_scan_payload(repository=str(source_dir)),
    )
    assert response.status_code == 200
    created = response.json()
    assert created["scan_id"]
    assert created["status"] in {"COMPLETED", "PARTIAL", "QUEUED", "RUNNING"}

    status = client.get(f"/api/v1/scans/{created['scan_id']}")
    assert status.status_code == 200
    body = status.json()
    assert body["scan_id"]
    assert body["status"]


def test_upload_and_scan_binary_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "upload.db"))
    monkeypatch.setenv("QRYPTON_UPLOADS", str(tmp_path / "uploads"))
    uploaded = client.post(
        "/api/v1/uploads",
        files={"file": ("service.bin", b"\x7fELF fake binary payload")},
    )
    assert uploaded.status_code == 200
    artifact = uploaded.json()
    assert artifact["artifact_id"]
    assert artifact["locator"] == f"upload://{artifact['artifact_id']}"

    for locator in ("", artifact["locator"]):
        response = client.post(
            "/api/v1/scans",
            json=_scan_payload(
                target_type="binary",
                repository=locator,
                artifact_id=artifact["artifact_id"] if not locator else None,
            ),
        )
        assert response.status_code == 200
        assert response.json()["scan_id"]


def test_scan_kms_key_arn_without_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "kms.db"))
    for identifier in (
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "https://myvault.vault.azure.net/keys/mykey/abc123",
        "projects/p/locations/global/keyRings/r/cryptoKeys/k",
    ):
        response = client.post(
            "/api/v1/scans",
            json=_scan_payload(target_type="cloud_kms", repository=identifier),
        )
        assert response.status_code == 200
        assert response.json()["scan_id"]


def test_scan_container_reference_without_pull(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "container.db"))
    response = client.post(
        "/api/v1/scans",
        json=_scan_payload(target_type="container_image", repository="nginx:latest"),
    )
    assert response.status_code == 200
    assert response.json()["scan_id"]


def test_scan_rejects_unknown_artifact_and_registry_ref(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "reject.db"))
    monkeypatch.setenv("QRYPTON_UPLOADS", str(tmp_path / "uploads"))
    unknown = client.post(
        "/api/v1/scans",
        json=_scan_payload(target_type="binary", repository="", artifact_id="0" * 32),
    )
    assert unknown.status_code == 422

    registry = client.post(
        "/api/v1/scans",
        json=_scan_payload(
            target_type="container_image",
            repository="registry.enterprise.io/app:v1.0.4",
        ),
    )
    assert registry.status_code == 422
    assert "docker save" in registry.json()["detail"]

    host = client.post(
        "/api/v1/scans",
        json=_scan_payload(
            target_type="source_repo",
            repository="https://example.com/foo/bar",
        ),
    )
    assert host.status_code == 422

    gitlab_shape = client.post(
        "/api/v1/scans",
        json=_scan_payload(
            target_type="source_repo",
            repository="https://gitlab.com/onlyone",
        ),
    )
    assert gitlab_shape.status_code == 422

    empty_upload = client.post("/api/v1/uploads", files={"file": ("empty.bin", b"")})
    assert empty_upload.status_code == 422


def test_cors_headers() -> None:
    response = client.options(
        "/api/v1/inventory",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
