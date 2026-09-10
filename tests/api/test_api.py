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


def test_api_inventory_never_returns_mock_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.db"))
    response = client.get("/api/v1/inventory")
    assert response.status_code == 503


def test_api_posture_never_returns_mock_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
        json=_scan_payload(
            target_type="binary", repository="", artifact_id="0" * 32
        ),
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
