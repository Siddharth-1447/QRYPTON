"""Regression coverage for early worker failures and terminal persistence."""

from __future__ import annotations

import asyncio
import importlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import ScanRequest, app
from qrypton.application.schemas import RunResult
from qrypton.contracts.enums import RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import SafeRunFailure

api = importlib.import_module("qrypton.api.app")
TENANT = "tenant_" + "a" * 52
RUN_ID = "run_" + "b" * 52
PRIVATE_ERROR = "private filesystem path and credential: " + "sensitive" * 100


@pytest.fixture
def worker_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, ScanRequest]:
    database = tmp_path / "worker.sqlite3"
    source = tmp_path / "source"
    source.mkdir()
    (source / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    store = SqliteRunStore(database)
    store.close()
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
            (TENANT, RUN_ID, "queued"),
        )
    return database, ScanRequest(
        target_type="source_repo",
        repository=str(source),
        data_lifetime=5,
        migration_time=2,
        crqc_horizon=10,
    )


def execute(request: ScanRequest) -> None:
    # Read the Future so an escaped thread exception fails the regression test.
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(api._run_full_scan_in_background, request, RUN_ID).result(timeout=10)


def persisted_failure(database: Path) -> RunResult:
    # Check persistence BEFORE polling: GET must not be needed to repair the row.
    with sqlite3.connect(database) as connection:
        status, payload = connection.execute(
            "SELECT status,result_json FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (TENANT, RUN_ID),
        ).fetchone()
    assert status == "failed"
    assert payload is not None
    assert "private filesystem" not in payload and "sensitive" not in payload
    result = RunResult.model_validate_json(payload)
    assert result.status is RunStatus.FAILED
    assert result.completed_at is not None
    assert result.completed_at >= result.started_at
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert 0 < len(failure.message) <= 256
    assert SafeRunFailure.model_validate(failure.model_dump()).stage == failure.stage
    assert api._scan_stage(RUN_ID) is None
    assert not result.policy_outcome.passed
    with TestClient(app) as client:
        response = client.get(f"/api/v1/scans/{RUN_ID}")
    assert response.status_code == 200
    assert response.json()["status"] == "FAILED"
    return result


@pytest.mark.parametrize("field", ["data_lifetime", "migration_time", "crqc_horizon"])
@pytest.mark.parametrize("value", [-1, 10_001, "NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("nested", [False, True])
def test_invalid_timelines_rejected_before_queueing(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    nested: bool,
) -> None:
    database, request = worker_context
    payload = request.model_dump()
    if nested:
        payload["business_context"] = {field: value}
    else:
        payload[field] = value
    executor = Mock()
    locator_validation = Mock()
    monkeypatch.setattr(api, "_SCAN_EXECUTOR", executor)
    monkeypatch.setattr(api, "_validate_scan_locator", locator_validation)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][-1] == field
    executor.submit.assert_not_called()
    locator_validation.assert_not_called()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM qrypton_runs").fetchone()[0] == 1


@pytest.mark.parametrize("value", [0, 10_000])
def test_timeline_bounds_are_inclusive(value: int) -> None:
    request = ScanRequest(
        target_type="source_repo",
        data_lifetime=value,
        migration_time=value,
        crqc_horizon=value,
    )
    assert request.data_lifetime == request.migration_time == request.crqc_horizon == value


@pytest.mark.parametrize(
    ("failing_call", "error", "stage", "code"),
    [
        ("_build_request", ValueError(PRIVATE_ERROR), "resolve", "target_resolution_failed"),
        ("_build_request", PermissionError(PRIVATE_ERROR), "resolve", "target_access_denied"),
        (
            "QryptonConfig",
            PermissionError(PRIVATE_ERROR),
            "configuration",
            "scan_configuration_failed",
        ),
        (
            "_run_scan_in_background",
            RuntimeError(PRIVATE_ERROR),
            "orchestration",
            "unexpected_worker_error",
        ),
        (
            "_persist_scan_status",
            sqlite3.OperationalError(PRIVATE_ERROR),
            "resolve",
            "target_resolution_failed",
        ),
    ],
)
def test_full_worker_persists_each_early_failure(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
    failing_call: str,
    error: Exception,
    stage: str,
    code: str,
) -> None:
    database, request = worker_context
    monkeypatch.setattr(api, failing_call, Mock(side_effect=error))
    execute(request)
    result = persisted_failure(database)
    assert result.failures[0].stage == stage
    assert result.failures[0].error_code == code


def test_runtime_validation_failure_is_contained_even_if_route_was_bypassed(
    worker_context: tuple[Path, ScanRequest],
) -> None:
    database, request = worker_context
    # Simulate an internal/legacy caller bypassing request model validation.
    execute(request.model_copy(update={"data_lifetime": -1}))
    result = persisted_failure(database)
    assert result.failures[0].stage == "configuration"
    assert result.asset is not None and result.target is not None


def test_inner_worker_error_still_persists_failure(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, request = worker_context
    monkeypatch.setattr(api, "build_orchestrator", Mock(side_effect=RuntimeError(PRIVATE_ERROR)))
    execute(request)
    assert persisted_failure(database).failures[0].error_code == "unexpected_worker_error"


@pytest.mark.parametrize("error", [RuntimeError(PRIVATE_ERROR), TimeoutError(PRIVATE_ERROR)])
def test_outer_guard_retries_failed_inner_error_persistence(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    database, request = worker_context
    monkeypatch.setattr(api, "build_orchestrator", Mock(side_effect=error))
    original = SqliteRunStore.finalize_run
    attempts = 0

    def fail_once(store: SqliteRunStore, result: RunResult) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("controlled transient failure")
        original(store, result)

    monkeypatch.setattr(SqliteRunStore, "finalize_run", fail_once)
    execute(request)
    assert attempts == 2
    assert persisted_failure(database).failures[0].stage == "orchestration"


def test_activity_cleared_even_when_failure_persistence_is_unavailable(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, request = worker_context
    monkeypatch.setattr(api, "_build_request", Mock(side_effect=ValueError(PRIVATE_ERROR)))
    monkeypatch.setattr(
        SqliteRunStore,
        "finalize_run",
        Mock(side_effect=sqlite3.OperationalError("database unavailable")),
    )
    execute(request)
    assert api._scan_stage(RUN_ID) is None
    assert "Unable to persist terminal failure" in caplog.text


def test_successful_worker_preserves_result_and_clears_activity(
    worker_context: tuple[Path, ScanRequest],
) -> None:
    database, request = worker_context
    execute(request)
    store = SqliteRunStore(database)
    try:
        result = store.get_run(tenant_id=TENANT, run_id=RUN_ID)
    finally:
        store.close()
    assert result is not None and result.status in {RunStatus.COMPLETED, RunStatus.PARTIAL}
    assert result.completed_at is not None
    assert api._scan_stage(RUN_ID) is None


@pytest.mark.parametrize(
    ("surface", "canonical", "expected"),
    [
        ("source_repo", "source_tree", 90),
        ("source_archive", "git_archive", 90),
        ("binary", "file", 1200),
        ("library", "file", 1200),
        ("container", "oci_image", 1200),
        ("cloud_kms", "file", 1200),
    ],
)
def test_timeout_budget_matches_api_and_canonical_surface(
    surface: str,
    canonical: str,
    expected: int,
) -> None:
    for size in (None, 0, 100 * 1024 * 1024):
        assert api._size_scaled_timeout_seconds(size, surface) == expected
        assert api._size_scaled_timeout_seconds(size, canonical) == expected
        assert api._limits(size, surface).max_wall_time_seconds == expected


@pytest.mark.parametrize("limiting_budget", ["request", "surface"])
def test_worker_watchdog_uses_tighter_budget_and_persists_timeout(
    worker_context: tuple[Path, ScanRequest],
    monkeypatch: pytest.MonkeyPatch,
    limiting_budget: str,
) -> None:
    database, request = worker_context
    cancelled = False
    original_build = api._build_request

    def build_request(*args, **kwargs):
        run_request, resolved_path = original_build(*args, **kwargs)
        updated = run_request.model_copy(
            update={
                "limits": run_request.limits.model_copy(
                    update={
                        "max_wall_time_seconds": 1 if limiting_budget == "request" else 60,
                    }
                ),
            }
        )
        return updated, resolved_path

    async def slow_run(*args, **kwargs):
        nonlocal cancelled
        try:
            await asyncio.sleep(3)
            raise AssertionError("watchdog did not interrupt the scan")
        finally:
            cancelled = True

    monkeypatch.setattr(api, "_build_request", build_request)
    if limiting_budget == "surface":
        monkeypatch.setattr(api, "_SOURCE_SCAN_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(api, "build_orchestrator", Mock(return_value=Mock(run=slow_run)))
    execute(request)
    assert cancelled
    assert persisted_failure(database).failures[0].error_code == "scan_timeout"
