"""Queue registration and durable heartbeat regressions."""

from __future__ import annotations

import importlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from qrypton.application.schemas import RunResult
from qrypton.storage.sqlite import SqliteRunStore

api = importlib.import_module("qrypton.api.app")
TENANT = "tenant_" + "a" * 52
RUN_ID = "run_" + "c" * 52


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database = tmp_path / "queue.sqlite3"
    store = SqliteRunStore(database)
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    monkeypatch.setenv("QRYPTON_SCAN_ORPHAN_GRACE_SECONDS", "60")
    root = tmp_path / "source"
    root.mkdir()
    (root / "crypto.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    yield (
        database,
        {
            "target_type": "source_repo",
            "repository": str(root),
            "data_lifetime": 5,
            "migration_time": 2,
            "crqc_horizon": 10,
        },
    )
    api._clear_scan_state(RUN_ID)


def seed(database: Path, status: str, heartbeat: float | None = None) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
            (TENANT, RUN_ID, status),
        )
        if heartbeat is not None:
            connection.execute(
                "INSERT INTO qrypton_run_heartbeats VALUES (?,?,?)", (TENANT, RUN_ID, heartbeat)
            )


def test_real_executor_queue_survives_polling_before_worker_start(context, monkeypatch):
    database, payload = context
    release, started = Event(), Event()

    def block_slot():
        started.set()
        assert release.wait(10)

    with ThreadPoolExecutor(max_workers=1) as executor, TestClient(api.app) as client:
        executor.submit(block_slot)
        assert started.wait(2)
        monkeypatch.setattr(api, "_SCAN_EXECUTOR", executor)
        scan_id = None
        try:
            response = client.post("/api/v1/scans", json=payload)
            assert response.status_code == 200
            scan_id = response.json()["scan_id"]
            assert api._scan_stage(scan_id) == "queued"
            for _ in range(3):
                status = client.get(f"/api/v1/scans/{scan_id}").json()
                assert status["status"] == "QUEUED"
                assert status["current_stage"] == 0
            with sqlite3.connect(database) as connection:
                assert connection.execute(
                    "SELECT status FROM qrypton_runs WHERE run_id=?", (scan_id,)
                ).fetchone() == ("queued",)
        finally:
            release.set()
    assert scan_id is not None and api._scan_stage(scan_id) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status FROM qrypton_runs WHERE run_id=?", (scan_id,)
        ).fetchone()[0] in {"completed", "partial"}


def test_registration_precedes_submission_and_rejection_is_terminal(context, monkeypatch):
    database, payload = context
    captured = []

    def reject(worker, request, scan_id):
        assert api._scan_stage(scan_id) == "queued"
        captured.append(scan_id)
        raise RuntimeError("executor shut down")

    monkeypatch.setattr(api, "_SCAN_EXECUTOR", Mock(submit=reject))
    with TestClient(api.app) as client:
        assert client.post("/api/v1/scans", json=payload).status_code == 503
    assert api._scan_stage(captured[0]) is None
    with sqlite3.connect(database) as connection:
        status, raw = connection.execute("SELECT status,result_json FROM qrypton_runs").fetchone()
    assert status == "failed"
    result = RunResult.model_validate_json(raw)
    assert result.completed_at is not None
    assert result.failures[0].error_code == "scan_submission_failed"


@pytest.mark.parametrize(
    ("status", "heartbeat", "registered", "expected"),
    [
        ("queued", 1, False, "QUEUED"),
        ("pending", 1, False, "QUEUED"),
        ("running", 995, False, "RUNNING"),  # Another process's live worker.
        ("running", 940, False, "RUNNING"),  # Full grace period, inclusive boundary.
        ("running", 939, False, "FAILED"),
        ("running", 1, True, "RUNNING"),
    ],
)
def test_orphan_requires_running_and_expired_heartbeat(
    context,
    monkeypatch,
    status,
    heartbeat,
    registered,
    expected,
):
    database, _ = context
    seed(database, status, heartbeat)
    monkeypatch.setattr(api.time, "time", lambda: 1000)
    if registered:
        api._set_scan_state(RUN_ID, "scanning cryptographic evidence")
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == expected


def test_legacy_running_row_gets_one_grace_period(context, monkeypatch):
    database, _ = context
    seed(database, "running")
    clock = [1000]
    monkeypatch.setattr(api.time, "time", lambda: clock[0])
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == "RUNNING"
    clock[0] = 1030
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == "RUNNING"
    clock[0] = 1061
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == "FAILED"


def test_heartbeat_refresh_protects_worker_without_local_registration(context, monkeypatch):
    database, _ = context
    seed(database, "running", 1)
    monkeypatch.setattr(api.time, "time", lambda: 1000)
    api._refresh_scan_heartbeat(database, TENANT, RUN_ID)
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == "RUNNING"


def test_orphan_compare_and_set_cannot_overwrite_completed_run(context):
    database, _ = context
    seed(database, "completed", 1)
    assert not api._expire_orphaned_running_scan(database, TENANT, RUN_ID)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM qrypton_runs").fetchone() == ("completed",)


@pytest.mark.parametrize("configured", ["invalid", "-1", "0", "nan", "inf"])
def test_invalid_orphan_grace_uses_default(monkeypatch, configured):
    monkeypatch.setenv("QRYPTON_SCAN_ORPHAN_GRACE_SECONDS", configured)
    assert api._orphan_grace_seconds() == 60


def test_orphan_grace_is_configurable(context, monkeypatch):
    database, _ = context
    seed(database, "running", 950)
    monkeypatch.setattr(api.time, "time", lambda: 1000)
    monkeypatch.setenv("QRYPTON_SCAN_ORPHAN_GRACE_SECONDS", "30")
    assert api.get_scan(RUN_ID, tenant_id=TENANT)["status"] == "FAILED"


def test_worker_heartbeats_while_busy_and_stops_after_exit(context, monkeypatch):
    database, payload = context
    seed(database, "queued")
    refreshed = Event()
    threads = []
    original = api._refresh_scan_heartbeat

    def refresh(*args):
        import threading

        threads.append(threading.current_thread())
        original(*args)
        refreshed.set()

    def slow_resolution(request):
        assert refreshed.wait(2)
        raise ValueError("controlled resolution failure")

    monkeypatch.setenv("QRYPTON_SCAN_ORPHAN_GRACE_SECONDS", "0.06")
    monkeypatch.setattr(api, "_refresh_scan_heartbeat", refresh)
    monkeypatch.setattr(api, "_build_request", slow_resolution)
    api._run_full_scan_in_background(api.ScanRequest(**payload), RUN_ID)
    assert threads and all(not thread.is_alive() for thread in threads)
    assert api._scan_stage(RUN_ID) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM qrypton_runs").fetchone() == ("failed",)
