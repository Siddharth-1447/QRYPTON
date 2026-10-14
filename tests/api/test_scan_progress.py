"""Real execution telemetry and tenant/target context regression coverage."""

import importlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest

from qrypton.api import scan_progress
from qrypton.api.app import ScanRequest
from qrypton.application.progress import observer, report
from qrypton.storage.sqlite import SqliteRunStore

api = importlib.import_module("qrypton.api.app")
TENANT = "tenant_" + "a" * 52


def test_progress_is_durable_and_never_assumes_skipped_stages(tmp_path: Path) -> None:
    path = tmp_path / "runs.db"
    scan_progress.register(path, TENANT, "run", "target", {})
    assert scan_progress.snapshot(path, TENANT, "run", "QUEUED") == {
        "stages": ["pending"] * 8, "findings_discovered": None,
    }
    scan_progress.record(path, TENANT, "run", 0, "completed")
    scan_progress.record(path, TENANT, "run", 1, "running")
    failed = scan_progress.snapshot(path, TENANT, "run", "FAILED")
    assert failed["stages"] == ["completed", "failed"] + ["pending"] * 6
    scan_progress.record(path, TENANT, "run", 3, "warning")
    scan_progress.record(path, TENANT, "run", 3, "completed")
    assert scan_progress.snapshot(path, TENANT, "run", "PARTIAL")["stages"][3] == "warning"
    assert scan_progress.snapshot(path, "other", "run", "COMPLETED")["stages"] is None
    with pytest.raises(ValueError):
        scan_progress.record(path, TENANT, "run", 8, "running")


def test_observer_scope_is_reset() -> None:
    callback = Mock()
    token = observer.set(callback)
    try:
        report(4, "completed", 5)
    finally:
        observer.reset(token)
    report(7, "completed")
    callback.assert_called_once_with(4, "completed", 5)


def test_real_worker_reports_findings_and_previous_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runs.db"
    source = tmp_path / "source"
    source.mkdir()
    (source / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setenv("QRYPTON_DB", str(path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    executor = Mock()
    monkeypatch.setattr(api, "_SCAN_EXECUTOR", executor)
    request = ScanRequest(
        target_type="source_repo", repository=str(source), data_lifetime=None,
        migration_time=2, crqc_horizon=10, business_criticality="high",
        data_sensitivity="confidential", internet_exposure=False,
    )
    accepted = api.create_scan(request)
    run_id = accepted["scan_id"]
    assert api.get_scan(run_id)["stages"] == ["pending"] * 8
    api._run_full_scan_in_background(request, run_id)
    completed = api.get_scan(run_id)
    assert completed["status"] == "COMPLETED"
    assert completed["stages"] == ["completed"] * 8
    assert completed["findings_discovered"] == completed["total_findings"] > 0
    assert completed["progress_percent"] is None
    context = api.previous_scan_context("source_repo", str(source))["context"]
    assert context["business_criticality"] == "high"
    assert context["data_lifetime"] is None
    assert context["internet_exposure"] is False
    assert api.previous_scan_context("source_repo", str(source), "other")["context"] is None
    assert api.previous_scan_context("binary", str(source))["context"] is None
    # Legacy scans remain eligible after telemetry metadata is removed.
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM qrypton_scan_progress")
    assert api.previous_scan_context("source_repo", str(source))["context"]["data_lifetime"] is None


def test_previous_context_matches_latest_target_and_tenant(tmp_path: Path) -> None:
    path = tmp_path / "runs.db"
    SqliteRunStore(path).close()
    target = json.dumps(["source_repo", "https://example.test/repo", "main"])
    for tenant, run, criticality in [(TENANT, "a", "high"), (TENANT, "b", "critical"),
                                     ("other", "c", "low")]:
        with sqlite3.connect(path) as db:
            db.execute("INSERT INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
                       (tenant, run, "queued"))
        scan_progress.register(path, tenant, run, target, {"business_criticality": criticality})
    assert scan_progress.previous(path, TENANT, target) == {"business_criticality": "critical"}
    assert scan_progress.previous(path, TENANT, "other-target") is None
