"""Historical and incomplete runs expose unavailable/metadata states without invented values."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from qrypton.application.schemas import PolicyOutcome, RunFailure, RunResult
from qrypton.contracts.enums import RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run


def test_historical_run_missing_recommendation_plans(tmp_path: Path) -> None:
    store = SqliteRunStore(tmp_path / "legacy.sqlite3")
    tenant_id = f"tenant_{'e' * 52}"
    run_id = f"run_{'e' * 52}"
    store.finalize_run(
        RunResult(
            run_id=run_id,
            tenant_id=tenant_id,
            status=RunStatus.COMPLETED,
            started_at=datetime(2025, 6, 1, tzinfo=UTC),
            completed_at=datetime(2025, 6, 1, 0, 10, tzinfo=UTC),
            policy_outcome=PolicyOutcome(passed=True, violations=()),
        )
    )
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert view.posture.total_findings == 0
    assert view.roadmap == ()
    assert view.has_cbom is False
    assert view.mosca_points == ()


def test_failed_run_view(tmp_path: Path) -> None:
    store = SqliteRunStore(tmp_path / "failed.sqlite3")
    tenant_id = f"tenant_{'f' * 52}"
    run_id = f"run_{'f' * 52}"
    store.finalize_run(
        RunResult(
            run_id=run_id,
            tenant_id=tenant_id,
            status=RunStatus.FAILED,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            completed_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            failures=(
                RunFailure(
                    stage="scanner",
                    error_code="scanner_timeout",
                    scanner_name="qrypton-source",
                    message="stage failed; inspect sanitized diagnostics",
                ),
            ),
            policy_outcome=PolicyOutcome(passed=False, violations=("scanner_failure",)),
        )
    )
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert view.posture.run_status == RunStatus.FAILED
    assert view.posture.policy_passed is False
    assert "scanner_failure" in view.posture.policy_violations


def test_metadata_only_run_does_not_invent_timestamps(tmp_path: Path) -> None:
    store = SqliteRunStore(tmp_path / "pending.sqlite3")
    tenant_id = f"tenant_{'g' * 52}"
    run_id = f"run_{'g' * 52}"
    store._connection.execute(
        "INSERT INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
        (tenant_id, run_id, "pending"),
    )
    store._connection.commit()
    summaries = SqliteDashboardDataProvider(store).list_runs(tenant_id=tenant_id)
    assert len(summaries) == 1
    assert summaries[0].record_state == "metadata_only"
    assert summaries[0].started_at is None
    assert summaries[0].total_findings is None
    provider = SqliteDashboardDataProvider(store)
    assert provider.get_run_view(tenant_id=tenant_id, run_id=run_id) is None


def test_legacy_findings_without_mosca_evaluations_are_unavailable(tmp_path: Path) -> None:
    store = SqliteRunStore(tmp_path / "no-mosca.sqlite3")
    tenant_id = f"tenant_{'i' * 52}"
    run_id = f"run_{'i' * 52}"
    store.finalize_run(create_sample_run(tenant_id, run_id, include_mosca=False))
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert view.mosca_points
    assert all(point.timeline_state == "unavailable" for point in view.mosca_points)
