"""Mosca dashboard mapping uses stored structured values or an explicit unavailable state."""

from __future__ import annotations

from pathlib import Path

from qrypton.contracts.enums import MoscaUrgency
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run


def test_mosca_points_copy_persisted_structured_evaluations(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    persisted = store.get_run(tenant_id=tenant_id, run_id=run_id)
    assert persisted is not None
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert len(view.mosca_points) == len(view.inventory)
    stored = {item.finding_id: item for item in persisted.mosca_evaluations}
    for point in view.mosca_points:
        record = stored[point.finding_id]
        assert point.timeline_state == "persisted"
        assert point.urgency is MoscaUrgency(record.urgency)
        assert point.exposure_score == record.exposure_score
        assert point.x_data_lifetime_years == record.x_data_lifetime_years
        assert point.y_migration_years == record.y_migration_years
        assert point.z_crqc_horizon_years == record.z_crqc_horizon_years
        assert point.required_security_years == record.required_security_years
        assert point.time_margin_years == record.time_margin_years


def test_mosca_points_unavailable_when_structured_evaluations_absent(tmp_path: Path) -> None:
    store = SqliteRunStore(tmp_path / "legacy-mosca.sqlite3")
    tenant_id = f"tenant_{'d' * 52}"
    run_id = f"run_{'d' * 52}"
    store.finalize_run(create_sample_run(tenant_id, run_id, include_mosca=False))
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    for point in view.mosca_points:
        assert point.timeline_state == "unavailable"
        assert point.x_data_lifetime_years is None
        assert point.y_migration_years is None
        assert point.z_crqc_horizon_years is None
        assert point.required_security_years is None
        assert point.time_margin_years is None
        assert point.urgency is MoscaUrgency.UNKNOWN
        assert point.exposure_score is None
