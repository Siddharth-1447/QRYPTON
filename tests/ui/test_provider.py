"""Unit tests for SqliteDashboardDataProvider."""

from __future__ import annotations

from qrypton.contracts.enums import RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider


def test_sqlite_provider_list_runs(populated_sqlite_store: tuple[SqliteRunStore, str, str]) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    provider = SqliteDashboardDataProvider(store)
    runs = provider.list_runs()
    assert len(runs) == 1
    assert runs[0].tenant_id == tenant_id
    assert runs[0].run_id == run_id
    assert runs[0].status == RunStatus.COMPLETED
    assert runs[0].record_state == "complete"
    assert runs[0].total_findings == 2
    assert len(provider.list_runs(tenant_id=tenant_id)) == 1
    assert provider.list_runs(tenant_id="tenant_nonexistent") == ()


def test_sqlite_provider_get_run_view_exact_persisted_values(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    persisted = store.get_run(tenant_id=tenant_id, run_id=run_id)
    assert persisted is not None
    provider = SqliteDashboardDataProvider(store)
    view = provider.get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert view.posture.total_findings == len(persisted.findings)
    assert view.posture.critical_findings_count == 1
    assert view.posture.high_findings_count == 1
    assert view.posture.unassessed_findings_count == 0
    assert view.posture.unique_asset_ids == 1
    assert view.posture.policy_passed is True
    assert {row.algorithm_name for row in view.inventory} == {"RSA", "SHA-1"}
    assert len(view.roadmap) == 2
    assert view.roadmap[0].priority == 1
    assert "ML-KEM-768" in view.roadmap[0].target_algorithms
    assert view.roadmap[0].hybrid_mode == "required"
    assert "Requires TLS 1.3 upgrade" in view.roadmap[0].blocking_conditions
    for row in view.inventory:
        assessment = next(
            item for item in persisted.assessments if item.finding_id == row.finding_id
        )
        assert row.risk_level == assessment.level
        assert row.risk_score == assessment.score.value


def test_sqlite_provider_get_finding_detail(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    provider = SqliteDashboardDataProvider(store)
    view = provider.get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    target_id = view.inventory[0].finding_id
    detail = provider.get_finding_detail(tenant_id=tenant_id, run_id=run_id, finding_id=target_id)
    assert detail is not None
    assert detail.finding.id == target_id
    assert detail.assessment is not None
    assert detail.assessment.finding_id == target_id
    assert len(detail.recommendations) > 0
    assert not hasattr(detail, "recommendation_plan")
    assert len(detail.evidence_provenance) > 0
    for evidence in detail.evidence_provenance:
        assert evidence.excerpt is None
        assert evidence.location.relative_path is None


def test_sqlite_provider_get_persisted_cbom(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    provider = SqliteDashboardDataProvider(store)
    cbom_bytes = provider.get_persisted_cbom(tenant_id=tenant_id, run_id=run_id)
    assert cbom_bytes is not None
    assert b"CycloneDX" in cbom_bytes
    assert b"1.6" in cbom_bytes
