"""Tests for MockDashboardDataProvider."""

from __future__ import annotations

from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.ui.contracts import DashboardFilters
from qrypton.ui.filtering import filter_and_sort_inventory
from qrypton.ui.mock_provider import MockDashboardDataProvider


def test_mock_dashboard_data_provider() -> None:
    provider = MockDashboardDataProvider()
    runs = provider.list_runs()
    assert len(runs) == 1
    run = runs[0]
    assert run.status == RunStatus.COMPLETED
    assert run.total_findings is not None and run.total_findings >= 5

    view = provider.get_run_view(tenant_id=run.tenant_id, run_id=run.run_id)
    assert view is not None
    assert view.posture.total_findings >= 5
    assert view.posture.critical_findings_count >= 1
    assert view.has_cbom is True
    assert len(view.inventory) >= 5
    assert len(view.heatmap_cells) == 30
    assert len(view.mosca_points) >= 5
    assert len(view.roadmap) >= 5

    finding_id = view.inventory[0].finding_id
    detail = provider.get_finding_detail(
        tenant_id=run.tenant_id, run_id=run.run_id, finding_id=finding_id
    )
    assert detail is not None
    assert detail.finding.id == finding_id
    assert detail.assessment is not None
    assert len(detail.recommendations) >= 1
    assert len(detail.evidence_provenance) >= 1

    cbom_bytes = provider.get_persisted_cbom(tenant_id=run.tenant_id, run_id=run.run_id)
    assert cbom_bytes is not None
    assert b"CycloneDX" in cbom_bytes

    # Test filtering on mock inventory
    filtered = filter_and_sort_inventory(
        view.inventory, DashboardFilters(risk_level=RiskLevel.CRITICAL)
    )
    assert len(filtered) >= 1
    assert all(item.risk_level == RiskLevel.CRITICAL for item in filtered)
