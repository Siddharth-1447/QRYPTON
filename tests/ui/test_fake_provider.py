"""UI tests that consume FakeDashboardDataProvider only."""

from __future__ import annotations

from datetime import UTC, datetime

from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.ui.contracts import (
    DashboardFilters,
    DashboardRunSummary,
    DashboardRunView,
    ExecutivePosture,
    InventoryRow,
)
from qrypton.ui.filtering import filter_and_sort_inventory
from tests.ui.conftest import FakeDashboardDataProvider


def _view(tenant_id: str, run_id: str, finding_id: str) -> DashboardRunView:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    row = InventoryRow(
        finding_id=finding_id,
        category="algorithm_use",
        algorithm_name="RSA",
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        evidence_count=1,
        first_observed_at=started,
        last_observed_at=started,
    )
    return DashboardRunView(
        summary=DashboardRunSummary(
            tenant_id=tenant_id,
            run_id=run_id,
            status=RunStatus.COMPLETED,
            started_at=started,
            total_findings=1,
        ),
        posture=ExecutivePosture(
            total_findings=1,
            unique_asset_ids=1,
            critical_findings_count=0,
            high_findings_count=1,
            medium_findings_count=0,
            low_findings_count=0,
            informational_findings_count=0,
            unassessed_findings_count=0,
            run_status=RunStatus.COMPLETED,
            scanner_failed_count=0,
            scanner_partial_count=0,
            policy_passed=True,
        ),
        inventory=(row,),
        heatmap_cells=(),
        mosca_points=(),
        roadmap=(),
        has_cbom=True,
        cbom_digest=f"sha256:{'a' * 64}",
    )


def test_fake_provider_scopes_runs_and_returns_stored_cbom_bytes() -> None:
    tenant_a = f"tenant_{'a' * 52}"
    tenant_b = f"tenant_{'b' * 52}"
    run_a = f"run_{'a' * 52}"
    run_b = f"run_{'b' * 52}"
    finding_id = f"finding_{'a' * 52}"
    payload = b'{"bomFormat":"CycloneDX"}'
    provider = FakeDashboardDataProvider(
        {
            (tenant_a, run_a): _view(tenant_a, run_a, finding_id),
            (tenant_b, run_b): _view(tenant_b, run_b, finding_id),
        },
        cbom_store={(tenant_a, run_a): payload},
    )
    assert len(provider.list_runs()) == 2
    assert len(provider.list_runs(tenant_id=tenant_a)) == 1
    view = provider.get_run_view(tenant_id=tenant_a, run_id=run_a)
    assert view is not None
    assert view.inventory[0].finding_id == finding_id
    assert provider.get_persisted_cbom(tenant_id=tenant_a, run_id=run_a) == payload
    assert provider.get_persisted_cbom(tenant_id=tenant_b, run_id=run_a) is None
    filtered = filter_and_sort_inventory(view.inventory, DashboardFilters(search_query="RSA"))
    assert [row.finding_id for row in filtered] == [finding_id]
