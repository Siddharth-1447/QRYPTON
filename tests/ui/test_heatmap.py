"""Heatmap aggregation never invents business criticality or missing urgency."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from qrypton.application.schemas import PolicyOutcome, RunResult
from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import sample_evidence, sample_finding


def test_heatmap_aggregation_unclassified_business_criticality(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    assert sum(cell.finding_count for cell in view.heatmap_cells) == len(view.inventory)
    active = [cell for cell in view.heatmap_cells if cell.finding_count > 0]
    assert active
    for cell in active:
        assert cell.business_criticality == "unclassified"
        assert cell.mosca_urgency is not RiskLevel.LOW
    crit = next(
        cell
        for cell in view.heatmap_cells
        if cell.mosca_urgency == RiskLevel.CRITICAL and cell.business_criticality == "unclassified"
    )
    high = next(
        cell
        for cell in view.heatmap_cells
        if cell.mosca_urgency == RiskLevel.HIGH and cell.business_criticality == "unclassified"
    )
    assert crit.finding_count == 1
    assert high.finding_count == 1


def test_heatmap_unassessed_finding_uses_unknown_urgency(tmp_path: Path) -> None:
    tenant_id = f"tenant_{'h' * 52}"
    run_id = f"run_{'h' * 52}"
    asset_id = f"asset_{'h' * 52}"
    target_id = f"target_{'h' * 52}"
    evidence_id = f"evidence_{'h' * 52}"
    finding_id = f"finding_{'h' * 52}"
    store = SqliteRunStore(tmp_path / "unassessed.sqlite3")
    store.finalize_run(
        RunResult(
            run_id=run_id,
            tenant_id=tenant_id,
            status=RunStatus.PARTIAL,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            evidence=(sample_evidence(evidence_id, tenant_id, asset_id, target_id),),
            findings=(sample_finding(finding_id, tenant_id, asset_id, target_id, evidence_id),),
            policy_outcome=PolicyOutcome(passed=False, violations=("partial_run",)),
        )
    )
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    unknown = next(
        cell
        for cell in view.heatmap_cells
        if cell.mosca_urgency == RiskLevel.UNKNOWN and cell.business_criticality == "unclassified"
    )
    assert unknown.finding_ids == (finding_id,)
    assert view.inventory[0].risk_level == RiskLevel.UNKNOWN
    assert view.posture.unassessed_findings_count == 1
