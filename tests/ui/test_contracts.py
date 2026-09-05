"""Unit tests validating dashboard DTO contracts and serialization."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.ui.contracts import (
    DashboardFilters,
    DashboardRunSummary,
    ExecutivePosture,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
    SafeRunFailure,
)


def test_dashboard_run_summary_contract() -> None:
    summary = DashboardRunSummary(
        tenant_id="tenant_123",
        run_id="run_456",
        status=RunStatus.COMPLETED,
        record_state="complete",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        total_findings=12,
    )
    restored = DashboardRunSummary.model_validate(summary.model_dump(mode="json"))
    assert restored.run_id == "run_456"
    assert restored.total_findings == 12
    with pytest.raises(ValidationError):
        DashboardRunSummary(
            tenant_id="t",
            run_id="r",
            status=RunStatus.COMPLETED,
            extra_field="disallowed",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        summary.total_findings = 99  # type: ignore[misc]


def test_metadata_only_summary_omits_invented_counts() -> None:
    summary = DashboardRunSummary(
        tenant_id="t",
        run_id="r",
        status=RunStatus.PENDING,
        record_state="metadata_only",
    )
    assert summary.started_at is None
    assert summary.total_findings is None


def test_executive_posture_contract() -> None:
    posture = ExecutivePosture(
        total_findings=10,
        unique_asset_ids=2,
        critical_findings_count=2,
        high_findings_count=3,
        medium_findings_count=4,
        low_findings_count=1,
        informational_findings_count=0,
        unassessed_findings_count=0,
        run_status=RunStatus.COMPLETED,
        scanner_failed_count=0,
        scanner_partial_count=1,
        policy_passed=True,
        policy_violations=(),
    )
    assert posture.unique_asset_ids == 2
    with pytest.raises(ValidationError):
        posture.policy_passed = False  # type: ignore[misc]


def test_inventory_row_and_filters_contract() -> None:
    row = InventoryRow(
        finding_id="finding_123",
        category="algorithm_use",
        algorithm_name="RSA",
        algorithm_family="asymmetric_encryption",
        key_size_bits=2048,
        lifecycle_status="deprecated",
        risk_level=RiskLevel.HIGH,
        risk_score=80.0,
        confidence=0.9,
        evidence_count=2,
        first_observed_at=datetime.now(UTC),
        last_observed_at=datetime.now(UTC),
    )
    filters = DashboardFilters(min_confidence=0.5, risk_level=RiskLevel.HIGH)
    assert row.algorithm_name == "RSA"
    assert filters.min_confidence == 0.5
    with pytest.raises(ValidationError):
        DashboardFilters(min_confidence=1.5)


def test_risk_heatmap_cell_contract() -> None:
    cell = RiskHeatmapCell(
        mosca_urgency=RiskLevel.UNKNOWN,
        business_criticality="unclassified",
        finding_count=3,
        finding_ids=("f1", "f2", "f3"),
    )
    assert cell.business_criticality == "unclassified"
    with pytest.raises(ValidationError):
        RiskHeatmapCell(
            mosca_urgency=RiskLevel.HIGH,
            business_criticality="secret",  # type: ignore[arg-type]
            finding_count=1,
        )


def test_mosca_point_unavailable_and_persisted_states() -> None:
    unavailable = MoscaPoint(
        finding_id="f1",
        urgency=RiskLevel.CRITICAL,
        exposure_score=95.0,
        timeline_state="unavailable",
    )
    assert unavailable.timeline_state == "unavailable"
    assert unavailable.x_data_lifetime_years is None
    persisted = MoscaPoint(
        finding_id="f1",
        urgency=RiskLevel.LOW,
        exposure_score=20.0,
        x_data_lifetime_years=5.0,
        y_migration_years=2.0,
        z_crqc_horizon_years=10.0,
        required_security_years=7.0,
        time_margin_years=3.0,
        timeline_state="persisted",
    )
    assert persisted.required_security_years == 7.0


def test_roadmap_row_and_safe_failure_contract() -> None:
    row = RoadmapRow(
        finding_id="f1",
        priority=1,
        action="Upgrade to ML-KEM-768",
        role="kem",
        target_algorithms=("ML-KEM-768",),
        hybrid_mode="required",
        blocking_conditions=("TLS 1.3 required",),
        standards_references=(),
    )
    failure = SafeRunFailure(stage="scanner", error_code="scanner_failed", message="stage failed")
    assert row.priority == 1
    assert failure.error_code == "scanner_failed"
