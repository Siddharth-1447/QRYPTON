"""Strict, read-only Pydantic v2 DTOs crossing the UI boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, HttpUrl

from qrypton.contracts.enums import AlgorithmFamily, RiskLevel, RunStatus
from qrypton.contracts.models import (
    CryptoFinding,
    DomainModel,
    Evidence,
    Recommendation,
    RiskAssessment,
)


class SafeRunFailure(DomainModel):
    """Sanitized execution failure; no exception text or filesystem paths."""

    stage: Literal[
        "scanner", "normalization", "correlation", "risk", "recommendation", "export", "store"
    ]
    error_code: str
    scanner_name: str | None = None
    message: str


class DashboardFilters(DomainModel):
    """Filter criteria applied in-memory to inventory rows."""

    category: str | None = None
    risk_level: RiskLevel | None = None
    algorithm_family: AlgorithmFamily | None = None
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    search_query: str | None = None


class DashboardRunSummary(DomainModel):
    """Metadata summary of a persisted run for list/selection."""

    tenant_id: str
    run_id: str
    status: RunStatus
    record_state: Literal["complete", "metadata_only"] = "complete"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_findings: int | None = None


class ExecutivePosture(DomainModel):
    """High-level measured counts for the selected persisted run."""

    total_findings: int
    unique_asset_ids: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    informational_findings_count: int
    unassessed_findings_count: int
    run_status: RunStatus
    scanner_failed_count: int
    scanner_partial_count: int
    policy_passed: bool
    policy_violations: tuple[str, ...] = ()


class InventoryRow(DomainModel):
    """Single finding item presented in the crypto inventory table."""

    finding_id: str
    category: str
    algorithm_name: str | None = None
    algorithm_family: str | None = None
    key_size_bits: int | None = None
    lifecycle_status: str | None = None
    risk_level: RiskLevel
    risk_score: float | None = None
    confidence: float
    evidence_count: int
    first_observed_at: datetime
    last_observed_at: datetime


class RiskHeatmapCell(DomainModel):
    """Single cell on the Mosca urgency × business criticality grid."""

    mosca_urgency: RiskLevel
    business_criticality: Literal["low", "medium", "high", "critical", "unclassified"]
    finding_count: int
    finding_ids: tuple[str, ...] = ()


class MoscaPoint(DomainModel):
    """Mosca chart point copied from persistence; timelines stay null when unavailable."""

    finding_id: str
    urgency: RiskLevel
    exposure_score: float | None = None
    x_data_lifetime_years: float | None = None
    y_migration_years: float | None = None
    z_crqc_horizon_years: float | None = None
    required_security_years: float | None = None
    time_margin_years: float | None = None
    timeline_state: Literal["persisted", "unavailable"] = "unavailable"


class FindingDetail(DomainModel):
    """Canonical finding drill-down assembled from persisted run records."""

    finding: CryptoFinding
    assessment: RiskAssessment | None = None
    recommendations: tuple[Recommendation, ...] = ()
    evidence_provenance: tuple[Evidence, ...] = ()
    failures: tuple[SafeRunFailure, ...] = ()


class RoadmapRow(DomainModel):
    """Single recommendation item in the PQC migration roadmap."""

    finding_id: str
    priority: int
    action: str
    role: str | None = None
    target_algorithms: tuple[str, ...] = ()
    hybrid_mode: str | None = None
    blocking_conditions: tuple[str, ...] = ()
    standards_references: tuple[HttpUrl, ...] = ()


class DashboardRunView(DomainModel):
    """Aggregated, read-only dashboard view model for a run."""

    summary: DashboardRunSummary
    posture: ExecutivePosture
    inventory: tuple[InventoryRow, ...]
    heatmap_cells: tuple[RiskHeatmapCell, ...]
    mosca_points: tuple[MoscaPoint, ...]
    roadmap: tuple[RoadmapRow, ...]
    has_cbom: bool
    cbom_digest: str | None = None
