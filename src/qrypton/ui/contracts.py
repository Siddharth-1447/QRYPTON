"""Strict, read-only Pydantic v2 DTOs crossing the UI boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, HttpUrl

from qrypton.contracts.enums import (
    AlgorithmFamily,
    MoscaUrgency,
    ObservationState,
    RiskLevel,
    RunStatus,
)
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
        "resolve", "configuration", "orchestration",
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
    unknown_findings_count: int = 0
    unassessed_findings_count: int
    run_status: RunStatus
    scanner_failed_count: int
    scanner_partial_count: int
    policy_passed: bool
    policy_violations: tuple[str, ...] = ()


class InventoryObservation(DomainModel):
    state: ObservationState = ObservationState.UNKNOWN
    value: str | float | bool | None = None
    rationale: str | None = None
    evidence_ids: tuple[str, ...] = ()


class InventoryEvidenceRow(DomainModel):
    id: str
    kind: str
    surface: str
    location: str | None = None
    confidence: float
    excerpt: str | None = None


class InventoryRow(DomainModel):
    """Single finding item presented in the crypto inventory table."""

    finding_id: str
    remediation_rank: int | None = None
    remediation_reason: str | None = None
    remediation_ruleset_version: str | None = None
    category: str
    algorithm_name: str | None = None
    algorithm_family: str | None = None
    algorithm_variant: str | None = None
    crypto_role: str | None = None
    library_name: str | None = None
    identity_status: str = "unknown"
    identity_label: str = "No cryptographic identity could be established"
    identification_confidence: float = 0.0
    usage_confidence: float = 0.0
    confidence_reasons: tuple[str, ...] = ()
    key_size_bits: int | None = None
    lifecycle_status: str | None = None
    quantum_resistant: bool = False
    risk_level: RiskLevel
    risk_assessment_state: Literal["assessed", "unassessed"] = "unassessed"
    business_criticality: Literal[
        "critical", "high", "medium", "low", "unclassified"
    ] = "unclassified"
    risk_score: float | None = None
    confidence: float
    evidence_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    asset_id: str | None = None
    application: str | None = None
    artifact_type: str | None = None
    environment: str | None = None
    source_surfaces: tuple[str, ...] = ()
    observations: dict[str, InventoryObservation] = Field(default_factory=dict)
    evidence_rows: tuple[InventoryEvidenceRow, ...] = ()
    quantum_status: Literal["resistant", "vulnerable", "quantum_relevant", "unknown"] = "unknown"
    quantum_rationale: str | None = None
    timeline_overflow: bool | None = None
    mosca_urgency: str = "unknown"
    missing_business_context: bool = True
    migration_status: str = "New"
    assigned_owner: str | None = None
    in_roadmap: bool = False


class RiskHeatmapCell(DomainModel):
    """Single cell on the Mosca urgency × business criticality grid."""

    mosca_urgency: MoscaUrgency
    business_criticality: Literal["low", "medium", "high", "critical", "unclassified"]
    finding_count: int
    finding_ids: tuple[str, ...] = ()


class MoscaPoint(DomainModel):
    """Mosca chart point copied from persistence; timelines stay null when unavailable."""

    finding_id: str
    urgency: MoscaUrgency
    mosca_applicable: Literal["yes", "no", "unknown"] = "unknown"
    exposure_score: float | None = None
    x_data_lifetime_years: float | None = None
    y_migration_years: float | None = None
    z_crqc_horizon_years: float | None = None
    required_security_years: float | None = None
    time_margin_years: float | None = None
    timeline_state: Literal["persisted", "unavailable"] = "unavailable"
    x_source: str | None = None


class EvidenceAuthenticity(DomainModel):
    """Whether the finding came from inspected bytes or identifier inference."""

    quality: Literal["observed", "inferred"]
    summary: str
    confidence_applicable: bool


class FindingDetail(DomainModel):
    """Canonical finding drill-down assembled from persisted run records."""

    finding: CryptoFinding
    investigation_context: dict[str, InventoryObservation] = Field(default_factory=dict)
    application_name: str | None = None
    application_run_id: str | None = None
    evidence_quality: dict[str, Literal["observed", "inferred"]] = Field(default_factory=dict)
    assessment: RiskAssessment | None = None
    business_criticality: Literal[
        "critical", "high", "medium", "low", "unclassified"
    ] = "unclassified"
    mosca: MoscaPoint | None = None
    recommendations: tuple[Recommendation, ...] = ()
    evidence_provenance: tuple[Evidence, ...] = ()
    failures: tuple[SafeRunFailure, ...] = ()
    evidence_authenticity: EvidenceAuthenticity | None = None
    migration_status: str = "New"
    assigned_owner: str | None = None
    in_roadmap: bool = False


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
    assigned_owner: str | None = None
    migration_status: str = "New"
    in_roadmap: bool = False


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
