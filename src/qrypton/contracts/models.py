"""Canonical immutable Pydantic v2 domain models."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmIdentificationStatus,
    AlgorithmStatus,
    AssetKind,
    Criticality,
    EvidenceCollectionMode,
    EvidenceKind,
    EvidenceSurface,
    KeyKind,
    MoscaUrgency,
    ObservationState,
    ProtocolLayer,
    RecommendationKind,
    RiskLevel,
    ScanTargetKind,
)
from qrypton.contracts.primitives import (
    Confidence,
    EntityId,
    Excerpt,
    JsonScalar,
    NonEmptyText,
    RelativePath,
    RiskScore,
    ScannerVersion,
    Sha256Digest,
    TenantId,
    UtcDateTime,
)

T = TypeVar("T")


class DomainModel(BaseModel):
    """Strict, immutable base model for every canonical record."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Observation(DomainModel, Generic[T]):
    """A value plus explicit evidence-backed knowledge semantics."""

    state: ObservationState
    value: T | None = None
    basis_evidence_ids: tuple[EntityId, ...] = ()
    rationale: Annotated[str | None, Field(max_length=1024)] = None

    @model_validator(mode="after")
    def validate_state(self) -> Observation[T]:
        if self.state is ObservationState.OBSERVED:
            if self.value is None or not self.basis_evidence_ids:
                raise ValueError("observed state requires a value and evidence")
        elif self.state is ObservationState.CONFIRMED_ABSENT:
            if self.value is not None or not self.basis_evidence_ids:
                raise ValueError("confirmed_absent requires evidence and no value")
        elif self.value is not None or self.basis_evidence_ids:
            raise ValueError(f"{self.state.value} must not carry a value or evidence")
        return self


class EvidenceLocation(DomainModel):
    relative_path: RelativePath | None = None
    line_start: Annotated[int | None, Field(ge=1)] = None
    line_end: Annotated[int | None, Field(ge=1)] = None
    byte_start: Annotated[int | None, Field(ge=0)] = None
    byte_end: Annotated[int | None, Field(ge=0)] = None
    symbol: Annotated[str | None, Field(max_length=1024)] = None
    image_layer_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_ranges(self) -> EvidenceLocation:
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must not precede line_start")
        if (
            self.byte_start is not None
            and self.byte_end is not None
            and self.byte_end < self.byte_start
        ):
            raise ValueError("byte_end must not precede byte_start")
        return self


class Provenance(DomainModel):
    scanner_name: NonEmptyText
    scanner_version: ScannerVersion
    scanner_config_digest: Sha256Digest
    observed_at: UtcDateTime
    source_digest: Sha256Digest | None = None
    parent_evidence_ids: tuple[EntityId, ...] = ()


class Asset(DomainModel):
    id: EntityId
    tenant_id: TenantId
    kind: AssetKind
    external_reference: NonEmptyText
    name: NonEmptyText
    owner_reference: Annotated[str | None, Field(max_length=256)] = None
    tags: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    created_at: UtcDateTime
    updated_at: UtcDateTime
    provenance: Provenance

    @model_validator(mode="after")
    def validate_times(self) -> Asset:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self


class ScanTarget(DomainModel):
    id: EntityId
    tenant_id: TenantId
    asset_id: EntityId
    kind: ScanTargetKind
    locator: NonEmptyText
    content_digest: Observation[Sha256Digest]
    declared_size_bytes: Observation[Annotated[int, Field(ge=0)]]
    requested_at: UtcDateTime
    provenance: Provenance


class Evidence(DomainModel):
    id: EntityId
    tenant_id: TenantId
    asset_id: EntityId
    scan_target_id: EntityId
    kind: EvidenceKind
    surface: EvidenceSurface = EvidenceSurface.UNKNOWN
    collection_mode: EvidenceCollectionMode = EvidenceCollectionMode.UNKNOWN
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = ()
    location: EvidenceLocation
    raw_content_digest: Sha256Digest | None = None
    excerpt: Excerpt | None = None
    attributes: Mapping[Annotated[str, Field(min_length=1, max_length=128)], JsonScalar] = Field(
        default_factory=dict
    )
    confidence: Confidence
    deduplication_fingerprint: Sha256Digest
    provenance: Provenance


class Algorithm(DomainModel):
    canonical_name: NonEmptyText
    family: AlgorithmFamily
    parameters: Mapping[Annotated[str, Field(min_length=1, max_length=64)], JsonScalar] = Field(
        default_factory=dict
    )
    key_size_bits: Observation[Annotated[int, Field(ge=1, le=1_000_000)]]
    security_strength_bits: Observation[Annotated[int, Field(ge=0, le=1_000_000)]]
    lifecycle_status: AlgorithmStatus
    registry_reference: HttpUrl | None = None

    @model_validator(mode="after")
    def validate_unknown(self) -> Algorithm:
        if self.canonical_name.casefold() == "unknown" and (
            self.family is not AlgorithmFamily.UNKNOWN
            and self.lifecycle_status is not AlgorithmStatus.UNKNOWN
        ):
            raise ValueError("unknown algorithm name requires unknown family or lifecycle status")
        return self


class KeyMaterialMetadata(DomainModel):
    kind: KeyKind
    size_bits: Observation[Annotated[int, Field(ge=1, le=1_000_000)]]
    storage_protection: Observation[Literal["hsm", "kms", "software", "unknown"]]
    rotation_interval_days: Observation[Annotated[int, Field(ge=1, le=36_500)]]
    exportable: Observation[bool]
    private_material_observed: Observation[bool]


class CertificateMetadata(DomainModel):
    subject_dn: Observation[Annotated[str, Field(max_length=2048)]]
    issuer_dn: Observation[Annotated[str, Field(max_length=2048)]]
    serial_number: Observation[Annotated[str, Field(max_length=512)]]
    not_before: Observation[UtcDateTime]
    not_after: Observation[UtcDateTime]
    signature_algorithm: Observation[Algorithm]
    public_key_algorithm: Observation[Algorithm]

    @model_validator(mode="after")
    def validate_validity_window(self) -> CertificateMetadata:
        if (
            self.not_before.value
            and self.not_after.value
            and self.not_after.value < self.not_before.value
        ):
            raise ValueError("certificate not_after must not precede not_before")
        return self


class ProtocolMetadata(DomainModel):
    name: Observation[NonEmptyText]
    version: Observation[Annotated[str, Field(max_length=128)]]
    layer: ProtocolLayer
    cipher_suite: Observation[NonEmptyText]
    peer_authentication: Observation[Literal["none", "server", "mutual", "unknown"]]


class LibraryMetadata(DomainModel):
    ecosystem: Observation[Annotated[str, Field(max_length=128)]]
    name: Observation[NonEmptyText]
    version: Observation[Annotated[str, Field(max_length=256)]]
    package_url: Observation[Annotated[str, Field(max_length=2048)]]
    known_maintenance_state: Observation[Literal["maintained", "unmaintained", "unknown"]]


class CryptoFinding(DomainModel):
    id: EntityId
    tenant_id: TenantId
    asset_id: EntityId
    scan_target_id: EntityId
    category: Literal["algorithm_use", "key_material", "certificate", "protocol", "library"]
    algorithm: Observation[Algorithm]
    key_material: Observation[KeyMaterialMetadata]
    certificate: Observation[CertificateMetadata]
    protocol: Observation[ProtocolMetadata]
    library: Observation[LibraryMetadata]
    algorithm_family: AlgorithmFamily | None = None
    algorithm_variant: Annotated[str | None, Field(max_length=256)] = None
    crypto_role: Annotated[str | None, Field(max_length=128)] = None
    algorithm_identification_status: AlgorithmIdentificationStatus = (
        AlgorithmIdentificationStatus.UNKNOWN
    )
    algorithm_identification_confidence: Confidence = 0.0
    algorithm_identification_evidence: tuple[EntityId, ...] = ()
    confidence_reasons: tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...] = ()
    identification_confidence: Confidence = 0.0
    usage_confidence: Confidence = 0.0
    mosca_x_data_lifetime_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)] = None
    mosca_y_migration_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)] = None
    mosca_x_source: Literal["finding", "asset", "scenario", "unknown"] = "unknown"
    mosca_y_source: Literal["finding", "asset", "scenario", "unknown"] = "unknown"
    evidence_ids: Annotated[tuple[EntityId, ...], Field(min_length=1)]
    confidence: Confidence
    first_observed_at: UtcDateTime
    last_observed_at: UtcDateTime
    provenance: Provenance
    correlation_provenance: Provenance | None = None

    @model_validator(mode="after")
    def validate_times(self) -> CryptoFinding:
        if self.last_observed_at < self.first_observed_at:
            raise ValueError("last_observed_at must not precede first_observed_at")
        for value, source, label in (
            (self.mosca_x_data_lifetime_years, self.mosca_x_source, "X"),
            (self.mosca_y_migration_years, self.mosca_y_source, "Y"),
        ):
            if value is None and source != "unknown":
                raise ValueError(f"Mosca {label} source requires a corresponding value")
        if self.mosca_x_data_lifetime_years is not None and self.mosca_x_source == "unknown":
            object.__setattr__(self, "mosca_x_source", "finding")
        if self.mosca_y_migration_years is not None and self.mosca_y_source == "unknown":
            object.__setattr__(self, "mosca_y_source", "finding")
        algorithm = (
            self.algorithm.value if self.algorithm.state is ObservationState.OBSERVED else None
        )
        updates: dict[str, object] = {}
        if self.algorithm_family is None and algorithm is not None:
            updates["algorithm_family"] = algorithm.family
        if self.algorithm_variant is None and algorithm is not None:
            updates["algorithm_variant"] = algorithm.canonical_name
        if (
            self.algorithm_identification_status is AlgorithmIdentificationStatus.UNKNOWN
            and algorithm is not None
        ):
            updates["algorithm_identification_status"] = (
                AlgorithmIdentificationStatus.IDENTIFIED
                if algorithm.family is not AlgorithmFamily.UNKNOWN
                and algorithm.canonical_name.casefold() != "unknown"
                else AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED
            )
        if not self.algorithm_identification_evidence and algorithm is not None:
            updates["algorithm_identification_evidence"] = self.algorithm.basis_evidence_ids
        if (
            algorithm is not None
            and self.algorithm_identification_confidence == 0.0
            and algorithm.family is not AlgorithmFamily.UNKNOWN
        ):
            updates["algorithm_identification_confidence"] = self.confidence
        if self.identification_confidence == 0.0 and algorithm is not None:
            identification_confidence = updates.get(
                "algorithm_identification_confidence", self.algorithm_identification_confidence
            )
            if isinstance(identification_confidence, (int, float)):
                updates["identification_confidence"] = float(identification_confidence)
        if self.usage_confidence == 0.0:
            updates["usage_confidence"] = self.confidence
        if not self.confidence_reasons:
            updates["confidence_reasons"] = (
                "Finding confidence is supported by evidence: " + ", ".join(self.evidence_ids),
            )
        for field_name, update_value in updates.items():
            # The validator computes updates across heterogeneous model fields.
            # Pydantic validates each field before this immutable normalization.
            object.__setattr__(self, field_name, update_value)
        return self


class BusinessContext(DomainModel):
    id: EntityId
    tenant_id: TenantId
    asset_id: EntityId
    criticality: Observation[Criticality]
    data_classification: Observation[Literal["public", "internal", "confidential", "restricted"]]
    internet_exposed: Observation[bool]
    regulatory_scopes: tuple[NonEmptyText, ...] = ()
    owner_reference: Observation[Annotated[str, Field(max_length=256)]]
    environment: Annotated[str | None, Field(default=None, max_length=64)] = None
    migration_complexity: Annotated[str | None, Field(default=None, max_length=32)] = None
    mosca_x_data_lifetime_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)] = None
    mosca_y_migration_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)] = None
    provenance: Provenance


class RiskFactors(DomainModel):
    cryptographic_obsolescence: Observation[RiskScore]
    quantum_exposure: Observation[RiskScore]
    exploitability: Observation[RiskScore]
    business_impact: Observation[RiskScore]
    evidence_confidence: Confidence
    policy_profile_id: NonEmptyText
    policy_profile_version: NonEmptyText
    rationale: tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...]
    # Independent categorical dimensions. The numeric legacy factors above remain
    # available for API compatibility; UNKNOWN means evidence was insufficient.
    crypto_risk: RiskLevel = RiskLevel.UNKNOWN
    quantum_risk: RiskLevel = RiskLevel.UNKNOWN
    business_impact_risk: RiskLevel = RiskLevel.UNKNOWN
    business_criticality: Criticality = Criticality.UNKNOWN
    risk_taxonomy_version: Literal["1.0.0"] = "1.0.0"
    priority_ruleset_version: Literal["1.0.0"] = "1.0.0"


class RiskAssessment(DomainModel):
    id: EntityId
    tenant_id: TenantId
    finding_id: EntityId
    business_context_id: EntityId | None = None
    score: Observation[RiskScore]
    level: RiskLevel
    final_priority: RiskLevel = RiskLevel.UNKNOWN
    mosca_urgency: MoscaUrgency = MoscaUrgency.UNKNOWN
    mosca_applicable: Literal["yes", "no", "unknown"] = "unknown"
    # Optional for historical run records written before assessment confidence existed.
    context_completeness: Confidence | None = None
    assessment_confidence: Confidence | None = None
    factors: RiskFactors
    assessed_at: UtcDateTime
    engine_name: NonEmptyText
    engine_version: ScannerVersion
    evidence_ids: tuple[EntityId, ...]

    @model_validator(mode="after")
    def preserve_legacy_priority(self) -> RiskAssessment:
        if self.final_priority is RiskLevel.UNKNOWN and self.level is not RiskLevel.UNKNOWN:
            object.__setattr__(self, "final_priority", self.level)
        elif self.level is not self.final_priority:
            raise ValueError("level and final_priority must match")
        return self


class PersistedMoscaEvaluation(DomainModel):
    """Structured Mosca timelines persisted with a run; not reconstructed from rationale text."""

    finding_id: EntityId
    x_data_lifetime_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)]
    y_migration_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)]
    z_crqc_horizon_years: Annotated[float | None, Field(ge=0.0, le=10_000.0)]
    required_security_years: Annotated[float | None, Field(ge=0.0, le=20_000.0)]
    time_margin_years: Annotated[float | None, Field(ge=-20_000.0, le=10_000.0)]
    exposure_score: Annotated[float | None, Field(ge=0.0, le=100.0)]
    urgency: Literal["critical", "high", "medium", "low", "not_applicable", "unknown"]
    mosca_applicable: Literal["yes", "no", "unknown"] = "unknown"
    x_source: str = "scenario"
    y_source: str = "scenario"
    z_source: str = "scenario"
    reason: str = ""
    mosca_ruleset_version: Literal["1.0.0"] = "1.0.0"


class Recommendation(DomainModel):
    id: EntityId
    tenant_id: TenantId
    finding_id: EntityId
    risk_assessment_id: EntityId | None = None
    kind: RecommendationKind
    priority: Annotated[int, Field(ge=1, le=100)]
    title: NonEmptyText
    action: Annotated[str, Field(min_length=1, max_length=4096)]
    nist_references: tuple[HttpUrl, ...]
    policy_profile_id: NonEmptyText
    policy_profile_version: NonEmptyText
    replacement_algorithm: Observation[Algorithm]
    created_at: UtcDateTime
    provenance: Provenance


class ScanResult(DomainModel):
    id: EntityId
    tenant_id: TenantId
    scan_target_id: EntityId
    status: Literal["completed", "partial", "failed"]
    started_at: UtcDateTime
    completed_at: UtcDateTime | None = None
    scanner_name: NonEmptyText
    scanner_version: ScannerVersion
    evidence_ids: tuple[EntityId, ...]
    finding_ids: tuple[EntityId, ...]
    warnings: tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...] = ()
    failure_reason: Annotated[str | None, Field(max_length=2048)] = None

    @model_validator(mode="after")
    def validate_status(self) -> ScanResult:
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if self.status == "failed" and not self.failure_reason:
            raise ValueError("failed scan requires failure_reason")
        if self.status != "failed" and self.failure_reason is not None:
            raise ValueError("only failed scan may include failure_reason")
        return self


class CBOMComponentRecord(DomainModel):
    bom_ref: NonEmptyText
    component_type: Literal["application", "library", "cryptographic_asset"]
    name: NonEmptyText
    version: str | None = None
    purl: str | None = None
    properties: Mapping[str, JsonScalar] = Field(default_factory=dict)


class CBOMCryptoAssetRecord(DomainModel):
    bom_ref: NonEmptyText
    finding_id: EntityId
    algorithm: Observation[Algorithm]
    key_material: Observation[KeyMaterialMetadata]
    certificate: Observation[CertificateMetadata]
    protocol: Observation[ProtocolMetadata]
    evidence_ids: tuple[EntityId, ...]
    risk_assessment_id: EntityId | None = None
    recommendation_ids: tuple[EntityId, ...] = ()


class CBOMExport(DomainModel):
    id: EntityId
    tenant_id: TenantId
    cyclonedx_spec_version: Literal["1.6"]
    serial_number: UUID
    generated_at: UtcDateTime
    tool_name: Literal["qrypton"]
    tool_version: ScannerVersion
    components: tuple[CBOMComponentRecord, ...]
    crypto_assets: tuple[CBOMCryptoAssetRecord, ...]
