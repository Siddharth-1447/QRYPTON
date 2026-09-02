"""Canonical immutable Pydantic v2 domain models."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    AssetKind,
    Criticality,
    EvidenceKind,
    KeyKind,
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
    evidence_ids: Annotated[tuple[EntityId, ...], Field(min_length=1)]
    confidence: Confidence
    first_observed_at: UtcDateTime
    last_observed_at: UtcDateTime
    provenance: Provenance

    @model_validator(mode="after")
    def validate_times(self) -> CryptoFinding:
        if self.last_observed_at < self.first_observed_at:
            raise ValueError("last_observed_at must not precede first_observed_at")
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


class RiskAssessment(DomainModel):
    id: EntityId
    tenant_id: TenantId
    finding_id: EntityId
    business_context_id: EntityId | None = None
    score: Observation[RiskScore]
    level: RiskLevel
    factors: RiskFactors
    assessed_at: UtcDateTime
    engine_name: NonEmptyText
    engine_version: ScannerVersion
    evidence_ids: tuple[EntityId, ...]


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
