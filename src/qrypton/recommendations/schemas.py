"""Immutable decision records for role-aware PQC recommendations."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, HttpUrl

from qrypton.contracts.models import Algorithm, DomainModel
from qrypton.contracts.primitives import Confidence, EntityId, JsonScalar


class CryptoRole(StrEnum):
    KEM = "kem"
    KEY_ESTABLISHMENT = "key_establishment"
    SIGNATURE = "signature"
    HASH = "hash"
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    MAC = "mac"
    KDF = "kdf"
    RNG = "rng"
    PROTOCOL_CONFIGURATION = "protocol_configuration"
    CERTIFICATE_PKI_ARTIFACT = "certificate_pki_artifact"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


class RecommendationBasis(StrEnum):
    STANDARDS_BACKED = "standards_backed"
    HEURISTIC = "heuristic"


class HybridMode(StrEnum):
    DISABLED = "disabled"
    OPTIONAL = "optional"
    REQUIRED = "required"


class SignatureSelection(StrEnum):
    ML_DSA = "ml_dsa"
    SLH_DSA = "slh_dsa"
    POLICY_RANKED = "policy_ranked"


class CompatibilityFactors(DomainModel):
    peer_support: Literal["confirmed", "unknown", "unsupported"] = "unknown"
    protocol_support: Literal["confirmed", "unknown", "unsupported"] = "unknown"
    hsm_kms_support: Literal["confirmed", "unknown", "unsupported"] = "unknown"
    certificate_ecosystem_support: Literal[
        "not_applicable", "confirmed", "unknown", "unsupported"
    ] = "not_applicable"
    performance_impact: Literal["low", "medium", "high", "unknown"] = "unknown"
    latency_impact: Literal["low", "medium", "high", "unknown"] = "unknown"
    migration_complexity: Literal["low", "medium", "high", "unknown"] = "unknown"
    operational_constraints: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = ()


class RoleClassification(DomainModel):
    role: CryptoRole
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    basis_evidence_ids: tuple[EntityId, ...]
    competing_roles: tuple[CryptoRole, ...] = ()
    confidence: Confidence


class RecommendationRationale(DomainModel):
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    role: CryptoRole
    basis: RecommendationBasis
    source_algorithm: Annotated[str | None, Field(max_length=512)] = None
    facts: dict[Annotated[str, Field(min_length=1, max_length=128)], JsonScalar] = Field(
        default_factory=dict
    )
    policy_decisions: dict[Annotated[str, Field(min_length=1, max_length=128)], JsonScalar] = Field(
        default_factory=dict
    )
    blocking_conditions: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = ()
    confidence: Confidence


class PqcRecommendationPlan(DomainModel):
    finding_id: EntityId
    role: CryptoRole
    target_algorithms: tuple[Algorithm, ...]
    hybrid_mode: HybridMode
    standard_references: tuple[HttpUrl, ...]
    basis: RecommendationBasis
    compatibility: CompatibilityFactors
    rationale: RecommendationRationale
    canonical_recommendation_ids: tuple[EntityId, ...]
