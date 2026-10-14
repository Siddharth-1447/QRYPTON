"""Offline policy contracts for NIST PQC-based future engines."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field, HttpUrl

from qrypton.contracts.models import DomainModel
from qrypton.contracts.primitives import NonEmptyText, UtcDateTime
from qrypton.recommendations.schemas import (
    CompatibilityFactors,
    CryptoRole,
    HybridMode,
    SignatureSelection,
)


class PolicyIdentity(DomainModel):
    profile_id: NonEmptyText
    profile_version: NonEmptyText
    published_at: UtcDateTime


class RiskPolicy(PolicyIdentity):
    """Opaque policy identity plus an explicit deterministic crypto taxonomy."""

    kind: Literal["risk"] = "risk"
    risk_taxonomy_version: Literal["1.0.0"] = "1.0.0"
    priority_ruleset_version: Literal["1.0.0"] = "1.0.0"


class PqcRecommendationPolicy(PolicyIdentity):
    """Versioned, deterministic controls for PQC recommendation selection."""

    kind: Literal["pqc_recommendation"] = "pqc_recommendation"
    nist_references: tuple[HttpUrl, ...]
    supported_fips: tuple[Literal["FIPS-203", "FIPS-204", "FIPS-205"], ...] = (
        "FIPS-203",
        "FIPS-204",
        "FIPS-205",
    )
    minimum_security_strength_bits: Annotated[int | None, Field(ge=0, le=1_000_000)] = None
    hybrid_kem_mode: HybridMode = HybridMode.OPTIONAL
    signature_selection: SignatureSelection = SignatureSelection.ML_DSA
    allow_slh_dsa_alternative: bool = True
    required_peer_support: bool = False
    require_hsm_kms_support: bool = False
    default_compatibility: CompatibilityFactors = Field(default_factory=CompatibilityFactors)
    role_overrides: Mapping[Annotated[str, Field(min_length=1, max_length=256)], CryptoRole] = (
        Field(default_factory=dict)
    )
