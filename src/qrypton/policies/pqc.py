"""Offline policy contracts for NIST PQC-based future engines."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, HttpUrl

from qrypton.contracts.models import DomainModel
from qrypton.contracts.primitives import NonEmptyText, UtcDateTime


class PolicyIdentity(DomainModel):
    profile_id: NonEmptyText
    profile_version: NonEmptyText
    published_at: UtcDateTime


class RiskPolicy(PolicyIdentity):
    """Opaque, versioned risk-policy identity for pure engine input."""

    kind: Literal["risk"] = "risk"


class PqcRecommendationPolicy(PolicyIdentity):
    """NIST-aligned policy identity; content is deliberately deferred."""

    kind: Literal["pqc_recommendation"] = "pqc_recommendation"
    nist_references: tuple[HttpUrl, ...]
    supported_fips: tuple[Literal["FIPS-203", "FIPS-204", "FIPS-205"], ...] = (
        "FIPS-203",
        "FIPS-204",
        "FIPS-205",
    )
    minimum_security_strength_bits: Annotated[int | None, Field(ge=0, le=1_000_000)] = None
