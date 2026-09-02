"""Interfaces for untrusted-input scanning adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Annotated, Protocol

from pydantic import Field

from qrypton.contracts.enums import EvidenceKind, ScanTargetKind
from qrypton.contracts.models import DomainModel, EvidenceLocation, ScanTarget
from qrypton.contracts.primitives import (
    Confidence,
    Excerpt,
    JsonScalar,
    ScannerVersion,
    Sha256Digest,
    TenantId,
)


class ScanLimits(DomainModel):
    """Mandatory upper bounds to be enforced by future scanner implementations."""

    max_compressed_bytes: Annotated[int, Field(gt=0)]
    max_expanded_bytes: Annotated[int, Field(gt=0)]
    max_file_count: Annotated[int, Field(gt=0)]
    max_nesting_depth: Annotated[int, Field(ge=0)]
    max_layer_count: Annotated[int, Field(gt=0)]
    max_ast_nodes: Annotated[int, Field(gt=0)]
    max_evidence_count: Annotated[int, Field(gt=0)]
    max_wall_time_seconds: Annotated[int, Field(gt=0)]
    max_memory_bytes: Annotated[int, Field(gt=0)]


class ScanRequest(DomainModel):
    tenant_id: TenantId
    target: ScanTarget
    limits: ScanLimits
    correlation_id: Annotated[str, Field(min_length=1, max_length=128)]


class RawObservation(DomainModel):
    """Bounded scanner output before canonical evidence normalization."""

    kind: EvidenceKind
    location: EvidenceLocation
    payload_digest: Sha256Digest | None = None
    attributes: Mapping[Annotated[str, Field(min_length=1, max_length=128)], JsonScalar] = Field(
        default_factory=dict
    )
    excerpt: Excerpt | None = None
    confidence: Confidence


class ScannerPlugin(Protocol):
    name: str
    version: ScannerVersion
    supported_targets: frozenset[ScanTargetKind]

    def scan(self, request: ScanRequest) -> AsyncIterator[RawObservation]:
        """Stream bounded observations; never execute or trust target contents."""
