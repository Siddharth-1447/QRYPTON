"""Interfaces for untrusted-input scanning adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Annotated, Literal, Protocol

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
    max_file_bytes: Annotated[int, Field(gt=0)] = 64 * 1024 * 1024


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


class SourceObservation(RawObservation):
    """Bounded source-analysis output; this is evidence, not a finding schema."""

    language: Literal["python", "c", "cpp"]
    detector_type: Literal["python_ast", "python_lexical", "cpp_lexical", "gcc_syntax_gate"]
    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_file_digest: Sha256Digest


class BinaryObservation(RawObservation):
    """Bounded binary-analysis output from a local executable image."""

    format: Literal["elf", "pe", "mach_o"]
    detector_type: Literal["symbol", "import", "export", "entropy"]
    binary_digest: Sha256Digest


class ScannerPlugin(Protocol):
    name: str
    version: ScannerVersion
    supported_targets: frozenset[ScanTargetKind]

    def scan(self, request: ScanRequest) -> AsyncIterator[RawObservation]:
        """Stream bounded observations; never execute or trust target contents."""


class SourceScanner(ScannerPlugin, Protocol):
    name: Literal["qrypton-source"]

    def scan(self, request: ScanRequest) -> AsyncIterator[SourceObservation]:
        """Stream read-only source observations from a local source-tree target."""


class BinaryScanner(ScannerPlugin, Protocol):
    name: Literal["qrypton-binary"]

    def scan(self, request: ScanRequest) -> AsyncIterator[BinaryObservation]:
        """Stream read-only observations from one local executable image."""
