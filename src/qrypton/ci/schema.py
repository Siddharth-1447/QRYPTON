"""Pydantic models for the machine-readable CI result document."""

from __future__ import annotations

from typing import Literal

from qrypton.contracts.models import DomainModel


class CiDelta(DomainModel):
    """A single finding that changed between baseline and current scan."""

    fingerprint: str
    change: Literal["new", "removed", "changed"]
    risk_level: str


class CiScannerSummary(DomainModel):
    """Aggregate scanner health for the CI run."""

    failed: int
    partial: int


class CiPolicySummary(DomainModel):
    """Run-level policy gate outcome."""

    passed: bool
    violations: tuple[str, ...]


class CiBaselineRef(DomainModel):
    """Reference to the baseline used for comparison."""

    schema_version: str | None
    run_id: str | None


class CiScope(DomainModel):
    """Scan scope metadata."""

    changed_from: str | None
    mode: Literal["full_repository"]


class CiResult(DomainModel):
    """Complete, validated CI result document.

    This model is the canonical schema for ``qrypton.ci.json`` artifacts.
    It deliberately excludes all evidence, source locations, excerpts, and
    secrets so the artifact is safe to upload and share.
    """

    schema_version: Literal["1.0"]
    exit_code: int
    exit_reason: str
    run_id: str
    status: str
    policy: CiPolicySummary
    scanner: CiScannerSummary
    inventory: dict[str, dict[str, str]]
    delta: tuple[CiDelta, ...]
    introduced: tuple[CiDelta, ...]
    baseline: CiBaselineRef | None
    scope: CiScope
