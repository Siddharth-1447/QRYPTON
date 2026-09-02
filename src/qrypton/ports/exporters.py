"""Read-only CBOM document construction interface."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from qrypton.contracts.models import (
    Asset,
    CBOMExport,
    CryptoFinding,
    Evidence,
    Recommendation,
    RiskAssessment,
)
from qrypton.contracts.primitives import ScannerVersion


class CBOMExporter(Protocol):
    name: str
    version: ScannerVersion

    def build(
        self,
        *,
        asset: Asset,
        findings: Sequence[CryptoFinding],
        assessments: Sequence[RiskAssessment],
        recommendations: Sequence[Recommendation],
        evidence: Sequence[Evidence],
    ) -> CBOMExport:
        """Build a validated CBOM contract without persistence or network I/O."""
