"""Pure PQC recommendation interface."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from qrypton.contracts.models import CryptoFinding, Recommendation, RiskAssessment
from qrypton.contracts.primitives import ScannerVersion
from qrypton.policies.pqc import PqcRecommendationPolicy


class RecommendationEngine(Protocol):
    name: str
    version: ScannerVersion

    def recommend(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment,
        policy: PqcRecommendationPolicy,
    ) -> Sequence[Recommendation]:
        """Return recommendations without I/O or hidden policy state."""
