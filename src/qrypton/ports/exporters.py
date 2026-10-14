"""Read-only CBOM document construction interface."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from qrypton.contracts.models import (
    Asset,
    BusinessContext,
    CryptoFinding,
    Evidence,
    PersistedMoscaEvaluation,
    Recommendation,
    RiskAssessment,
)
from qrypton.contracts.primitives import ScannerVersion
from qrypton.exporters.cyclonedx_1_6 import CbomExportContext
from qrypton.recommendations.schemas import PqcRecommendationPlan


class CBOMExporter(Protocol):
    name: str
    version: ScannerVersion

    def export(
        self,
        *,
        asset: Asset,
        findings: Sequence[CryptoFinding],
        assessments: Sequence[RiskAssessment],
        recommendations: Sequence[Recommendation],
        recommendation_plans: Sequence[PqcRecommendationPlan],
        evidence: Sequence[Evidence],
        context: CbomExportContext,
        business_context: BusinessContext | None = None,
        finding_business_contexts: dict[str, BusinessContext] | None = None,
        mosca_evaluations: Sequence[PersistedMoscaEvaluation] = (),
    ) -> bytes:
        """Return validated, deterministic CycloneDX 1.6 JSON without I/O."""
