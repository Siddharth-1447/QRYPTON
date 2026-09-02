"""Pure risk-assessment interface."""

from __future__ import annotations

from typing import Protocol

from qrypton.contracts.models import BusinessContext, CryptoFinding, RiskAssessment
from qrypton.contracts.primitives import ScannerVersion
from qrypton.policies.pqc import RiskPolicy


class RiskEngine(Protocol):
    name: str
    version: ScannerVersion

    def assess(
        self,
        finding: CryptoFinding,
        business_context: BusinessContext | None,
        policy: RiskPolicy,
    ) -> RiskAssessment:
        """Assess a finding deterministically; missing context remains unknown."""
