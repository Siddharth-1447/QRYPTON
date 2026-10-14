"""Pure risk-assessment interface."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from qrypton.contracts.models import BusinessContext, CryptoFinding, Evidence, RiskAssessment
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
        evidence: Sequence[Evidence] | Mapping[str, Evidence] | None = None,
    ) -> RiskAssessment:
        """Assess a finding deterministically; missing context remains unknown."""
