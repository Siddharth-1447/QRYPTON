"""CI-specific policy configuration for delta-level gating."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from qrypton.contracts.enums import RiskLevel
from qrypton.contracts.models import DomainModel


class CiPolicyConfig(DomainModel):
    """Configurable thresholds for CI gating decisions.

    These control the *delta-level* gate: how many newly introduced findings
    at each severity are tolerated before the CI run fails.  This is
    complementary to ``PolicyGate.max_allowed_risk`` which gates all findings.

    A ``None`` threshold means unlimited findings at that severity are allowed.
    """

    max_new_critical: Annotated[int | None, Field(ge=0)] = 0
    max_new_high: Annotated[int | None, Field(ge=0)] = 0
    max_new_medium: Annotated[int | None, Field(ge=0)] = None
    max_new_low: Annotated[int | None, Field(ge=0)] = None
    fail_on_baseline_drift: bool = False
    fail_on_scanner_failure: bool = True
    fail_on_partial_scan: bool = True

    def threshold_for(self, level: RiskLevel) -> int | None:
        """Return the maximum allowed new findings for a given risk level."""
        mapping: dict[RiskLevel, int | None] = {
            RiskLevel.CRITICAL: self.max_new_critical,
            RiskLevel.HIGH: self.max_new_high,
            RiskLevel.MEDIUM: self.max_new_medium,
            RiskLevel.LOW: self.max_new_low,
            RiskLevel.INFORMATIONAL: None,
            RiskLevel.UNKNOWN: self.max_new_critical,  # treat unknown as critical
        }
        return mapping.get(level)
