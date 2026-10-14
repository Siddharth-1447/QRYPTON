"""Versioned remediation ordering over recorded inputs; finding volume is never a signal."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, Self, TypeVar

from qrypton.contracts.enums import ObservationState, RiskLevel


class RecordedObservation(Protocol):
    @property
    def state(self) -> ObservationState: ...
    @property
    def value(self) -> str | float | bool | None: ...


class RemediationRow(Protocol):
    @property
    def finding_id(self) -> str: ...
    @property
    def observations(self) -> Mapping[str, RecordedObservation]: ...
    @property
    def risk_level(self) -> RiskLevel: ...
    @property
    def mosca_urgency(self) -> str: ...
    @property
    def business_criticality(self) -> str: ...
    @property
    def quantum_status(self) -> str: ...
    @property
    def algorithm_name(self) -> str | None: ...
    @property
    def environment(self) -> str | None: ...
    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self: ...


Row = TypeVar("Row", bound=RemediationRow)


REMEDIATION_RULESET = "1.0.0"
LONG_LIVED_YEARS = 5.0
_RISK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_SENSITIVITY = {"restricted": 3, "confidential": 2, "internal": 1, "public": 0}


def _value(row: RemediationRow, name: str) -> str | float | bool | None:
    observation = row.observations.get(name)
    return (
        observation.value
        if observation and observation.state == ObservationState.OBSERVED
        else None
    )


def remediation_key(row: RemediationRow) -> tuple[int, int, int, int, int, float, int]:
    """Descending key. Counts and IDs cannot override a protection-context difference."""
    sensitivity = _SENSITIVITY.get(str(_value(row, "data_sensitivity")), -1)
    lifetime = _value(row, "data_lifetime")
    years = (
        float(lifetime)
        if isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool)
        else -1.0
    )
    exposed = _value(row, "exposure") is True
    sensitive = sensitivity >= 2
    long_lived = years >= LONG_LIVED_YEARS
    protection = (
        3
        if sensitive and long_lived and exposed
        else 2
        if sensitive and long_lived
        else 1
        if sensitive or row.business_criticality in {"high", "critical"}
        else 0
    )
    return (
        protection,
        _RISK.get(row.risk_level.value, -1),
        _RISK.get(row.mosca_urgency, -1),
        sensitivity,
        int(exposed),
        years,
        _RISK.get(row.business_criticality, -1),
    )


def remediation_reason(row: RemediationRow) -> str:
    """Describe recorded facts without inventing reachability or context."""
    subject = (
        "Public-key crypto"
        if row.quantum_status == "vulnerable"
        else row.algorithm_name or "Cryptographic finding"
    )
    sensitivity = _value(row, "data_sensitivity")
    lifetime = _value(row, "data_lifetime")
    exposure = _value(row, "exposure")
    parts = [subject]
    if sensitivity in {"restricted", "confidential"}:
        parts.append("protecting sensitive data")
    elif sensitivity is not None:
        parts.append(f"with {sensitivity} data classification")
    if isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool):
        parts.append(f"requiring {lifetime:g} years of confidentiality")
    if exposure is True:
        parts.append("on an internet-facing system")
    elif exposure is False:
        parts.append("on a system recorded as not internet-facing")
    if row.environment:
        parts.append(f"in {row.environment}")
    missing = [
        name
        for name, value in (
            ("sensitivity", sensitivity),
            ("lifetime", lifetime),
            ("exposure", exposure),
        )
        if value is None
    ]
    if missing:
        parts.append(f"— unknown {', '.join(missing)}")
    return " ".join(parts) + "."


def rank_remediation(rows: Sequence[Row]) -> list[Row]:
    ordered = sorted(rows, key=lambda row: row.finding_id)
    ordered.sort(key=remediation_key, reverse=True)
    return [
        row.model_copy(
            update={
                "remediation_rank": index + 1,
                "remediation_reason": remediation_reason(row),
                "remediation_ruleset_version": REMEDIATION_RULESET,
            }
        )
        for index, row in enumerate(ordered)
    ]
