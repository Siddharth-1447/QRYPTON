from __future__ import annotations

from datetime import UTC, datetime

from qrypton.contracts.enums import ObservationState
from qrypton.contracts.models import Observation, Provenance


def entity_id(namespace: str = "asset") -> str:
    return f"{namespace}_{'a' * 52}"


def tenant_id() -> str:
    return f"tenant_{'a' * 52}"


def digest() -> str:
    return f"sha256:{'a' * 64}"


def observed(value: object, evidence_id: str | None = None) -> Observation[object]:
    return Observation(
        state=ObservationState.OBSERVED,
        value=value,
        basis_evidence_ids=(evidence_id or entity_id("evidence"),),
    )


def unknown() -> Observation[object]:
    return Observation(state=ObservationState.UNKNOWN)


def provenance() -> Provenance:
    return Provenance(
        scanner_name="unit-test",
        scanner_version="1.0.0",
        scanner_config_digest=digest(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
