from __future__ import annotations

from datetime import UTC, datetime

from qrypton.contracts.enums import AlgorithmFamily, AlgorithmStatus, ObservationState
from qrypton.contracts.models import Algorithm, CryptoFinding, Observation, Provenance


def unknown() -> Observation[object]:
    return Observation(state=ObservationState.UNKNOWN)


def provenance() -> Provenance:
    return Provenance(
        scanner_name="test",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{'a' * 64}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def finding(name: str, family: AlgorithmFamily) -> CryptoFinding:
    evidence_id = f"evidence_{'a' * 52}"
    algorithm = Algorithm(
        canonical_name=name,
        family=family,
        lifecycle_status=AlgorithmStatus.LEGACY,
        key_size_bits=unknown(),
        security_strength_bits=unknown(),
    )
    return CryptoFinding(
        id=f"finding_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        asset_id=f"asset_{'a' * 52}",
        scan_target_id=f"target_{'a' * 52}",
        category="algorithm_use",
        algorithm=Observation(
            state=ObservationState.OBSERVED, value=algorithm, basis_evidence_ids=(evidence_id,)
        ),
        key_material=unknown(),
        certificate=unknown(),
        protocol=unknown(),
        library=unknown(),
        evidence_ids=(evidence_id,),
        confidence=0.9,
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=provenance(),
    )
