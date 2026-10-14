from __future__ import annotations

import pytest

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmIdentificationStatus,
    AlgorithmStatus,
    ObservationState,
    RiskLevel,
)
from qrypton.contracts.models import Observation
from qrypton.risk.taxonomy import classify_finding
from tests.risk.conftest import finding
from tests.risk.conftest import unknown as unknown_observation


@pytest.mark.parametrize(
    ("name", "family", "status", "crypto", "quantum", "applicable"),
    [
        (
            "AES-256",
            AlgorithmFamily.SYMMETRIC_CIPHER,
            AlgorithmStatus.APPROVED,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            "no",
        ),
        (
            "RSA-2048",
            AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
            AlgorithmStatus.LEGACY,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            "yes",
        ),
        (
            "MD5",
            AlgorithmFamily.HASH,
            AlgorithmStatus.DISALLOWED,
            RiskLevel.CRITICAL,
            RiskLevel.MEDIUM,
            "no",
        ),
        (
            "ML-KEM-768",
            AlgorithmFamily.KEY_AGREEMENT,
            AlgorithmStatus.APPROVED,
            RiskLevel.LOW,
            RiskLevel.LOW,
            "no",
        ),
        (
            "unknown",
            AlgorithmFamily.UNKNOWN,
            AlgorithmStatus.UNKNOWN,
            RiskLevel.UNKNOWN,
            RiskLevel.UNKNOWN,
            "unknown",
        ),
    ],
)
def test_v1_taxonomy_is_explicit_and_deterministic(
    name: str,
    family: AlgorithmFamily,
    status: AlgorithmStatus,
    crypto: RiskLevel,
    quantum: RiskLevel,
    applicable: str,
) -> None:
    item = finding(name, family)
    observed_algorithm = item.algorithm.value.model_copy(update={"lifecycle_status": status})
    item = item.model_copy(
        update={
            "algorithm": Observation(
                state=ObservationState.OBSERVED,
                value=observed_algorithm,
                basis_evidence_ids=item.evidence_ids,
            )
        }
    )

    result = classify_finding(item)

    assert result.taxonomy_version == "1.0.0"
    assert result.crypto_risk is crypto
    assert result.quantum_risk is quantum
    assert result.mosca_applicable == applicable
    assert result == classify_finding(item)


def test_missing_parameters_do_not_turn_unknown_rsa_into_weak_crypto() -> None:
    item = finding("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    result = classify_finding(item)
    assert result.crypto_risk is RiskLevel.UNKNOWN
    assert result.quantum_risk is RiskLevel.HIGH
    assert result.mosca_applicable == "yes"


def test_observed_ecb_mode_is_classified_as_high_crypto_risk() -> None:
    item = finding("AES-256", AlgorithmFamily.SYMMETRIC_CIPHER)
    algorithm = item.algorithm.value.model_copy(update={"parameters": {"mode": "ECB"}})
    item = item.model_copy(
        update={
            "algorithm": item.algorithm.model_copy(update={"value": algorithm}),
        }
    )
    assert classify_finding(item).crypto_risk is RiskLevel.HIGH


def test_unobserved_algorithm_stays_unknown() -> None:
    item = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION).model_copy(
        update={"algorithm": unknown_observation()}
    )
    result = classify_finding(item)
    assert result.crypto_risk is RiskLevel.UNKNOWN
    assert result.quantum_risk is RiskLevel.UNKNOWN
    assert result.mosca_applicable == "unknown"


def test_identified_partially_identified_and_unknown_algorithm_states() -> None:
    identified = finding("RSA-3072", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    identified_algorithm = identified.algorithm.value.model_copy(
        update={"lifecycle_status": AlgorithmStatus.APPROVED}
    )
    identified = identified.model_copy(
        update={
            "algorithm": identified.algorithm.model_copy(update={"value": identified_algorithm})
        }
    )
    assert identified.algorithm_identification_status is AlgorithmIdentificationStatus.IDENTIFIED
    identified_risk = classify_finding(identified)
    assert identified_risk.crypto_risk is RiskLevel.LOW
    assert identified_risk.quantum_risk is RiskLevel.HIGH

    partial = finding("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    partial_algorithm = partial.algorithm.value.model_copy(
        update={"lifecycle_status": AlgorithmStatus.UNKNOWN}
    )
    partial = partial.model_copy(
        update={
            "algorithm": partial.algorithm.model_copy(update={"value": partial_algorithm}),
            "algorithm_identification_status": AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED,
            "algorithm_identification_confidence": 0.4,
        }
    )
    partial_risk = classify_finding(partial)
    assert partial_risk.crypto_risk is RiskLevel.UNKNOWN
    assert partial_risk.quantum_risk is RiskLevel.HIGH

    unknown = partial.model_copy(
        update={
            "algorithm": unknown_observation(),
            "algorithm_identification_status": AlgorithmIdentificationStatus.UNKNOWN,
            "algorithm_identification_confidence": 0.0,
        }
    )
    unknown_risk = classify_finding(unknown)
    assert unknown_risk.crypto_risk is RiskLevel.UNKNOWN
    assert unknown_risk.quantum_risk is RiskLevel.UNKNOWN
    assert unknown_risk.mosca_applicable == "unknown"


def test_unknown_protocol_finding_does_not_inherit_public_key_quantum_risk() -> None:
    protocol = finding("TLS-unknown", AlgorithmFamily.PROTOCOL).model_copy(
        update={"category": "protocol"}
    )
    result = classify_finding(protocol)
    assert result.crypto_risk is RiskLevel.UNKNOWN
    assert result.quantum_risk is RiskLevel.UNKNOWN
    assert result.mosca_applicable == "unknown"


def test_unsupported_taxonomy_version_is_rejected() -> None:
    item = finding("AES-256", AlgorithmFamily.SYMMETRIC_CIPHER)
    with pytest.raises(ValueError, match="unsupported risk taxonomy"):
        classify_finding(item, "2.0.0")  # type: ignore[arg-type]
