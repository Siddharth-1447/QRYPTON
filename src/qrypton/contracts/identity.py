"""Canonical labels for algorithm and library identity states."""

from __future__ import annotations

from qrypton.contracts.enums import AlgorithmIdentificationStatus, ObservationState
from qrypton.contracts.models import CryptoFinding


def finding_identity_label(finding: CryptoFinding) -> str:
    """Render canonical identity without guessing an algorithm from weak evidence."""
    algorithm = (
        finding.algorithm.value if finding.algorithm.state is ObservationState.OBSERVED else None
    )
    if (
        algorithm is not None
        and finding.algorithm_identification_status is AlgorithmIdentificationStatus.IDENTIFIED
    ):
        return algorithm.canonical_name

    library = finding.library.value if finding.library.state is ObservationState.OBSERVED else None
    if (
        library is not None
        and library.name.state is ObservationState.OBSERVED
        and library.name.value
    ):
        return "Known cryptographic library, specific primitive not identified"

    if (
        finding.algorithm_identification_status
        is AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED
    ):
        if finding.algorithm_variant:
            return f"Partially identified algorithm: {finding.algorithm_variant}"
        return "Cryptographic identity partially identified"

    return "No cryptographic identity could be established"
