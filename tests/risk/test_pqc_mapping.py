from __future__ import annotations

import pytest

from qrypton.contracts.enums import AlgorithmFamily
from qrypton.risk.pqc_mapping import PqcMapper
from tests.risk.conftest import finding


@pytest.mark.parametrize(
    ("legacy", "family", "replacement", "reference"),
    [
        ("ecdh", AlgorithmFamily.KEY_AGREEMENT, "ml-kem", "fips/203"),
        ("ecdsa", AlgorithmFamily.SIGNATURE, "ml-dsa", "fips/204"),
        ("sha-1", AlgorithmFamily.HASH, "sha3-256", None),
        ("triple-des", AlgorithmFamily.SYMMETRIC_CIPHER, "aes-256", None),
    ],
)
def test_maps_legacy_algorithms(
    legacy: str, family: AlgorithmFamily, replacement: str, reference: str | None
) -> None:
    mapping = PqcMapper().map_finding(finding(legacy, family))
    assert mapping is not None
    assert mapping.replacement_algorithm.canonical_name == replacement
    if reference is not None:
        assert any(reference in str(item) for item in mapping.standard_references)


def test_does_not_map_modern_unrelated_algorithm() -> None:
    assert PqcMapper().map_finding(finding("aes", AlgorithmFamily.SYMMETRIC_CIPHER)) is None
