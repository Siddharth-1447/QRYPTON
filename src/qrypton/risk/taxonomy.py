"""Compatibility imports for the shared, pure cryptographic classification contract."""

from qrypton.contracts.crypto_taxonomy import (
    RiskDimensions,
    RiskTaxonomyVersion,
    classify_finding,
    is_post_quantum_finding,
)

__all__ = ["RiskDimensions", "RiskTaxonomyVersion", "classify_finding", "is_post_quantum_finding"]
