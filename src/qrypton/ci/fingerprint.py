"""Stable, secret-free fingerprinting for cryptographic findings."""

from __future__ import annotations

import hashlib
from typing import Any

from qrypton.contracts.ids import canonical_json_bytes


def _observed_value(value: Any) -> Any:
    """Return an observation value only when it was actually observed."""
    return value.value if value.state.value == "observed" else None


def finding_fingerprint(finding: Any) -> str:
    """Stable identity excluding tenant/run IDs, paths, excerpts, and secrets."""
    algorithm = _observed_value(finding.algorithm)
    protocol = _observed_value(finding.protocol)
    library = _observed_value(finding.library)
    payload = {
        "category": finding.category,
        "algorithm": None if algorithm is None else {
            "name": algorithm.canonical_name,
            "family": algorithm.family.value,
            "key_size": _observed_value(algorithm.key_size_bits),
            "parameters": dict(sorted(algorithm.parameters.items())),
        },
        "protocol": None if protocol is None else {
            "name": _observed_value(protocol.name),
            "version": _observed_value(protocol.version),
            "suite": _observed_value(protocol.cipher_suite),
        },
        "library": None if library is None else {
            "ecosystem": _observed_value(library.ecosystem),
            "name": _observed_value(library.name),
            "version": _observed_value(library.version),
        },
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
