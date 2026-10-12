"""Exact spelling aliases shared by discovery and risk classification."""

from __future__ import annotations

# Canonical spellings are stable persisted identities. Do not collapse SHA-3
# variants or infer a digest length from an incomplete name such as "sha3".
HASH_ALIASES: dict[str, str] = {}
for _bits in (1, 224, 256, 384, 512):
    for _alias in (f"sha{_bits}", f"sha-{_bits}", f"sha_{_bits}"):
        HASH_ALIASES[_alias] = f"sha-{_bits}"
for _bits in (224, 256, 384, 512):
    for _alias in (f"sha3{_bits}", f"sha3-{_bits}", f"sha3_{_bits}"):
        HASH_ALIASES[_alias] = f"sha3-{_bits}"


def canonical_algorithm_name(name: str) -> str:
    """Normalize known aliases; preserve the identity of unrecognized variants."""
    lowered = name.strip().casefold()
    return HASH_ALIASES.get(lowered, lowered.replace("_", "-"))
