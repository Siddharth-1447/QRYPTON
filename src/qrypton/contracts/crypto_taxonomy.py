"""Versioned, conservative taxonomy for per-finding cryptographic risk.

Taxonomy 1.0.0 separates classical cryptographic condition from quantum
applicability. It only classifies named algorithms, lifecycle states, and
parameters covered by the explicit rules below. Unmatched or under-specified
algorithms remain UNKNOWN; absence of a match is not evidence of weakness.
"""

from __future__ import annotations

import re
from typing import Literal

from qrypton.contracts.algorithm_names import canonical_algorithm_name
from qrypton.contracts.enums import AlgorithmFamily, AlgorithmStatus, ObservationState, RiskLevel
from qrypton.contracts.models import CryptoFinding, DomainModel

RiskTaxonomyVersion = Literal["1.0.0"]

_PQC_MARKERS = ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS", "FALCON")
_BROKEN_MARKERS = ("MD2", "MD4", "MD5", "DES", "RC2", "RC4", "SHA0", "3DES")
_PUBLIC_KEY_FAMILIES = {
    AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
    AlgorithmFamily.KEY_AGREEMENT,
    AlgorithmFamily.SIGNATURE,
}
_SYMMETRIC_FAMILIES = {
    AlgorithmFamily.SYMMETRIC_CIPHER,
    AlgorithmFamily.HASH,
    AlgorithmFamily.MAC,
    AlgorithmFamily.KDF,
}
_SCORE_BY_RISK = {
    RiskLevel.UNKNOWN: None,
    RiskLevel.INFORMATIONAL: 0.0,
    RiskLevel.LOW: 10.0,
    RiskLevel.MEDIUM: 40.0,
    RiskLevel.HIGH: 75.0,
    RiskLevel.CRITICAL: 95.0,
}
_QUANTUM_SCORE_BY_RISK = {
    RiskLevel.UNKNOWN: None,
    RiskLevel.INFORMATIONAL: 0.0,
    RiskLevel.LOW: 0.0,
    RiskLevel.MEDIUM: 20.0,
    RiskLevel.HIGH: 100.0,
    RiskLevel.CRITICAL: 100.0,
}


class RiskDimensions(DomainModel):
    """Independent intrinsic dimensions emitted by the crypto taxonomy."""

    taxonomy_version: RiskTaxonomyVersion
    crypto_risk: RiskLevel
    quantum_risk: RiskLevel
    mosca_applicable: Literal["yes", "no", "unknown"]
    crypto_score: float | None
    quantum_score: float | None
    rationale: tuple[str, ...]


def _key_size(finding: CryptoFinding, algorithm_name: str) -> int | None:
    observation = finding.algorithm.value.key_size_bits  # type: ignore[union-attr]
    if observation.state is ObservationState.OBSERVED and observation.value is not None:
        return observation.value
    match = re.search(r"(?:RSA|AES|ECDSA|ECDH)[- _]?(\d{3,5})", algorithm_name)
    return int(match.group(1)) if match else None


def _is_pqc(name: str, family: AlgorithmFamily, status: AlgorithmStatus) -> bool:
    return (
        family.value == "pqc"
        or status.value == "pqc_ready"
        or any(marker in name for marker in _PQC_MARKERS)
    )


def is_post_quantum_finding(finding: CryptoFinding) -> bool:
    """Identify named PQC usage independently of its scored risk tier."""
    if finding.algorithm.state is not ObservationState.OBSERVED:
        return False
    algorithm = finding.algorithm.value
    if algorithm is None:
        return False
    return _is_pqc(
        canonical_algorithm_name(algorithm.canonical_name).upper(),
        algorithm.family,
        algorithm.lifecycle_status,
    )


def _is_classical_public_key(name: str, family: AlgorithmFamily) -> bool:
    return family in _PUBLIC_KEY_FAMILIES or any(
        marker in name
        for marker in ("RSA", "ECDSA", "ECDH", "ECC", "DSA", "DH", "ED25519", "X25519")
    )


def _crypto_risk(
    finding: CryptoFinding, name: str, family: AlgorithmFamily, status: AlgorithmStatus
) -> tuple[RiskLevel, str]:
    if any(marker in name for marker in _BROKEN_MARKERS):
        return RiskLevel.CRITICAL, "Algorithm name matches the explicit broken-primitive list."

    algorithm = finding.algorithm.value
    assert algorithm is not None
    key_size = _key_size(finding, name)
    mode = str(algorithm.parameters.get("mode", "")).strip().upper()
    if mode == "ECB" or "ECB" in name:
        return RiskLevel.HIGH, "Observed ECB mode is deprecated for block-cipher confidentiality."
    if status in {AlgorithmStatus.DEPRECATED, AlgorithmStatus.DISALLOWED}:
        return RiskLevel.HIGH, f"Lifecycle status is {status.value}."

    if _is_pqc(name, family, status):
        return RiskLevel.LOW, "Named post-quantum algorithm is not a weak classical primitive."

    if "SHA-1" in name or "SHA1" in name or name in {"SHA-224", "SHA224"}:
        return RiskLevel.HIGH if "SHA1" in name or "SHA-1" in name else RiskLevel.MEDIUM, (
            "SHA-1 is deprecated."
            if "SHA1" in name or "SHA-1" in name
            else "SHA-224 has less security margin than the current SHA-2 choices."
        )
    if name.startswith("RSA"):
        if key_size is None:
            return RiskLevel.UNKNOWN, "RSA key size is missing; strength cannot be classified."
        if key_size < 1024:
            return RiskLevel.CRITICAL, f"RSA key size {key_size} is below 1024 bits."
        if key_size < 2048:
            return RiskLevel.HIGH, f"RSA key size {key_size} is below 2048 bits."
        if key_size < 3072:
            return (
                RiskLevel.MEDIUM,
                f"RSA key size {key_size} is below the taxonomy's 3072-bit low-risk band.",
            )
        return RiskLevel.LOW, f"RSA key size {key_size} meets the taxonomy's 3072-bit band."
    if name.startswith("AES"):
        if key_size is None:
            return RiskLevel.UNKNOWN, "AES key size is missing; strength cannot be classified."
        if key_size < 128:
            return RiskLevel.CRITICAL, f"AES key size {key_size} is below 128 bits."
        if key_size == 128:
            return RiskLevel.MEDIUM, "AES-128 is classified in the legacy band."
        if key_size in {192, 256}:
            return RiskLevel.LOW, f"AES key size {key_size} meets the current-strength band."
        return RiskLevel.UNKNOWN, f"AES key size {key_size} is outside the named taxonomy bands."
    if name.startswith(("ECDSA", "ECDH", "ECC")):
        if key_size is None:
            curve_match = re.search(r"P[- ]?(256|384|521)", name)
            key_size = int(curve_match.group(1)) if curve_match else None
        if key_size is None:
            return (
                RiskLevel.UNKNOWN,
                "Elliptic-curve size is missing; strength cannot be classified.",
            )
        if key_size < 256:
            return RiskLevel.HIGH, f"Elliptic-curve size {key_size} is below P-256."
        if key_size == 256:
            return RiskLevel.MEDIUM, "P-256 is classified in the legacy band."
        if key_size in {384, 521}:
            return RiskLevel.LOW, f"Elliptic-curve size {key_size} meets the current-strength band."
        return (
            RiskLevel.UNKNOWN,
            f"Elliptic-curve size {key_size} is outside the named taxonomy bands.",
        )
    if name in {
        "SHA-256",
        "SHA256",
        "SHA-384",
        "SHA384",
        "SHA-512",
        "SHA512",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
    }:
        return RiskLevel.LOW, "Named SHA-2/SHA-3 digest meets the current-strength band."
    if name in {"ED25519", "X25519"}:
        return (
            RiskLevel.MEDIUM,
            "Named 25519 primitive is retained in the legacy compatibility band.",
        )
    if family is AlgorithmFamily.UNKNOWN or name.casefold() == "unknown":
        return RiskLevel.UNKNOWN, "Algorithm identity is unknown."
    return RiskLevel.UNKNOWN, "Algorithm is not covered by taxonomy 1.0.0."


def classify_finding(
    finding: CryptoFinding, version: RiskTaxonomyVersion = "1.0.0"
) -> RiskDimensions:
    """Classify one canonical finding; no business, confidence, or Mosca input is consumed."""
    if version != "1.0.0":
        raise ValueError(f"unsupported risk taxonomy version: {version}")
    if finding.algorithm.state is not ObservationState.OBSERVED or finding.algorithm.value is None:
        return RiskDimensions(
            taxonomy_version=version,
            crypto_risk=RiskLevel.UNKNOWN,
            quantum_risk=RiskLevel.UNKNOWN,
            mosca_applicable="unknown",
            crypto_score=None,
            quantum_score=None,
            rationale=(
                "Algorithm evidence is absent or unobserved.",
                "Quantum applicability is unknown without an observed algorithm classification.",
            ),
        )

    algorithm = finding.algorithm.value
    name = canonical_algorithm_name(algorithm.canonical_name).upper()
    family = algorithm.family
    status = algorithm.lifecycle_status
    crypto_risk, crypto_reason = _crypto_risk(finding, name, family, status)

    if _is_pqc(name, family, status):
        quantum_risk = RiskLevel.LOW
        mosca_applicable: Literal["yes", "no", "unknown"] = "no"
        quantum_reason = "Post-quantum algorithm; classical public-key Mosca model does not apply."
    elif _is_classical_public_key(name, family):
        quantum_risk = RiskLevel.HIGH
        mosca_applicable = "yes"
        quantum_reason = "Classical public-key algorithm is vulnerable under the Shor threat model."
    elif family in _SYMMETRIC_FAMILIES or any(
        marker in name for marker in ("AES", "SHA", "MD", "HMAC", "BLAKE")
    ):
        quantum_risk = RiskLevel.MEDIUM
        mosca_applicable = "no"
        quantum_reason = (
            "Symmetric/hash primitive is quantum-relevant; public-key Mosca model does not apply."
        )
    else:
        quantum_risk = RiskLevel.UNKNOWN
        mosca_applicable = "unknown"
        quantum_reason = "Quantum applicability is not established by the observed classification."

    return RiskDimensions(
        taxonomy_version=version,
        crypto_risk=crypto_risk,
        quantum_risk=quantum_risk,
        mosca_applicable=mosca_applicable,
        crypto_score=_SCORE_BY_RISK[crypto_risk],
        quantum_score=_QUANTUM_SCORE_BY_RISK[quantum_risk],
        rationale=(crypto_reason, quantum_reason),
    )
