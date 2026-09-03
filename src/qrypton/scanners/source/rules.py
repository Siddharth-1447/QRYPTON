"""Small, explicit source-level crypto rule catalog."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AlgorithmRule:
    canonical_name: str
    family: str
    lifecycle: str


ALGORITHM_RULES: dict[str, AlgorithmRule] = {
    "md5": AlgorithmRule("md5", "hash", "disallowed"),
    "sha1": AlgorithmRule("sha-1", "hash", "deprecated"),
    "sha224": AlgorithmRule("sha-224", "hash", "approved"),
    "sha256": AlgorithmRule("sha-256", "hash", "approved"),
    "sha384": AlgorithmRule("sha-384", "hash", "approved"),
    "sha512": AlgorithmRule("sha-512", "hash", "approved"),
    "sha3_256": AlgorithmRule("sha3-256", "hash", "approved"),
    "aes": AlgorithmRule("aes", "symmetric_cipher", "approved"),
    "chacha20": AlgorithmRule("chacha20", "symmetric_cipher", "approved"),
    "rsa": AlgorithmRule("rsa", "asymmetric_encryption", "legacy"),
    "ec": AlgorithmRule("ec", "key_agreement", "approved"),
    "dsa": AlgorithmRule("dsa", "signature", "deprecated"),
    "dh": AlgorithmRule("dh", "key_agreement", "legacy"),
    "x25519": AlgorithmRule("x25519", "key_agreement", "approved"),
    "x448": AlgorithmRule("x448", "key_agreement", "approved"),
    "ed25519": AlgorithmRule("ed25519", "signature", "approved"),
    "ed448": AlgorithmRule("ed448", "signature", "approved"),
    "hmac": AlgorithmRule("hmac", "mac", "approved"),
    "hkdf": AlgorithmRule("hkdf", "kdf", "approved"),
    "pbkdf2": AlgorithmRule("pbkdf2", "kdf", "approved"),
    "scrypt": AlgorithmRule("scrypt", "kdf", "approved"),
    "argon2": AlgorithmRule("argon2", "kdf", "approved"),
    "ml_kem": AlgorithmRule("ml-kem", "key_agreement", "approved"),
    "ml_dsa": AlgorithmRule("ml-dsa", "signature", "approved"),
    "slh_dsa": AlgorithmRule("slh-dsa", "signature", "approved"),
}

MODE_NAMES = frozenset({"ecb", "cbc", "ctr", "gcm", "ccm", "xts", "ofb", "cfb"})
CRYPTO_LIBRARY_PREFIXES = frozenset(
    {"cryptography", "crypto", "hashlib", "hmac", "ssl", "nacl", "openssl", "mbedtls", "wolfssl"}
)


def algorithm_for_name(name: str) -> AlgorithmRule | None:
    normalized = name.casefold().replace("-", "_")
    for token, rule in ALGORITHM_RULES.items():
        if normalized == token or normalized.startswith(f"{token}_"):
            return rule
    return None
