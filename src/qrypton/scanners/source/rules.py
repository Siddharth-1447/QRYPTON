"""Small, explicit source-level crypto rule catalog."""

from __future__ import annotations

from dataclasses import dataclass

from qrypton.contracts.algorithm_names import HASH_ALIASES, canonical_algorithm_name


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
    "sha3_224": AlgorithmRule("sha3-224", "hash", "approved"),
    "sha3_384": AlgorithmRule("sha3-384", "hash", "approved"),
    "sha3_512": AlgorithmRule("sha3-512", "hash", "approved"),
    "aes": AlgorithmRule("aes", "symmetric_cipher", "approved"),
    "chacha20": AlgorithmRule("chacha20", "symmetric_cipher", "approved"),
    "rsa": AlgorithmRule("rsa", "asymmetric_encryption", "legacy"),
    "ec": AlgorithmRule("ec", "key_agreement", "approved"),
    "ecdsa": AlgorithmRule("ecdsa", "signature", "approved"),
    "ecdh": AlgorithmRule("ecdh", "key_agreement", "approved"),
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
    "bcrypt": AlgorithmRule("bcrypt-cng", "symmetric_cipher", "approved"),
    "ncrypt": AlgorithmRule("ncrypt-cng", "asymmetric_encryption", "approved"),
    "crypt": AlgorithmRule("windows-capi", "asymmetric_encryption", "legacy"),
    "crypt32": AlgorithmRule("windows-capi", "asymmetric_encryption", "legacy"),
    "pfx": AlgorithmRule("pkcs12-pfx", "asymmetric_encryption", "legacy"),
    "cert": AlgorithmRule("x509-certificate", "asymmetric_encryption", "approved"),
}

MODE_NAMES = frozenset({"ecb", "cbc", "ctr", "gcm", "ccm", "xts", "ofb", "cfb"})
CRYPTO_LIBRARY_PREFIXES = frozenset(
    {
        "cryptography",
        "crypto",
        "hashlib",
        "hmac",
        "ssl",
        "nacl",
        "openssl",
        "mbedtls",
        "wolfssl",
        "bcrypt",
        "ncrypt",
        "crypt32",
        "certcli",
        "cryptui",
        "cryptsp",
    }
)

_ORDERED_TOKENS: tuple[tuple[str, AlgorithmRule], ...] = (
    ("sha512", ALGORITHM_RULES["sha512"]),
    ("sha384", ALGORITHM_RULES["sha384"]),
    ("sha256", ALGORITHM_RULES["sha256"]),
    ("sha224", ALGORITHM_RULES["sha224"]),
    ("sha1", ALGORITHM_RULES["sha1"]),
    ("sha_1", ALGORITHM_RULES["sha1"]),
    ("md5", ALGORITHM_RULES["md5"]),
    ("ecdsa", ALGORITHM_RULES["ecdsa"]),
    ("ecdh", ALGORITHM_RULES["ecdh"]),
    ("aes", ALGORITHM_RULES["aes"]),
    ("rsa", ALGORITHM_RULES["rsa"]),
    ("dsa", ALGORITHM_RULES["dsa"]),
    ("chacha20", ALGORITHM_RULES["chacha20"]),
    ("chacha", ALGORITHM_RULES["chacha20"]),
    ("ed25519", ALGORITHM_RULES["ed25519"]),
    ("x25519", ALGORITHM_RULES["x25519"]),
    ("hmac", ALGORITHM_RULES["hmac"]),
    ("hkdf", ALGORITHM_RULES["hkdf"]),
    ("pbkdf2", ALGORITHM_RULES["pbkdf2"]),
    ("scrypt", ALGORITHM_RULES["scrypt"]),
    ("argon2", ALGORITHM_RULES["argon2"]),
    ("bcrypt", ALGORITHM_RULES["bcrypt"]),
    ("ncrypt", ALGORITHM_RULES["ncrypt"]),
    ("crypt32", ALGORITHM_RULES["crypt32"]),
    ("crypt", ALGORITHM_RULES["crypt"]),
    ("pfx", ALGORITHM_RULES["pfx"]),
    ("cert", ALGORITHM_RULES["cert"]),
)

_CANONICAL_RULES = {rule.canonical_name: rule for rule in ALGORITHM_RULES.values()}
_RULE_ALIASES = {
    name.replace("-", "_"): rule
    for name, rule in (*ALGORITHM_RULES.items(), *_CANONICAL_RULES.items())
}
_RULE_ALIASES.update(
    {
        alias.replace("-", "_"): _CANONICAL_RULES[canonical]
        for alias, canonical in HASH_ALIASES.items()
    }
)
_ORDERED_ALIASES = tuple(sorted(_RULE_ALIASES.items(), key=lambda item: len(item[0]), reverse=True))
_HASH_TOKENS = tuple(
    sorted(
        ((alias, rule) for alias, rule in _RULE_ALIASES.items() if rule.family == "hash"),
        key=lambda item: len(item[0]),
        reverse=True,
    )
)


def algorithm_for_name(name: str) -> AlgorithmRule | None:
    canonical = canonical_algorithm_name(name)
    if canonical in _CANONICAL_RULES:
        return _CANONICAL_RULES[canonical]
    normalized = name.strip().casefold().replace("-", "_").replace(".", "_")
    for token, rule in _ORDERED_ALIASES:
        if normalized == token or normalized.startswith(f"{token}_"):
            return rule
    for token, rule in (*_HASH_TOKENS, *_ORDERED_TOKENS):
        if token in normalized:
            return rule
    return None
