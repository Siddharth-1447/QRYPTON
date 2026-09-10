"""Enterprise Cryptographic Service Demo Source Code.

Contains cryptographic implementations across multiple algorithms and modes
for QRYPTON multi-surface discovery demonstration.
"""

from __future__ import annotations

import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


def generate_legacy_rsa_key() -> RSA.RsaKey:
    """Generate 2048-bit RSA key pair (Vulnerable to CRQC breakdown)."""
    return RSA.generate(2048)


def encrypt_payload_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Insecure AES-ECB mode encryption (Lacks semantic security)."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def compute_legacy_hash(data: bytes) -> str:
    """Weak MD5 digest generation."""
    return hashlib.md5(data).hexdigest()
