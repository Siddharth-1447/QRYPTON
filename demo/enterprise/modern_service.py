"""Control fixture: modern primitives must not become legacy findings."""

from cryptography.hazmat.primitives.ciphers import aead


def modern_path() -> object:
    kem = "ML-KEM-768"
    cipher = aead.AESGCM(b"0" * 32)
    return kem, cipher

