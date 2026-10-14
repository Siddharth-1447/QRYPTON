"""Synthetic production-bound settlement signing and key agreement."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def settlement_private_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign_settlement(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def agree_settlement_key(private_key, peer_public_key) -> bytes:
    return private_key.exchange(ec.ECDH(), peer_public_key)
