"""Deterministic demo fixture: import-bound Python crypto usage."""

import hashlib
import ssl

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def establish_session() -> tuple[object, object]:
    digest = hashlib.sha1(b"legacy-token")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    peer_key = ec.generate_private_key(ec.SECP256R1())
    cipher = Cipher(algorithms.AES(b"0123456789abcdef"), modes.GCM(b"0" * 12))
    context = ssl.create_default_context()
    return digest, private_key, peer_key, cipher, context

