"""Synthetic cryptographic usage awaiting business ownership classification."""

import hashlib


def callback_digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()
