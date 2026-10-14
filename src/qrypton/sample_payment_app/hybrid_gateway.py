"""Synthetic migration candidate using a standardized PQC KEM."""

from pqcrypto.kem import ml_kem_768


def encapsulate_session():
    return ml_kem_768.generate_keypair()
