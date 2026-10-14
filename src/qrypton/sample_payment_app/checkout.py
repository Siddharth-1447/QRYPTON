"""Synthetic payment checkout code used only for the QRYPTON sample workspace."""

from Crypto.PublicKey import RSA


def negotiate_checkout_key():
    return RSA.generate(2048)
