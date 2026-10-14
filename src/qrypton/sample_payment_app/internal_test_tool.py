"""Synthetic internal test utility; not a production payment dependency."""

from Crypto.PublicKey import RSA


def make_test_key():
    return RSA.generate(2048)
