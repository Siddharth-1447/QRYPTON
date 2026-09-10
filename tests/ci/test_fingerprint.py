"""Tests for finding fingerprint stability and correctness."""

from __future__ import annotations

from qrypton.ci.fingerprint import finding_fingerprint
from qrypton.contracts.enums import AlgorithmFamily
from tests.ci.conftest import make_finding


def test_fingerprint_stable_across_runs() -> None:
    """Same finding content produces the same fingerprint regardless of IDs."""
    f1 = make_finding(finding_id=f"finding_{'a' * 52}")
    f2 = make_finding(finding_id=f"finding_{'z' * 52}")
    assert finding_fingerprint(f1) == finding_fingerprint(f2)


def test_fingerprint_excludes_tenant() -> None:
    """Same finding under different tenants produces the same fingerprint."""
    f1 = make_finding(tenant_id=f"tenant_{'a' * 52}")
    f2 = make_finding(tenant_id=f"tenant_{'z' * 52}")
    assert finding_fingerprint(f1) == finding_fingerprint(f2)


def test_fingerprint_changes_on_algorithm() -> None:
    """Different algorithm names produce different fingerprints."""
    f1 = make_finding(algorithm_name="SHA-1")
    f2 = make_finding(algorithm_name="SHA-256")
    assert finding_fingerprint(f1) != finding_fingerprint(f2)


def test_fingerprint_changes_on_key_size() -> None:
    """Different key sizes produce different fingerprints."""
    f1 = make_finding(algorithm_name="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, key_size=128)
    f2 = make_finding(algorithm_name="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, key_size=256)
    assert finding_fingerprint(f1) != finding_fingerprint(f2)


def test_fingerprint_changes_on_family() -> None:
    """Different algorithm families produce different fingerprints."""
    f1 = make_finding(algorithm_name="TestAlgo", family=AlgorithmFamily.HASH)
    f2 = make_finding(algorithm_name="TestAlgo", family=AlgorithmFamily.SYMMETRIC_CIPHER)
    assert finding_fingerprint(f1) != finding_fingerprint(f2)


def test_fingerprint_is_sha256_prefixed() -> None:
    """Fingerprints follow the sha256: prefix convention."""
    f = make_finding()
    fp = finding_fingerprint(f)
    assert fp.startswith("sha256:")
    assert len(fp) == len("sha256:") + 64
