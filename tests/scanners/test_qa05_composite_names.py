"""Explicit expectations for signature/hash constituents and encoded RSA sizes."""

from pathlib import Path
from typing import Any

import pytest

from qrypton.contracts.enums import AlgorithmFamily, ObservationState, RiskLevel
from qrypton.ports.scanners import RawObservation
from qrypton.risk.taxonomy import classify_finding
from qrypton.scanners.source.normalization import SourceNormalizer
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.python_lexical import analyze_python_lexical
from qrypton.scanners.source.rules import algorithm_for_name
from tests.scanners.test_python_ast import _limits, _source
from tests.scanners.test_source_normalization import context as context
from tests.scanners.test_source_normalization import raw_observation


@pytest.mark.parametrize("detector", ["ast", "lexical"])
@pytest.mark.parametrize(
    ("token", "names", "bits"),
    [
        ("RSAWithSHA256", {"rsa", "sha-256"}, None),
        ("SHA256withRSA", {"rsa", "sha-256"}, None),
        ("SHA256WithRSAEncryption", {"rsa", "sha-256"}, None),
        ("RSA_4096", {"rsa"}, 4096),
        ("rsa2048", {"rsa"}, 2048),
    ],
)
def test_detectors_preserve_composite_token(
    detector: str, token: str, names: set[str], bits: int | None, context: dict[str, Any]
) -> None:
    analyze = analyze_python_ast if detector == "ast" else analyze_python_lexical
    raw = tuple(analyze(
        _source(f"import signatures\nsignatures.{token}()"),
        policy=SourceScanPolicy(allowed_root=Path.cwd()), limits=_limits(),
    ))
    normalizer = SourceNormalizer()
    findings = normalizer.derive_findings(
        tuple(normalizer.normalize(item, **context) for item in raw), **context
    )
    algorithms = []
    for finding in findings:
        assert finding.algorithm.value is not None
        algorithms.append(finding.algorithm.value)
    assert {algorithm.canonical_name for algorithm in algorithms} == names
    assert all(algorithm.key_size_bits.value == bits for algorithm in algorithms)


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("RSAWithSHA256", [("rsa", "signature", None), ("sha-256", "hash", None)]),
        ("SHA256withRSA", [("rsa", "signature", None), ("sha-256", "hash", None)]),
        ("SHA256WithRSAEncryption", [("rsa", "signature", None), ("sha-256", "hash", None)]),
        ("ecdsa-with-SHA384", [("ecdsa", "signature", None), ("sha-384", "hash", None)]),
        ("RSA-2048", [("rsa", "asymmetric_encryption", 2048)]),
        ("rsa2048", [("rsa", "asymmetric_encryption", 2048)]),
        ("RSA_4096", [("rsa", "asymmetric_encryption", 4096)]),
        ("SHA256", [("sha-256", "hash", None)]),
        ("MD5", [("md5", "hash", None)]),
    ],
)
def test_composite_constituents_and_sizes(
    token: str, expected: list[tuple[str, str, int | None]], context: dict[str, Any]
) -> None:
    normalizer = SourceNormalizer()
    evidence = normalizer.normalize(raw_observation(token), **context)
    findings = normalizer.derive_findings((evidence,), **context)
    actual = []
    for finding in findings:
        algorithm = finding.algorithm.value
        assert algorithm is not None
        actual.append(
            (algorithm.canonical_name, algorithm.family.value, algorithm.key_size_bits.value)
        )
        assert finding.evidence_ids == (evidence.id,)
    assert sorted(actual) == sorted(expected)
    assert len({finding.id for finding in findings}) == len(expected)
    primary = algorithm_for_name(token)
    assert primary is not None and primary.canonical_name == expected[0][0]


@pytest.mark.parametrize("token", ["RSAWithSHA256junk", "RSA_with_unknown", "rsa_sha256"])
def test_unparseable_composite_is_unknown(token: str, context: dict[str, Any]) -> None:
    normalizer = SourceNormalizer()
    evidence = normalizer.normalize(raw_observation(token), **context)
    findings = normalizer.derive_findings((evidence,), **context)
    assert len(findings) == 1
    assert findings[0].algorithm.state is ObservationState.UNKNOWN
    assert findings[0].algorithm_identification_confidence == 0


def test_rsa_signature_is_quantum_relevant_public_key(context: dict[str, Any]) -> None:
    normalizer = SourceNormalizer()
    evidence = normalizer.normalize(raw_observation("RSAWithSHA256"), **context)
    findings = normalizer.derive_findings((evidence,), **context)
    signature = next(
        f for f in findings if f.algorithm.value is not None
        and f.algorithm.value.canonical_name == "rsa"
    )
    assert signature.algorithm.value is not None
    assert signature.algorithm_family is AlgorithmFamily.SIGNATURE
    assert signature.crypto_role == "signature"
    assert signature.algorithm.value.parameters["hash_algorithm"] == "sha-256"
    dimensions = classify_finding(signature)
    assert dimensions.quantum_risk is RiskLevel.HIGH
    assert dimensions.mosca_applicable == "yes"


def test_signature_curve_stays_with_public_key_constituent(context: dict[str, Any]) -> None:
    normalizer = SourceNormalizer()
    raw: RawObservation = raw_observation("ecdsa-with-SHA384", curve="secp384r1")
    evidence = normalizer.normalize(raw, **context)
    findings = normalizer.derive_findings((evidence,), **context)
    algorithms = {}
    for finding in findings:
        assert finding.algorithm.value is not None
        algorithms[finding.algorithm.value.canonical_name] = finding.algorithm.value
    assert algorithms["ecdsa"].parameters["curve"] == "secp384r1"
    assert "curve" not in algorithms["sha-384"].parameters
    assert tuple(f.id for f in findings) == tuple(
        f.id for f in normalizer.derive_findings((evidence, evidence), **context)
    )
