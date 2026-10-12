"""Alias, key-size and mode regressions through the actual AST/normalizer pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from qrypton.application.schemas import PolicyOutcome, RunResult
from qrypton.contracts.algorithm_names import HASH_ALIASES, canonical_algorithm_name
from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmIdentificationStatus,
    AssetKind,
    EvidenceKind,
    ObservationState,
    RiskLevel,
    RunStatus,
    ScanTargetKind,
)
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import Asset, EvidenceLocation, Observation, Provenance, ScanTarget
from qrypton.exporters.cyclonedx_1_6 import CycloneDx16CbomExporter
from qrypton.ports.scanners import RawObservation
from qrypton.risk.taxonomy import classify_finding
from qrypton.scanners.source.normalization import SourceNormalizer
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.rules import ALGORITHM_RULES, algorithm_for_name
from qrypton.storage.sqlite import SqliteRunStore
from tests.scanners.test_python_ast import _limits, _source


@pytest.fixture
def context():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    provenance = Provenance(
        scanner_name="qrypton-source",
        scanner_version="0.2.0",
        scanner_config_digest="sha256:" + "a" * 64,
        observed_at=now,
    )
    asset = Asset(
        id="asset_" + "a" * 52,
        tenant_id="tenant_" + "a" * 52,
        kind=AssetKind.REPOSITORY,
        external_reference="test",
        name="test",
        created_at=now,
        updated_at=now,
        provenance=provenance,
    )
    target = ScanTarget(
        id="target_" + "a" * 52,
        tenant_id=asset.tenant_id,
        asset_id=asset.id,
        kind=ScanTargetKind.SOURCE_TREE,
        locator="test",
        content_digest=Observation(state=ObservationState.UNKNOWN),
        declared_size_bytes=Observation(state=ObservationState.UNKNOWN),
        requested_at=now,
        provenance=provenance,
    )
    return {
        "asset": asset,
        "target": target,
        "provenance": provenance,
        "id_deriver": HmacIdDeriver(b"a" * 32),
    }


def normalize(raw, context):
    normalizer = SourceNormalizer()
    evidence = normalizer.normalize(raw, **context)
    return evidence, normalizer.derive_findings((evidence,), **context)[0]


def ast_findings(text, context):
    observations = analyze_python_ast(
        _source(text), policy=SourceScanPolicy(allowed_root=Path.cwd()), limits=_limits()
    )
    return [
        (raw, *normalize(raw, context))
        for raw in observations
        if raw.attributes["subject_kind"] != "library"
    ]


def raw_observation(subject: str, **attributes):
    return RawObservation(
        kind=EvidenceKind.SOURCE_AST,
        location=EvidenceLocation(relative_path="crypto.py", line_start=1),
        attributes={"subject_kind": "algorithm", "subject_value": subject, **attributes},
        confidence=0.95,
    )


@pytest.mark.parametrize(("alias", "canonical"), HASH_ALIASES.items())
def test_hash_aliases_roundtrip_and_share_taxonomy_identity(alias, canonical, context):
    rule = algorithm_for_name(alias.upper())
    assert rule is not None and rule.canonical_name == canonical
    assert algorithm_for_name(canonical) == rule
    assert canonical_algorithm_name(alias) == canonical
    _, finding = normalize(raw_observation(alias), context)
    assert finding.algorithm.value.canonical_name == canonical
    assert finding.algorithm_identification_status is AlgorithmIdentificationStatus.IDENTIFIED
    assert finding.algorithm_identification_confidence == 0.95
    # Taxonomy must classify direct historical aliases just like new normalized rows.
    legacy = finding.model_copy(
        update={
            "algorithm": finding.algorithm.model_copy(
                update={
                    "value": finding.algorithm.value.model_copy(update={"canonical_name": alias}),
                }
            )
        }
    )
    assert classify_finding(legacy) == classify_finding(finding)


@pytest.mark.parametrize("rule", list(ALGORITHM_RULES.values()))
def test_every_catalog_canonical_name_roundtrips(rule):
    assert algorithm_for_name(rule.canonical_name) == rule


def test_incomplete_sha3_name_does_not_invent_digest_size():
    assert algorithm_for_name("sha3") is None


def test_hashlib_sha256_stays_identified_at_high_confidence(context):
    _, evidence, finding = ast_findings("import hashlib\nhashlib.sha256(b'payload')\n", context)[0]
    assert finding.algorithm.value.canonical_name == "sha-256"
    assert finding.algorithm_family is AlgorithmFamily.HASH
    assert finding.algorithm_identification_confidence == evidence.confidence == 0.95
    assert finding.algorithm_identification_status is AlgorithmIdentificationStatus.IDENTIFIED
    assert classify_finding(finding).crypto_risk is RiskLevel.LOW


@pytest.mark.parametrize(
    "code",
    [
        "from Crypto.PublicKey import RSA\nRSA.generate(2048)",
        "from Crypto.PublicKey import RSA as rsa\nrsa.generate(bits=2048)",
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)",
    ],
)
def test_ast_rsa_key_sizes_reach_finding_and_risk(code, context):
    raw, evidence, finding = ast_findings(code, context)[0]
    assert raw.attributes["key_size_bits"] == 2048
    size = finding.algorithm.value.key_size_bits
    assert size.state is ObservationState.OBSERVED and size.value == 2048
    assert size.basis_evidence_ids == (evidence.id,)
    assert classify_finding(finding).crypto_risk is RiskLevel.MEDIUM


@pytest.mark.parametrize("size", [1, 2048, 1_000_000])
def test_explicit_key_size_attributes_are_preserved(size, context):
    _, finding = normalize(raw_observation("rsa", key_size_bits=size), context)
    assert finding.algorithm.value.key_size_bits.value == size


@pytest.mark.parametrize("size", [None, True, False, 0, -1, 1_000_001, "2048", 2048.5])
def test_invalid_sizes_stay_unknown_without_crashing(size, context):
    _, finding = normalize(raw_observation("rsa", key_size_bits=size), context)
    assert finding.algorithm.value.key_size_bits.state is ObservationState.UNKNOWN


@pytest.mark.parametrize(
    "code",
    [
        "from Crypto.PublicKey import RSA\nRSA.generate(size)",
        "from Crypto.PublicKey import RSA\nRSA.generate(True)",
        "from Crypto.PublicKey import RSA\nRSA.encrypt(2048)",
        "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\nHKDF(length=32)",
    ],
)
def test_ast_does_not_guess_sizes_or_treat_byte_lengths_as_bits(code, context):
    for raw, _, finding in ast_findings(code, context):
        assert "key_size_bits" not in raw.attributes
        assert finding.algorithm.value.key_size_bits.state is ObservationState.UNKNOWN


@pytest.mark.parametrize("mode", ["CBC", "GCM", "ECB"])
def test_composite_mode_and_explicit_binding_are_preserved(mode, context):
    for raw in (
        raw_observation(f"AES-{mode}", subject_kind="mode", key_size_bits=256),
        raw_observation(mode, subject_kind="mode", algorithm_name="aes", key_size_bits=256),
        raw_observation("aes", mode=mode.lower(), key_size_bits=256),
    ):
        _, finding = normalize(raw, context)
        algorithm = finding.algorithm.value
        assert algorithm.canonical_name == "aes"
        assert algorithm.parameters == {"mode": mode}
        assert algorithm.key_size_bits.value == 256
        assert finding.algorithm_identification_status is AlgorithmIdentificationStatus.IDENTIFIED
        assert classify_finding(finding).crypto_risk is (
            RiskLevel.HIGH if mode == "ECB" else RiskLevel.LOW
        )
        assert (
            CycloneDx16CbomExporter._algorithm_properties(algorithm)["algorithmProperties"]["mode"]
            == mode.lower()
        )


@pytest.mark.parametrize("mode", ["CBC", "GCM", "ECB"])
def test_unbound_mode_retains_parameter_without_inventing_aes(mode, context):
    _, finding = normalize(raw_observation(mode, subject_kind="mode"), context)
    assert finding.algorithm.value.canonical_name == "unknown"
    assert finding.algorithm.value.parameters == {"mode": mode}
    assert (
        finding.algorithm_identification_status
        is AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED
    )
    assert finding.algorithm_identification_confidence == 0


@pytest.mark.parametrize("mode", ["CBC", "GCM", "ECB"])
def test_ast_cipher_binds_mode_only_within_same_cipher_call(mode, context):
    code = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        f"Cipher(algorithms.AES(key), modes.{mode}(iv))\n"
        f"modes.{mode}(other_iv)\n"
    )
    findings = ast_findings(code, context)
    mode_findings = [
        (raw, finding) for raw, _, finding in findings if raw.attributes["subject_kind"] == "mode"
    ]
    assert len(mode_findings) == 2
    assert mode_findings[0][1].algorithm.value.canonical_name == "aes"
    assert mode_findings[0][1].algorithm.value.parameters == {"mode": mode}
    assert mode_findings[1][1].algorithm.value.canonical_name == "unknown"


@pytest.mark.parametrize("mode", ["CBC", "GCM", "ECB"])
def test_pycryptodome_mode_attribute_reaches_aes_finding(mode, context):
    code = f"from Crypto.Cipher import AES\nAES.new(key, AES.MODE_{mode})"
    _, _, finding = ast_findings(code, context)[0]
    assert finding.algorithm.value.canonical_name == "aes"
    assert finding.algorithm.value.parameters == {"mode": mode}


def test_parameters_and_evidence_survive_sqlite_roundtrip(tmp_path, context):
    evidence, finding = normalize(raw_observation("aes", key_size_bits=256, mode="GCM"), context)
    now = context["provenance"].observed_at
    result = RunResult(
        run_id="run_" + "a" * 52,
        tenant_id=finding.tenant_id,
        status=RunStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        evidence=(evidence,),
        findings=(finding,),
        policy_outcome=PolicyOutcome(passed=True),
    )
    store = SqliteRunStore(tmp_path / "normalized.sqlite3")
    try:
        store.finalize_run(result)
        loaded = store.get_run(tenant_id=result.tenant_id, run_id=result.run_id)
        assert loaded.findings[0].algorithm == finding.algorithm
        assert loaded.evidence[0].attributes["key_size_bits"] == 256
        assert loaded.evidence[0].attributes["mode"] == "GCM"
    finally:
        store.close()

