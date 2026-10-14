"""Phase 3 regression tests for canonical multi-surface correlation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from qrypton.application.correlation import DeterministicCorrelationEngine
from qrypton.application.schemas import PolicyOutcome, RunResult
from qrypton.contracts.enums import (
    AlgorithmFamily,
    EvidenceCollectionMode,
    EvidenceKind,
    EvidenceSurface,
    ObservationState,
    RunStatus,
)
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import Evidence, EvidenceLocation, Provenance
from qrypton.ports.scanners import RawObservation
from qrypton.scanners.source.normalization import SourceNormalizer
from qrypton.storage.sqlite import SqliteRunStore
from tests.risk.conftest import finding, provenance


def _evidence(
    evidence_id: str,
    *,
    line: int,
    kind: EvidenceKind = EvidenceKind.SOURCE_AST,
    subject_kind: str = "algorithm",
    subject_value: str = "rsa",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        tenant_id=f"tenant_{'a' * 52}",
        asset_id=f"asset_{'a' * 52}",
        scan_target_id=f"target_{'a' * 52}",
        kind=kind,
        surface=EvidenceSurface.SOURCE,
        collection_mode=EvidenceCollectionMode.STATIC_ARTIFACT,
        location=EvidenceLocation(relative_path="src/crypto.py", line_start=line, line_end=line),
        attributes={"subject_kind": subject_kind, "subject_value": subject_value},
        confidence=0.8,
        deduplication_fingerprint=f"sha256:{'d' * 64}",
        provenance=provenance(),
    )


def _candidate(evidence_id: str, finding_id: str, *, confidence: float):
    item = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    return item.model_copy(
        update={
            "id": finding_id,
            "evidence_ids": (evidence_id,),
            "confidence": confidence,
            "confidence_reasons": (f"Evidence {evidence_id} supports {confidence}",),
        }
    )


def _correlate(candidates, evidence):  # type: ignore[no-untyped-def]
    first = candidates[0]
    return DeterministicCorrelationEngine().correlate(
        candidates,
        evidence=evidence,
        asset=SimpleNamespace(id=first.asset_id, tenant_id=first.tenant_id),
        target=SimpleNamespace(id=first.scan_target_id),
        provenance=Provenance(
            scanner_name="qrypton-correlation",
            scanner_version="2.0.0",
            scanner_config_digest=f"sha256:{'c' * 64}",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )


def test_equivalent_same_location_evidence_merges_without_confidence_uplift() -> None:
    first_id = f"evidence_{'a' * 52}"
    second_id = f"evidence_{'b' * 52}"
    first = _candidate(first_id, f"finding_{'a' * 52}", confidence=0.4)
    second = _candidate(second_id, f"finding_{'b' * 52}", confidence=0.98)

    correlated = _correlate(
        (first, second),
        (
            _evidence(first_id, line=10),
            _evidence(second_id, line=10, kind=EvidenceKind.SOURCE_LEXICAL),
        ),
    )

    assert len(correlated) == 1
    result = correlated[0]
    assert result.evidence_ids == (first_id, second_id)
    assert result.confidence == 0.4
    assert result.provenance == first.provenance
    assert result.correlation_provenance is not None
    assert "did not change confidence" in result.confidence_reasons[-1]


def test_distinct_locations_with_the_same_algorithm_remain_distinct() -> None:
    first_id = f"evidence_{'a' * 52}"
    second_id = f"evidence_{'b' * 52}"
    correlated = _correlate(
        (
            _candidate(first_id, f"finding_{'a' * 52}", confidence=0.4),
            _candidate(second_id, f"finding_{'b' * 52}", confidence=0.98),
        ),
        (_evidence(first_id, line=10), _evidence(second_id, line=42)),
    )

    assert len(correlated) == 2
    assert {item.evidence_ids for item in correlated} == {(first_id,), (second_id,)}
    assert {item.confidence for item in correlated} == {0.4, 0.98}


def test_one_repository_asset_can_retain_hundreds_of_distinct_usages() -> None:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    pairs = tuple(
        (
            f"evidence_{'a' * 50}"
            f"{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}",
            f"finding_{'a' * 50}"
            f"{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}",
        )
        for index in range(128)
    )
    candidates = tuple(
        _candidate(evidence_id, finding_id, confidence=0.8) for evidence_id, finding_id in pairs
    )
    evidence = tuple(
        _evidence(evidence_id, line=index + 1)
        for index, (evidence_id, _finding_id) in enumerate(pairs)
    )

    correlated = _correlate(candidates, evidence)

    assert len(correlated) == len(pairs)
    assert {item.asset_id for item in correlated} == {candidates[0].asset_id}


def test_unresolved_evidence_ids_do_not_merge_by_algorithm_name() -> None:
    first_id = f"evidence_{'a' * 52}"
    second_id = f"evidence_{'b' * 52}"
    correlated = _correlate(
        (
            _candidate(first_id, f"finding_{'a' * 52}", confidence=0.4),
            _candidate(second_id, f"finding_{'b' * 52}", confidence=0.98),
        ),
        (),
    )
    assert len(correlated) == 2


@pytest.mark.parametrize(
    ("scanner_name", "rule_id", "surface", "mode"),
    (
        (
            "qrypton-source",
            "source.call",
            EvidenceSurface.SOURCE,
            EvidenceCollectionMode.STATIC_ARTIFACT,
        ),
        (
            "qrypton-binary",
            "binary.symbol",
            EvidenceSurface.BINARY,
            EvidenceCollectionMode.STATIC_ARTIFACT,
        ),
        (
            "qrypton-library",
            "package.metadata",
            EvidenceSurface.LIBRARY,
            EvidenceCollectionMode.STATIC_ARTIFACT,
        ),
        (
            "qrypton-container",
            "image.layer",
            EvidenceSurface.CONTAINER,
            EvidenceCollectionMode.STATIC_ARTIFACT,
        ),
        (
            "qrypton-kms",
            "static.kms-reference",
            EvidenceSurface.KMS,
            EvidenceCollectionMode.STATIC_IDENTIFIER,
        ),
    ),
)
def test_all_surfaces_normalize_to_the_same_evidence_contract(
    scanner_name: str,
    rule_id: str,
    surface: EvidenceSurface,
    mode: EvidenceCollectionMode,
) -> None:
    raw = RawObservation(
        kind=EvidenceKind.PACKAGE_METADATA,
        location=EvidenceLocation(relative_path="input.json", line_start=1, line_end=1),
        attributes={"rule_id": rule_id, "subject_kind": "library", "subject_value": "crypto-lib"},
        confidence=0.8,
    )
    item = SourceNormalizer().normalize(
        raw,
        asset=SimpleNamespace(id=f"asset_{'a' * 52}", tenant_id=f"tenant_{'a' * 52}"),  # type: ignore[arg-type]
        target=SimpleNamespace(id=f"target_{'a' * 52}"),  # type: ignore[arg-type]
        provenance=Provenance(
            scanner_name=scanner_name,
            scanner_version="1.0.0",
            scanner_config_digest=f"sha256:{'a' * 64}",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )

    assert item.surface is surface
    assert item.collection_mode is mode
    assert item.location.relative_path == "input.json"
    assert item.provenance.scanner_name == scanner_name
    if surface is EvidenceSurface.KMS:
        assert "no authenticated cloud-provider API call" in item.limitations[0]


@pytest.mark.parametrize(
    ("subject_kind", "subject_value", "category"),
    (
        ("library", "cryptography", "library"),
        ("protocol", "tls", "protocol"),
    ),
)
def test_library_and_protocol_observations_do_not_claim_algorithm_usage(
    subject_kind: str, subject_value: str, category: str
) -> None:
    raw = RawObservation(
        kind=EvidenceKind.SOURCE_AST,
        location=EvidenceLocation(relative_path="src/client.py", line_start=12, line_end=12),
        attributes={"subject_kind": subject_kind, "subject_value": subject_value},
        confidence=0.8,
    )
    asset = SimpleNamespace(id=f"asset_{'a' * 52}", tenant_id=f"tenant_{'a' * 52}")
    target = SimpleNamespace(id=f"target_{'a' * 52}")
    normalizer = SourceNormalizer()
    evidence = normalizer.normalize(
        raw,
        asset=asset,  # type: ignore[arg-type]
        target=target,  # type: ignore[arg-type]
        provenance=Provenance(
            scanner_name="qrypton-source",
            scanner_version="1.0.0",
            scanner_config_digest=f"sha256:{'a' * 64}",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    derived = normalizer.derive_findings(
        (evidence,),
        asset=asset,  # type: ignore[arg-type]
        target=target,  # type: ignore[arg-type]
        provenance=evidence.provenance,
        id_deriver=HmacIdDeriver(b"a" * 32),
    )

    assert len(derived) == 1
    result = derived[0]
    assert result.category == category
    assert result.algorithm.state is not ObservationState.OBSERVED
    if category == "library":
        assert result.library.value is not None
        assert result.library.value.name.value == "cryptography"
    else:
        assert result.protocol.value is not None
        assert result.protocol.value.name.value == "tls"


def test_persistence_retains_auditable_evidence_location_and_surface(tmp_path: Path) -> None:
    evidence_id = f"evidence_{'a' * 52}"
    evidence = _evidence(evidence_id, line=10)
    stored_finding = _candidate(evidence_id, f"finding_{'a' * 52}", confidence=0.8)
    store = SqliteRunStore(tmp_path / "phase3.sqlite3")
    store.finalize_run(
        RunResult(
            run_id=f"run_{'a' * 52}",
            tenant_id=evidence.tenant_id,
            status=RunStatus.COMPLETED,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            evidence=(evidence,),
            findings=(stored_finding,),
            policy_outcome=PolicyOutcome(passed=True),
        )
    )
    restored = store.get_run(tenant_id=evidence.tenant_id, run_id=f"run_{'a' * 52}")

    assert restored is not None
    restored_evidence = restored.evidence[0]
    assert restored_evidence.location.relative_path == "src/crypto.py"
    assert restored_evidence.location.line_start == 10
    assert restored_evidence.surface is EvidenceSurface.SOURCE
    assert restored_evidence.collection_mode is EvidenceCollectionMode.STATIC_ARTIFACT
    assert restored_evidence.attributes["subject_value"] == "rsa"
