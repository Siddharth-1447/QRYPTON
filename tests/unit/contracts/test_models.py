from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    AssetKind,
    EvidenceKind,
    ObservationState,
    RiskLevel,
)
from qrypton.contracts.models import (
    Algorithm,
    Asset,
    Evidence,
    EvidenceLocation,
    Observation,
    PersistedMoscaEvaluation,
    RiskAssessment,
    RiskFactors,
    ScanResult,
)

from .conftest import digest, entity_id, observed, provenance, tenant_id, unknown


@pytest.mark.parametrize(
    ("state", "value", "evidence", "valid"),
    [
        (ObservationState.OBSERVED, "rsa", (entity_id("evidence"),), True),
        (ObservationState.OBSERVED, None, (entity_id("evidence"),), False),
        (ObservationState.NOT_OBSERVED, None, (), True),
        (ObservationState.NOT_OBSERVED, "rsa", (), False),
        (ObservationState.UNKNOWN, None, (), True),
        (ObservationState.UNKNOWN, None, (entity_id("evidence"),), False),
        (ObservationState.CONFIRMED_ABSENT, None, (entity_id("evidence"),), True),
        (ObservationState.CONFIRMED_ABSENT, "rsa", (entity_id("evidence"),), False),
    ],
)
def test_observation_knowledge_semantics(
    state: ObservationState, value: object, evidence: tuple[str, ...], valid: bool
) -> None:
    payload = {"state": state, "value": value, "basis_evidence_ids": evidence}
    if valid:
        assert Observation[object](**payload).state is state
    else:
        with pytest.raises(ValidationError):
            Observation[object](**payload)


def test_asset_normalizes_to_utc_and_rejects_extra_fields() -> None:
    asset = Asset(
        id=entity_id(),
        tenant_id=tenant_id(),
        kind=AssetKind.APPLICATION,
        external_reference="payments",
        name="Payments",
        created_at="2026-01-01T08:00:00+08:00",
        updated_at="2026-01-01T09:00:00+08:00",
        provenance=provenance(),
    )
    assert asset.created_at.tzinfo is UTC
    assert asset.created_at.hour == 0
    with pytest.raises(ValidationError):
        Asset.model_validate({**asset.model_dump(), "unexpected": "field"})


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "C:\\temp\\a.py", "../a.py", "a/../b.py", "a//b.py", "a\x00b"]
)
def test_evidence_location_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        EvidenceLocation(relative_path=path)


def test_evidence_location_accepts_and_normalizes_windows_separator() -> None:
    assert EvidenceLocation(relative_path="src\\crypto.py").relative_path == "src/crypto.py"


def test_unknown_algorithm_requires_unknown_classification() -> None:
    common = {
        "canonical_name": "unknown",
        "key_size_bits": unknown(),
        "security_strength_bits": unknown(),
    }
    with pytest.raises(ValidationError):
        Algorithm(
            **common,
            family=AlgorithmFamily.HASH,
            lifecycle_status=AlgorithmStatus.APPROVED,
        )
    assert (
        Algorithm(
            **common,
            family=AlgorithmFamily.UNKNOWN,
            lifecycle_status=AlgorithmStatus.UNKNOWN,
        ).family
        is AlgorithmFamily.UNKNOWN
    )


def test_algorithm_observed_values_require_evidence() -> None:
    algorithm = Algorithm(
        canonical_name="rsa",
        family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
        key_size_bits=observed(2048),
        security_strength_bits=observed(112),
        lifecycle_status=AlgorithmStatus.LEGACY,
    )
    assert algorithm.key_size_bits.value == 2048


def test_scan_result_failure_invariants() -> None:
    base = {
        "id": entity_id("scan_result"),
        "tenant_id": tenant_id(),
        "scan_target_id": entity_id("target"),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "scanner_name": "unit-test",
        "scanner_version": "1",
        "evidence_ids": (),
        "finding_ids": (),
    }
    with pytest.raises(ValidationError):
        ScanResult(**base, status="failed")
    with pytest.raises(ValidationError):
        ScanResult(**base, status="completed", failure_reason="no")
    assert ScanResult(**base, status="failed", failure_reason="parser crashed").status == "failed"


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Asset(
            id=entity_id(),
            tenant_id=tenant_id(),
            kind=AssetKind.APPLICATION,
            external_reference="x",
            name="x",
            created_at=datetime(2026, 1, 1),
            updated_at=datetime(2026, 1, 1, tzinfo=UTC),
            provenance=provenance(),
        )


def test_duplicate_and_conflicting_evidence_remain_independent_records() -> None:
    base = {
        "tenant_id": tenant_id(),
        "asset_id": entity_id(),
        "scan_target_id": entity_id("target"),
        "kind": EvidenceKind.BINARY_STRING,
        "location": EvidenceLocation(relative_path="bin/service", byte_start=4, byte_end=7),
        "deduplication_fingerprint": digest(),
        "provenance": provenance(),
    }
    duplicate = Evidence(id=entity_id("evidence"), confidence=0.7, **base)
    same_evidence = Evidence(id=entity_id("evidence"), confidence=0.7, **base)
    conflicting = Evidence(id=f"evidence_{'b' * 52}", confidence=0.2, **base)
    assert duplicate == same_evidence
    assert duplicate.deduplication_fingerprint == conflicting.deduplication_fingerprint
    assert duplicate.confidence != conflicting.confidence


def test_missing_business_context_is_represented_without_fabricating_a_score() -> None:
    factors = RiskFactors(
        cryptographic_obsolescence=unknown(),
        quantum_exposure=unknown(),
        exploitability=unknown(),
        business_impact=unknown(),
        evidence_confidence=0.0,
        policy_profile_id="baseline",
        policy_profile_version="1",
        rationale=("Business context was not supplied.",),
    )
    assessment = RiskAssessment(
        id=entity_id("risk"),
        tenant_id=tenant_id(),
        finding_id=entity_id("finding"),
        score=unknown(),
        level=RiskLevel.UNKNOWN,
        factors=factors,
        assessed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_name="unit",
        engine_version="1",
        evidence_ids=(),
    )
    assert assessment.business_context_id is None
    assert assessment.score.state is ObservationState.UNKNOWN


def test_persisted_mosca_evaluation_is_structured_and_immutable() -> None:
    record = PersistedMoscaEvaluation(
        finding_id=entity_id("finding"),
        x_data_lifetime_years=5.0,
        y_migration_years=2.0,
        z_crqc_horizon_years=10.0,
        required_security_years=7.0,
        time_margin_years=3.0,
        exposure_score=70.0,
        urgency="medium",
    )
    dumped = record.model_dump()
    restored = PersistedMoscaEvaluation.model_validate(dumped)
    assert restored.required_security_years == 7.0
    with pytest.raises(ValidationError):
        record.exposure_score = 1.0  # type: ignore[misc]
