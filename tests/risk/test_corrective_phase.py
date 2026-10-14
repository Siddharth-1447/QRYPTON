from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from qrypton.application.config import default_risk_policy
from qrypton.application.correlation import DeterministicCorrelationEngine
from qrypton.contracts.enums import (
    AlgorithmFamily,
    Criticality,
    EvidenceKind,
    MoscaUrgency,
    ObservationState,
    RiskLevel,
)
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import BusinessContext, Evidence, EvidenceLocation, Observation
from qrypton.risk.mosca import MoscaParameters, MoscaRiskEngine
from tests.risk.conftest import finding, provenance, unknown


def _context(target, criticality: Criticality, suffix: str) -> BusinessContext:
    evidence_id = target.evidence_ids[0]
    context_id = f"business_context_{suffix * 52}"
    return BusinessContext(
        id=context_id,
        tenant_id=target.tenant_id,
        asset_id=target.asset_id,
        criticality=Observation(
            state=ObservationState.OBSERVED,
            value=criticality,
            basis_evidence_ids=(evidence_id,),
        ),
        data_classification=Observation(state=ObservationState.UNKNOWN),
        internet_exposed=Observation(state=ObservationState.UNKNOWN),
        owner_reference=Observation(state=ObservationState.UNKNOWN),
        provenance=provenance(),
    )


def test_missing_business_criticality_stays_unclassified() -> None:
    target = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    assessment = engine.assess(target, None, default_risk_policy(datetime.now(UTC)))
    assert assessment.factors.business_impact.state is ObservationState.UNKNOWN
    assert "criticality was not provided" in assessment.factors.business_impact.rationale
    assert assessment.mosca_urgency is MoscaUrgency.MEDIUM


def test_assessment_confidence_tracks_context_completeness_without_changing_detection() -> None:
    target = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    evidence_id = target.evidence_ids[0]
    observed = lambda value: Observation(  # noqa: E731
        state=ObservationState.OBSERVED, value=value, basis_evidence_ids=(evidence_id,)
    )
    full = BusinessContext(
        id=f"business_context_{'f' * 52}",
        tenant_id=target.tenant_id,
        asset_id=target.asset_id,
        criticality=observed(Criticality.LOW),
        data_classification=observed("public"),
        internet_exposed=observed(False),
        owner_reference=Observation(state=ObservationState.UNKNOWN),
        provenance=provenance(),
    )
    partial = full.model_copy(
        update={"data_classification": Observation(state=ObservationState.UNKNOWN)}
    )
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    policy = default_risk_policy(datetime.now(UTC))
    complete, incomplete, missing = (
        engine.assess(target, context, policy) for context in (full, partial, None)
    )
    assert [item.factors.evidence_confidence for item in (complete, incomplete, missing)] == [
        0.9,
        0.9,
        0.9,
    ]
    assert complete.context_completeness == 1.0
    assert incomplete.context_completeness == pytest.approx(2 / 3)
    assert missing.context_completeness == 0.0
    assert [item.assessment_confidence for item in (complete, incomplete, missing)] == [
        0.9,
        0.6,
        0.0,
    ]
    assert all(item.level is not RiskLevel.LOW for item in (incomplete, missing))
    assert "context completeness 0/3" in missing.factors.rationale[-2]


def test_unobserved_algorithm_can_be_assessed_without_inventing_risk() -> None:
    target = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION).model_copy(
        update={"algorithm": unknown()}
    )
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    assessment = engine.assess(target, None, default_risk_policy(datetime.now(UTC)))
    assert assessment.level is RiskLevel.UNKNOWN
    assert assessment.mosca_applicable == "unknown"
    assert assessment.mosca_urgency is MoscaUrgency.UNKNOWN


def test_findings_can_use_different_business_contexts() -> None:
    first = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    second = first.model_copy(update={"id": f"finding_{'b' * 52}"})
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    policy = default_risk_policy(datetime.now(UTC))
    low = engine.assess(first, _context(first, Criticality.LOW, "c"), policy)
    high = engine.assess(second, _context(second, Criticality.HIGH, "d"), policy)
    assert low.business_context_id != high.business_context_id
    assert low.factors.business_impact.value < high.factors.business_impact.value


def test_mosca_timeline_changes_urgency_not_composite_risk_or_confidence() -> None:
    target = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    policy = default_risk_policy(datetime.now(UTC))
    engines = (
        MoscaRiskEngine(
            parameters=MoscaParameters(
                data_shelf_life_years=1, migration_time_years=1, quantum_threat_horizon_years=10
            ),
            id_deriver=HmacIdDeriver(b"a" * 32),
        ),
        MoscaRiskEngine(
            parameters=MoscaParameters(
                data_shelf_life_years=6, migration_time_years=5, quantum_threat_horizon_years=10
            ),
            id_deriver=HmacIdDeriver(b"a" * 32),
        ),
    )
    results = [engine.assess(target, None, policy) for engine in engines]
    assert results[0].mosca_urgency is MoscaUrgency.LOW
    assert results[1].mosca_urgency is MoscaUrgency.CRITICAL
    assert results[0].level == results[1].level
    assert results[0].score.value == results[1].score.value
    assert results[0].factors.evidence_confidence == results[1].factors.evidence_confidence


def test_correlation_does_not_raise_confidence_from_another_observation() -> None:
    first = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION).model_copy(
        update={"confidence": 0.4, "confidence_reasons": ("Evidence a supports 0.4",)}
    )
    second = first.model_copy(
        update={
            "id": f"finding_{'b' * 52}",
            "evidence_ids": (f"evidence_{'b' * 52}",),
            "confidence": 0.99,
            "confidence_reasons": ("Evidence b supports 0.99",),
        }
    )
    evidence = (
        Evidence(
            id=first.evidence_ids[0],
            tenant_id=first.tenant_id,
            asset_id=first.asset_id,
            scan_target_id=first.scan_target_id,
            kind=EvidenceKind.SOURCE_AST,
            location=EvidenceLocation(relative_path="crypto.py", line_start=10, line_end=10),
            attributes={"subject_kind": "algorithm", "subject_value": "rsa"},
            confidence=0.4,
            deduplication_fingerprint=f"sha256:{'a' * 64}",
            provenance=provenance(),
        ),
        Evidence(
            id=second.evidence_ids[0],
            tenant_id=second.tenant_id,
            asset_id=second.asset_id,
            scan_target_id=second.scan_target_id,
            kind=EvidenceKind.SOURCE_LEXICAL,
            location=EvidenceLocation(relative_path="crypto.py", line_start=10, line_end=10),
            attributes={"subject_kind": "algorithm", "subject_value": "rsa"},
            confidence=0.99,
            deduplication_fingerprint=f"sha256:{'b' * 64}",
            provenance=provenance(),
        ),
    )
    correlated = DeterministicCorrelationEngine().correlate(
        (first, second),
        evidence=evidence,
        asset=SimpleNamespace(id=first.asset_id, tenant_id=first.tenant_id),  # type: ignore[arg-type]
        target=SimpleNamespace(id=first.scan_target_id),  # type: ignore[arg-type]
        provenance=provenance(),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    assert len(correlated) == 1
    assert correlated[0].confidence == 0.4
    assert correlated[0].confidence_reasons[0] == "Evidence a supports 0.4"
    assert "did not change confidence" in correlated[0].confidence_reasons[-1]


def test_mosca_horizon_is_temporal_and_does_not_rewrite_finding_dimensions() -> None:
    from qrypton.contracts.enums import RiskLevel

    raw_samples = (
        finding("RSA-2048", AlgorithmFamily.ASYMMETRIC_ENCRYPTION),
        finding("ECDSA-P256", AlgorithmFamily.SIGNATURE),
        finding("AES-256", AlgorithmFamily.SYMMETRIC_CIPHER),
        finding("SHA-256", AlgorithmFamily.HASH),
        finding("MD5", AlgorithmFamily.HASH),
        finding("ML-KEM-768", AlgorithmFamily.KEY_AGREEMENT),
        finding("unknown", AlgorithmFamily.UNKNOWN),
    )
    raw_samples = tuple(
        item.model_copy(
            update={
                "id": f"finding_{suffix * 52}",
                "asset_id": f"asset_{suffix * 52}",
                "scan_target_id": f"target_{suffix * 52}",
                "evidence_ids": (f"evidence_{suffix * 52}",),
                "algorithm": item.algorithm.model_copy(
                    update={"basis_evidence_ids": (f"evidence_{suffix * 52}",)}
                ),
                "algorithm_identification_evidence": (f"evidence_{suffix * 52}",),
            }
        )
        for item, suffix in zip(raw_samples, "abcdefg", strict=True)
    )
    samples = tuple(
        item.model_copy(
            update={
                "crypto_role": role,
                "confidence": confidence,
                "confidence_reasons": (reason,),
                "algorithm_identification_confidence": confidence,
                "usage_confidence": confidence,
            }
        )
        for item, role, confidence, reason in zip(
            raw_samples,
            (
                "public_key_encryption",
                "digital_signature",
                "data_encryption",
                "integrity_digest",
                "legacy_checksum",
                "key_encapsulation",
                "unknown",
            ),
            (0.98, 0.87, 0.94, 0.78, 0.99, 0.96, 0.30),
            (
                "RSA parameters observed",
                "signature call observed",
                "AES call observed",
                "digest call inferred",
                "MD5 evidence observed",
                "KEM call observed",
                "algorithm unavailable",
            ),
            strict=True,
        )
    )
    criticalities = (
        Criticality.HIGH,
        Criticality.CRITICAL,
        Criticality.LOW,
        Criticality.MEDIUM,
        Criticality.HIGH,
        Criticality.LOW,
        Criticality.UNKNOWN,
    )
    contexts = tuple(
        _context(item, criticality, suffix)
        for item, criticality, suffix in zip(samples, criticalities, "abcdefg", strict=True)
    )
    scenario_b_contexts = tuple(context.model_copy(deep=True) for context in contexts)
    policy = default_risk_policy(datetime(2026, 1, 1, tzinfo=UTC))
    engines = (
        MoscaRiskEngine(
            parameters=MoscaParameters(
                data_shelf_life_years=5, migration_time_years=7, quantum_threat_horizon_years=8
            ),
            id_deriver=HmacIdDeriver(b"a" * 32),
        ),
        MoscaRiskEngine(
            parameters=MoscaParameters(
                data_shelf_life_years=5, migration_time_years=7, quantum_threat_horizon_years=20
            ),
            id_deriver=HmacIdDeriver(b"a" * 32),
        ),
    )
    scenario_b_findings = tuple(item.model_copy(deep=True) for item in samples)
    evaluations = [
        [
            engine.assess(item, context, policy)
            for item, context in zip(findings, business_contexts, strict=True)
        ]
        for engine, findings, business_contexts in zip(
            engines,
            (samples, scenario_b_findings),
            (contexts, scenario_b_contexts),
            strict=True,
        )
    ]
    assert len(evaluations[0]) == len(evaluations[1]) == 7
    for first, second, first_context, second_context, before, after in zip(
        samples,
        scenario_b_findings,
        contexts,
        scenario_b_contexts,
        *evaluations,
        strict=True,
    ):
        assert first.asset_id == second.asset_id
        assert first.algorithm == second.algorithm
        assert first.algorithm_identification_status == second.algorithm_identification_status
        assert first.library == second.library
        assert first.confidence == second.confidence
        assert first.confidence_reasons == second.confidence_reasons
        assert first_context.id == second_context.id
        assert first_context.criticality == second_context.criticality
        assert first_context.data_classification == second_context.data_classification
        assert first_context.internet_exposed == second_context.internet_exposed
        assert before.finding_id == after.finding_id
        assert before.level == after.level
        assert before.score == after.score
        assert before.factors.evidence_confidence == after.factors.evidence_confidence
        assert before.factors.crypto_risk == after.factors.crypto_risk
        assert before.factors.quantum_risk == after.factors.quantum_risk
        assert before.factors.business_impact_risk == after.factors.business_impact_risk
        assert before.factors.business_criticality == after.factors.business_criticality
        assert before.mosca_applicable == after.mosca_applicable
    assert evaluations[0][0].mosca_urgency is MoscaUrgency.CRITICAL
    assert evaluations[1][0].mosca_urgency is MoscaUrgency.MEDIUM
    assert evaluations[0][2].mosca_urgency is MoscaUrgency.NOT_APPLICABLE
    assert evaluations[0][5].factors.quantum_risk is RiskLevel.LOW
    assert evaluations[0][6].level is RiskLevel.UNKNOWN
    assert [result.factors.crypto_risk for result in evaluations[1]] == [
        RiskLevel.MEDIUM,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.LOW,
        RiskLevel.CRITICAL,
        RiskLevel.LOW,
        RiskLevel.UNKNOWN,
    ]
    assert [result.factors.quantum_risk for result in evaluations[1]] == [
        RiskLevel.HIGH,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.MEDIUM,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.UNKNOWN,
    ]
    assert [result.final_priority for result in evaluations[1]] == [
        RiskLevel.CRITICAL,
        RiskLevel.CRITICAL,
        RiskLevel.MEDIUM,
        RiskLevel.MEDIUM,
        RiskLevel.CRITICAL,
        RiskLevel.LOW,
        RiskLevel.UNKNOWN,
    ]


def test_finding_timeline_overrides_are_persisted_with_sources() -> None:
    item = finding("RSA-2048", AlgorithmFamily.ASYMMETRIC_ENCRYPTION).model_copy(
        update={
            "mosca_x_data_lifetime_years": 20,
            "mosca_y_migration_years": 5,
            "mosca_x_source": "asset",
            "mosca_y_source": "finding",
        }
    )
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5,
            migration_time_years=7,
            quantum_threat_horizon_years=8,
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    persisted = engine.persistable_evaluation(item)
    assert persisted.x_data_lifetime_years == 20
    assert persisted.y_migration_years == 5
    assert persisted.z_crqc_horizon_years == 8
    assert persisted.x_source == "asset"
    assert persisted.y_source == "finding"
    assert persisted.z_source == "scenario"
    assert persisted.urgency == "critical"


def test_confidence_changes_assessment_certainty_not_final_priority() -> None:
    item = finding("RSA-2048", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    lower = item.model_copy(
        update={"confidence": 0.35, "confidence_reasons": ("symbol-only evidence",)}
    )
    higher = item.model_copy(
        update={"confidence": 0.98, "confidence_reasons": ("algorithm and callsite observed",)}
    )
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5,
            migration_time_years=2,
            quantum_threat_horizon_years=10,
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    low_assessment = engine.assess(
        lower, None, default_risk_policy(datetime(2026, 1, 1, tzinfo=UTC))
    )
    high_assessment = engine.assess(
        higher, None, default_risk_policy(datetime(2026, 1, 1, tzinfo=UTC))
    )
    assert low_assessment.final_priority == high_assessment.final_priority
    assert low_assessment.factors.crypto_risk == high_assessment.factors.crypto_risk
    assert low_assessment.factors.quantum_risk == high_assessment.factors.quantum_risk
    assert low_assessment.factors.evidence_confidence == 0.35
    assert high_assessment.factors.evidence_confidence == 0.98
    assert "symbol-only evidence" in low_assessment.factors.rationale[6]


def test_asset_timeline_is_used_when_finding_override_is_absent() -> None:
    item = finding("RSA-2048", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    context = _context(item, Criticality.MEDIUM, "e").model_copy(
        update={
            "mosca_x_data_lifetime_years": 20,
            "mosca_y_migration_years": 5,
        }
    )
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5,
            migration_time_years=7,
            quantum_threat_horizon_years=8,
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    persisted = engine.persistable_evaluation(item, business_context=context)
    assert persisted.x_data_lifetime_years == 20
    assert persisted.y_migration_years == 5
    assert persisted.x_source == "asset"
    assert persisted.y_source == "asset"


def test_mosca_strict_boundary_and_missing_inputs() -> None:
    from pydantic import ValidationError

    cases = ((7, 8, "medium"), (8, 8, "high"), (9, 8, "critical"))
    for required, horizon, urgency in cases:
        result = MoscaRiskEngine(
            parameters=MoscaParameters(
                data_shelf_life_years=required - 2,
                migration_time_years=2,
                quantum_threat_horizon_years=horizon,
            ),
            id_deriver=HmacIdDeriver(b"a" * 32),
        ).persistable_evaluation(finding("RSA-2048", AlgorithmFamily.ASYMMETRIC_ENCRYPTION))
        assert result.urgency == urgency
    valid_inputs = {
        "data_shelf_life_years": 1,
        "migration_time_years": 1,
        "quantum_threat_horizon_years": 8,
    }
    for missing in valid_inputs:
        with pytest.raises(ValidationError):
            MoscaParameters.model_validate(
                {key: value for key, value in valid_inputs.items() if key != missing}
            )
    for negative in valid_inputs:
        values = {**valid_inputs, negative: -1}
        with pytest.raises(ValidationError):
            MoscaParameters(**values)
