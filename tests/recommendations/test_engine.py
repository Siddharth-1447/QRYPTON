from __future__ import annotations

from datetime import UTC, datetime

from qrypton.contracts.enums import AlgorithmFamily, ObservationState, RiskLevel
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import Observation, RiskAssessment, RiskFactors
from qrypton.policies.pqc import PqcRecommendationPolicy
from qrypton.recommendations.engine import PqcRecommendationEngine
from qrypton.recommendations.schemas import CompatibilityFactors, HybridMode, SignatureSelection
from tests.risk.conftest import finding, provenance


def _policy(**updates: object) -> PqcRecommendationPolicy:
    values: dict[str, object] = {
        "profile_id": "pqc-default",
        "profile_version": "1.0.0",
        "published_at": datetime(2026, 1, 1, tzinfo=UTC),
        "nist_references": ("https://csrc.nist.gov/pubs/fips/203/final",),
    }
    values.update(updates)
    return PqcRecommendationPolicy(**values)


def _assessment(finding_id: str) -> RiskAssessment:
    unknown = Observation[float](state=ObservationState.UNKNOWN)
    return RiskAssessment(
        id=f"risk_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        finding_id=finding_id,
        score=unknown,
        level=RiskLevel.HIGH,
        factors=RiskFactors(
            cryptographic_obsolescence=unknown,
            quantum_exposure=unknown,
            exploitability=unknown,
            business_impact=unknown,
            evidence_confidence=0.9,
            policy_profile_id="risk-default",
            policy_profile_version="1.0.0",
            rationale=("test",),
        ),
        assessed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_name="test",
        engine_version="1.0.0",
        evidence_ids=(f"evidence_{'a' * 52}",),
    )


def _engine() -> PqcRecommendationEngine:
    return PqcRecommendationEngine(id_deriver=HmacIdDeriver(b"a" * 32), provenance=provenance())


def test_key_establishment_maps_to_fips_203_with_hybrid_policy() -> None:
    item = finding("ecdh", AlgorithmFamily.KEY_AGREEMENT)
    result = _engine().plan(
        item,
        _assessment(item.id),
        _policy(hybrid_kem_mode=HybridMode.REQUIRED),
        compatibility=CompatibilityFactors(peer_support="confirmed"),
    )
    assert result.plan.target_algorithms[0].canonical_name == "ml-kem"
    assert result.plan.hybrid_mode is HybridMode.REQUIRED
    assert "fips/203" in str(result.plan.standard_references[0])


def test_signature_policy_selects_slh_dsa() -> None:
    item = finding("ecdsa", AlgorithmFamily.SIGNATURE)
    result = _engine().plan(
        item, _assessment(item.id), _policy(signature_selection=SignatureSelection.SLH_DSA)
    )
    assert result.plan.target_algorithms[0].canonical_name == "slh-dsa"
    assert "fips/205" in str(result.plan.standard_references[0])


def test_symmetric_finding_never_receives_asymmetric_pqc_target() -> None:
    item = finding("triple-des", AlgorithmFamily.SYMMETRIC_CIPHER)
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.target_algorithms == ()
    assert "do not replace" in result.recommendations[0].action


def test_ambiguous_rsa_produces_validation_not_direct_migration() -> None:
    item = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.role.value == "ambiguous"
    assert result.recommendations[0].kind.value == "validation"


def test_unknown_algorithm_routes_to_manual_review_required() -> None:
    item = finding("unknown", AlgorithmFamily.UNKNOWN)
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert len(result.recommendations) == 1
    rec = result.recommendations[0]
    assert rec.priority == 1
    assert "Manual Review Required" in rec.title
    assert "Manual review required" in rec.action


def test_rsa_encryption_without_operation_context_is_insufficient_context() -> None:
    item = finding("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.role.value == "ambiguous"
    assert result.plan.target_algorithms == ()
    assert result.recommendations[0].kind.value == "validation"
    assert "do not select a primitive replacement" in result.recommendations[0].action


def test_library_only_finding_does_not_recommend_primitive_replacement() -> None:
    item = finding("openssl", AlgorithmFamily.UNKNOWN).model_copy(update={"category": "library"})
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.target_algorithms == ()
    assert result.recommendations[0].title == "Insufficient Context: Library Only"
    assert "does not prove cryptographic use" in result.recommendations[0].action


def test_existing_ml_dsa_requires_deployment_validation_not_replacement() -> None:
    item = finding("ML-DSA-65", AlgorithmFamily.SIGNATURE)
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.target_algorithms == ()
    assert result.recommendations[0].kind.value == "validation"
    assert "already present" in result.recommendations[0].action


def test_pqc_decision_includes_evidence_confidence_and_compatibility() -> None:
    item = finding("ECDH", AlgorithmFamily.KEY_AGREEMENT)
    result = _engine().plan(item, _assessment(item.id), _policy())
    action = result.recommendations[0].action
    assert "Evidence: evidence_" in action
    assert "Recommendation confidence:" in action
    assert "performance=unknown" in action
    assert "latency=unknown" in action
    assert "Hybrid KEM transition mode" in action


def test_explicit_rsa_signature_context_enables_ml_dsa_mapping() -> None:
    item = finding("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION).model_copy(
        update={"crypto_role": "signature"}
    )
    result = _engine().plan(item, _assessment(item.id), _policy())
    assert result.plan.role.value == "signature"
    assert result.plan.target_algorithms[0].canonical_name == "ml-dsa"


def test_weak_hash_and_symmetric_findings_have_distinct_classical_remediation() -> None:
    policy = _policy()
    sha1 = finding("SHA-1", AlgorithmFamily.HASH)
    des = finding("3DES", AlgorithmFamily.SYMMETRIC_CIPHER)
    sha_plan = _engine().plan(sha1, _assessment(sha1.id), policy)
    des_plan = _engine().plan(des, _assessment(des.id), policy)
    assert "FIPS 180-4" in sha_plan.recommendations[0].action or "fips/180-4" in str(
        sha_plan.recommendations[0].nist_references
    )
    assert "classically_weak_or_disallowed" in sha_plan.recommendations[0].action
    assert "AEAD" in des_plan.recommendations[0].action
    assert "classically_weak_or_disallowed" in des_plan.recommendations[0].action


def test_recommendation_ids_are_deterministic_for_same_finding_and_policy() -> None:
    item = finding("ECDH", AlgorithmFamily.KEY_AGREEMENT)
    assessment = _assessment(item.id)
    policy = _policy()
    first = _engine().plan(item, assessment, policy)
    second = _engine().plan(item, assessment, policy)
    assert first.plan.model_dump(mode="json") == second.plan.model_dump(mode="json")
    assert tuple(rec.id for rec in first.recommendations) == tuple(
        rec.id for rec in second.recommendations
    )
