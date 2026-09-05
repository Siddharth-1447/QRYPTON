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
