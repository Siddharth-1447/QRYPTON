from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qrypton.contracts.enums import AlgorithmFamily
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.risk.mosca import MoscaParameters, MoscaRiskCalculator, MoscaRiskEngine
from tests.risk.conftest import finding


@pytest.mark.parametrize(
    ("parameters", "immediate", "urgency"),
    [
        (
            MoscaParameters(
                data_shelf_life_years=5, migration_time_years=3, quantum_threat_horizon_years=7
            ),
            True,
            "critical",
        ),
        (
            MoscaParameters(
                data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=7
            ),
            False,
            "high",
        ),
        (
            MoscaParameters(
                data_shelf_life_years=2, migration_time_years=1, quantum_threat_horizon_years=10
            ),
            False,
            "low",
        ),
    ],
)
def test_mosca_boundary_conditions(
    parameters: MoscaParameters, immediate: bool, urgency: str
) -> None:
    result = MoscaRiskCalculator.evaluate(parameters)
    assert result.immediate_vulnerability is immediate
    assert result.urgency == urgency


def test_target_uses_the_worst_finding_timeline() -> None:
    first = finding("ecdh", AlgorithmFamily.KEY_AGREEMENT)
    second = first.model_copy(update={"id": f"finding_{'b' * 52}"})
    calculator = MoscaRiskCalculator()
    result = calculator.evaluate_target(
        (first, second),
        {
            first.id: MoscaParameters(
                data_shelf_life_years=1, migration_time_years=1, quantum_threat_horizon_years=10
            ),
            second.id: MoscaParameters(
                data_shelf_life_years=9, migration_time_years=2, quantum_threat_horizon_years=10
            ),
        },
    )
    assert result.aggregate.immediate_vulnerability
    assert result.aggregate == result.finding_evaluations[second.id]


def test_mosca_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        MoscaParameters(
            data_shelf_life_years=-1, migration_time_years=1, quantum_threat_horizon_years=2
        )


def test_maximum_accepted_timelines_remain_representable() -> None:
    parameters = MoscaParameters(
        data_shelf_life_years=10_000,
        migration_time_years=10_000,
        quantum_threat_horizon_years=0,
    )
    result = MoscaRiskCalculator.evaluate(parameters)
    assert result.required_security_years == 20_000
    assert result.time_margin_years == -20_000
    assert result.urgency == "critical"
    engine = MoscaRiskEngine(parameters=parameters, id_deriver=HmacIdDeriver(b"a" * 32))
    stored = engine.persistable_evaluation(finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION))
    assert stored.required_security_years == 20_000
    assert stored.time_margin_years == -20_000


@pytest.mark.parametrize(
    "component", ["data_shelf_life_years", "migration_time_years", "quantum_threat_horizon_years"]
)
def test_input_boundary_inside_and_outside(component: str) -> None:
    values = {
        "data_shelf_life_years": 0.0,
        "migration_time_years": 0.0,
        "quantum_threat_horizon_years": 0.0,
    }
    values[component] = 9_999.999
    MoscaRiskCalculator.evaluate(MoscaParameters(**values))
    values[component] = 10_000.001
    with pytest.raises(ValueError):
        MoscaParameters(**values)


@settings(max_examples=250, deadline=None)
@given(
    x=st.floats(min_value=0, max_value=10_000, allow_nan=False, allow_infinity=False),
    y=st.floats(min_value=0, max_value=10_000, allow_nan=False, allow_infinity=False),
    z=st.floats(min_value=0, max_value=10_000, allow_nan=False, allow_infinity=False),
)
def test_every_accepted_timeline_evaluates(x: float, y: float, z: float) -> None:
    parameters = MoscaParameters(
        data_shelf_life_years=x,
        migration_time_years=y,
        quantum_threat_horizon_years=z,
    )
    result = MoscaRiskCalculator.evaluate(parameters)
    assert result.required_security_years == x + y
    assert result.time_margin_years == z - (x + y)


def test_persistable_evaluation_copies_calculator_output() -> None:
    parameters = MoscaParameters(
        data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
    )
    calculated = MoscaRiskCalculator.evaluate(parameters)
    engine = MoscaRiskEngine(parameters=parameters, id_deriver=HmacIdDeriver(b"a" * 32))
    stored = engine.persistable_evaluation(finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION))
    assert stored.x_data_lifetime_years == parameters.data_shelf_life_years
    assert stored.y_migration_years == parameters.migration_time_years
    assert stored.z_crqc_horizon_years == parameters.quantum_threat_horizon_years
    assert stored.required_security_years == calculated.required_security_years
    assert stored.time_margin_years == calculated.time_margin_years
    assert stored.exposure_score == calculated.exposure_score
    assert stored.urgency == calculated.urgency


def test_business_context_impacts_composite_risk_level() -> None:
    from datetime import UTC, datetime

    from qrypton.application.config import default_risk_policy
    from qrypton.contracts.enums import Criticality, ObservationState
    from qrypton.contracts.models import BusinessContext, Observation

    parameters = MoscaParameters(
        data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
    )
    engine = MoscaRiskEngine(parameters=parameters, id_deriver=HmacIdDeriver(b"a" * 32))
    target_finding = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    policy = default_risk_policy(datetime.now(UTC))

    low_context = BusinessContext(
        id=f"ctx_{'a' * 52}",
        tenant_id=target_finding.tenant_id,
        asset_id=target_finding.asset_id,
        criticality=Observation(
            state=ObservationState.OBSERVED,
            value=Criticality.LOW,
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        data_classification=Observation(
            state=ObservationState.OBSERVED,
            value="public",
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        internet_exposed=Observation(
            state=ObservationState.OBSERVED,
            value=False,
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        regulatory_scopes=(),
        owner_reference=Observation(
            state=ObservationState.OBSERVED,
            value="team-test",
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        provenance=target_finding.provenance,
    )

    high_context = BusinessContext(
        id=f"ctx_{'b' * 52}",
        tenant_id=target_finding.tenant_id,
        asset_id=target_finding.asset_id,
        criticality=Observation(
            state=ObservationState.OBSERVED,
            value=Criticality.CRITICAL,
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        data_classification=Observation(
            state=ObservationState.OBSERVED,
            value="restricted",
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        internet_exposed=Observation(
            state=ObservationState.OBSERVED,
            value=True,
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        regulatory_scopes=("pci-dss",),
        owner_reference=Observation(
            state=ObservationState.OBSERVED,
            value="team-prod",
            basis_evidence_ids=target_finding.evidence_ids,
        ),
        provenance=target_finding.provenance,
    )

    low_assessment = engine.assess(target_finding, low_context, policy)
    high_assessment = engine.assess(target_finding, high_context, policy)

    assert (
        low_assessment.factors.business_impact.value < high_assessment.factors.business_impact.value
    )
    assert low_assessment.level.value != high_assessment.level.value
    assert low_assessment.score.value < high_assessment.score.value
