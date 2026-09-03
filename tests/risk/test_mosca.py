from __future__ import annotations

import pytest

from qrypton.contracts.enums import AlgorithmFamily
from qrypton.risk.mosca import MoscaParameters, MoscaRiskCalculator
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
