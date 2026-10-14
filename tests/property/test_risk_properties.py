from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from qrypton.risk.engine import evaluate_qrypton_risk
from qrypton.risk.schemas import BusinessContext, MoscaInput

_years = st.floats(min_value=0, max_value=500, allow_nan=False, allow_infinity=False)
_horizons = st.floats(min_value=0.01, max_value=500, allow_nan=False, allow_infinity=False)
_urgency = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_business = BusinessContext(
    data_sensitivity=3,
    system_criticality=3,
    exposure_level=3,
    regulatory_importance=3,
    migration_complexity=3,
)


@given(x=_years, y=_years, increment=_years, z=_horizons)
def test_changing_x_changes_only_temporal_urgency_without_finding_evidence(
    x: float, y: float, increment: float, z: float
) -> None:
    initial = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=x, y_migration_years=y, z_crqc_horizon_years=z), _business
    )
    increased = evaluate_qrypton_risk(
        MoscaInput(
            x_data_lifetime_years=x + increment, y_migration_years=y, z_crqc_horizon_years=z
        ),
        _business,
    )
    assert increased.risk_level == initial.risk_level == "unknown"
    assert (
        _urgency[increased.explanation.urgency_tier] >= _urgency[initial.explanation.urgency_tier]
    )


@given(x=_years, y=_years, increment=_years, z=_horizons)
def test_changing_y_changes_only_temporal_urgency_without_finding_evidence(
    x: float, y: float, increment: float, z: float
) -> None:
    initial = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=x, y_migration_years=y, z_crqc_horizon_years=z), _business
    )
    increased = evaluate_qrypton_risk(
        MoscaInput(
            x_data_lifetime_years=x, y_migration_years=y + increment, z_crqc_horizon_years=z
        ),
        _business,
    )
    assert increased.risk_level == initial.risk_level == "unknown"
    assert (
        _urgency[increased.explanation.urgency_tier] >= _urgency[initial.explanation.urgency_tier]
    )


@given(x=_years, y=_years, z=_horizons)
def test_finite_urgency_ratio_matches_mosca_equation(x: float, y: float, z: float) -> None:
    result = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=x, y_migration_years=y, z_crqc_horizon_years=z), _business
    )
    assert result.explanation.urgency_ratio == pytest.approx((x + y) / z)
