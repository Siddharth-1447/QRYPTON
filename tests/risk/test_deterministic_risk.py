from __future__ import annotations

import math

import pytest

from qrypton.risk.engine import evaluate_qrypton_risk
from qrypton.risk.schemas import BusinessContext, MoscaInput


def _business(**updates: int) -> BusinessContext:
    values = {
        "data_sensitivity": 3,
        "system_criticality": 3,
        "exposure_level": 3,
        "regulatory_importance": 3,
        "migration_complexity": 3,
    }
    values.update(updates)
    return BusinessContext(**values)


def test_equal_horizon_is_not_an_immediate_mosca_vulnerability() -> None:
    result = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=6, y_migration_years=4, z_crqc_horizon_years=10),
        _business(),
    )
    assert result.explanation.urgency_ratio == 1.0
    assert result.explanation.exposure_overlap_years == 0.0
    assert result.explanation.urgency_tier == "high"


def test_permanent_confidentiality_has_infinite_urgency() -> None:
    result = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=None, y_migration_years=2, z_crqc_horizon_years=10),
        _business(),
    )
    assert math.isinf(result.explanation.urgency_ratio)
    assert result.explanation.urgency_tier == "critical"


def test_negative_duration_is_rejected() -> None:
    with pytest.raises(ValueError):
        MoscaInput(x_data_lifetime_years=1, y_migration_years=-0.1, z_crqc_horizon_years=10)


def test_low_business_impact_caps_critical_urgency_at_high() -> None:
    result = evaluate_qrypton_risk(
        MoscaInput(x_data_lifetime_years=20, y_migration_years=1, z_crqc_horizon_years=10),
        _business(
            data_sensitivity=1,
            system_criticality=1,
            exposure_level=1,
            regulatory_importance=1,
            migration_complexity=1,
        ),
    )
    assert result.explanation.urgency_tier == "critical"
    assert result.risk_level == "high"


def test_extreme_migration_duration_and_uncertainty_are_auditable() -> None:
    result = evaluate_qrypton_risk(
        MoscaInput(
            x_data_lifetime_years=5,
            y_migration_years=30.0,
            z_crqc_horizon_years=20,
            uncertainty_delta_years=20,
        ),
        _business(),
    )
    assert result.explanation.exposure_overlap_years == 15.0
    assert result.explanation.sensitivity_flip
    assert "Deterministic Mosca assessment" in result.explanation.markdown
