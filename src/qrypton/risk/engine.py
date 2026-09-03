"""Pure, deterministic Mosca and business-context risk evaluator."""

from __future__ import annotations

import math
from typing import Literal

from qrypton.risk.schemas import (
    BusinessContext,
    MoscaInput,
    RiskAssessmentResult,
    RiskExplanation,
    RiskMatrixVersion,
)

UrgencyTier = Literal["critical", "high", "medium", "low"]
RiskLevel = Literal["critical", "high", "medium", "low"]
_WEIGHTS = (0.30, 0.25, 0.20, 0.15, 0.10)
_LEVELS: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


def _urgency_tier(ratio: float) -> UrgencyTier:
    """Tier boundaries are ordered and preserve Mosca's strict X + Y > Z condition."""
    if ratio > 1.0:
        return "critical"
    if ratio == 1.0:
        return "high"
    if ratio >= 0.75:
        return "medium"
    return "low"


def _business_band(score: float) -> int:
    if score <= 2.0:
        return 0
    if score <= 3.5:
        return 1
    return 2


def _matrix(tier: UrgencyTier, business_score: float) -> RiskLevel:
    """v1.0.0 matrix; low impact caps immediate Mosca urgency at High."""
    rows: dict[UrgencyTier, tuple[RiskLevel, RiskLevel, RiskLevel]] = {
        "low": ("low", "low", "medium"),
        "medium": ("low", "medium", "high"),
        "high": ("medium", "high", "critical"),
        "critical": ("high", "high", "critical"),
    }
    return rows[tier][_business_band(business_score)]


def _business_score(business: BusinessContext) -> float:
    values = (
        business.data_sensitivity,
        business.system_criticality,
        business.exposure_level,
        business.regulatory_importance,
        business.migration_complexity,
    )
    return round(sum(weight * value for weight, value in zip(_WEIGHTS, values, strict=True)), 4)


def evaluate_qrypton_risk(
    mosca: MoscaInput,
    business: BusinessContext,
    matrix_version: RiskMatrixVersion = RiskMatrixVersion.V1_0_0,
) -> RiskAssessmentResult:
    """Evaluate QRYPTON risk without external state, clocks, or implicit assumptions."""
    if matrix_version is not RiskMatrixVersion.V1_0_0:
        raise ValueError("unsupported risk matrix version")
    business_score = _business_score(business)
    if mosca.x_data_lifetime_years is None:
        ratio = math.inf
        overlap = math.inf
        overlap_min = math.inf
        overlap_max = math.inf
        flip = False
    else:
        required = mosca.x_data_lifetime_years + mosca.y_migration_years
        ratio = required / mosca.z_crqc_horizon_years
        overlap = max(0.0, required - mosca.z_crqc_horizon_years)
        delta = mosca.uncertainty_delta_years
        overlap_min = max(0.0, required - delta - mosca.z_crqc_horizon_years)
        overlap_max = max(0.0, required + delta - mosca.z_crqc_horizon_years)
        flip = _urgency_tier((required - delta) / mosca.z_crqc_horizon_years) != _urgency_tier(
            (required + delta) / mosca.z_crqc_horizon_years
        )
    tier = _urgency_tier(ratio)
    risk_level = _matrix(tier, business_score)
    x_value = (
        "permanent" if mosca.x_data_lifetime_years is None else f"{mosca.x_data_lifetime_years:g}"
    )
    ratio_value = "∞" if math.isinf(ratio) else f"{ratio:.4f}"
    overlap_value = "∞" if math.isinf(overlap) else f"{overlap:g}"
    markdown = (
        "### Deterministic Mosca assessment\n\n"
        f"- X (data lifetime): **{x_value} years**; Y (migration): "
        f"**{mosca.y_migration_years:g} years**; Z (CRQC horizon): "
        f"**{mosca.z_crqc_horizon_years:g} years**.\n"
        f"- Urgency ratio R_U = (X + Y) / Z: **{ratio_value}**; "
        f"exposure overlap E: **{overlap_value} years**.\n"
        f"- Uncertainty overlap range: **{overlap_min:g}–{overlap_max:g} years**; "
        f"status flip: **{'yes' if flip else 'no'}**.\n"
        f"- Business impact B: **{business_score:.4f}/5**; urgency tier: "
        f"**{tier}**; matrix {matrix_version.value} result: **{risk_level}**."
    )
    return RiskAssessmentResult(
        matrix_version=matrix_version,
        risk_level=risk_level,
        explanation=RiskExplanation(
            urgency_ratio=ratio,
            exposure_overlap_years=overlap,
            exposure_overlap_min_years=overlap_min,
            exposure_overlap_max_years=overlap_max,
            sensitivity_flip=flip,
            urgency_tier=tier,
            business_impact_score=business_score,
            markdown=markdown,
        ),
    )
