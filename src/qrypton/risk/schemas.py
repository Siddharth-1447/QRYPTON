"""Strict input and output schemas for deterministic QRYPTON risk evaluation."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from qrypton.contracts.models import DomainModel

Rating = Annotated[int, Field(ge=1, le=5)]
Years = Annotated[float, Field(ge=0.0, le=10_000.0)]
PositiveYears = Annotated[float, Field(gt=0.0, le=10_000.0)]


class RiskMatrixVersion(StrEnum):
    V1_0_0 = "1.0.0"


class BusinessContext(DomainModel):
    """Five auditable business-impact dimensions, each scored from 1 through 5."""

    data_sensitivity: Rating
    system_criticality: Rating
    exposure_level: Rating
    regulatory_importance: Rating
    migration_complexity: Rating


class MoscaInput(DomainModel):
    """Mosca timelines in years; ``None`` for X means permanent confidentiality."""

    x_data_lifetime_years: Years | None
    y_migration_years: Years
    z_crqc_horizon_years: PositiveYears
    uncertainty_delta_years: Years = 0.0

    @model_validator(mode="after")
    def validate_durations(self) -> MoscaInput:
        values: tuple[float, ...] = (
            self.y_migration_years,
            self.z_crqc_horizon_years,
            self.uncertainty_delta_years,
        )
        if self.x_data_lifetime_years is not None:
            values = (*values, self.x_data_lifetime_years)
        if not all(math.isfinite(value) and value >= 0.0 for value in values):
            raise ValueError("Mosca durations must be finite and non-negative")
        return self


class RiskExplanation(DomainModel):
    """Auditable intermediate calculations plus their Markdown rationale."""

    urgency_ratio: float
    exposure_overlap_years: float
    exposure_overlap_min_years: float
    exposure_overlap_max_years: float
    sensitivity_flip: bool
    urgency_tier: Literal["critical", "high", "medium", "low"]
    business_impact_score: Annotated[float, Field(ge=1.0, le=5.0)]
    markdown: Annotated[str, Field(min_length=1, max_length=4096)]


class RiskAssessmentResult(DomainModel):
    matrix_version: RiskMatrixVersion
    risk_level: Literal["critical", "high", "medium", "low", "unknown"]
    explanation: RiskExplanation
