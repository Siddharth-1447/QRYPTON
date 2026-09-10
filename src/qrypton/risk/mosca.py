"""Mosca timeline calculations for quantum-migration urgency."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import Field, model_validator

from qrypton.contracts.enums import Criticality, ObservationState, RiskLevel
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    BusinessContext,
    CryptoFinding,
    DomainModel,
    Observation,
    PersistedMoscaEvaluation,
    RiskAssessment,
    RiskFactors,
)
from qrypton.policies.pqc import RiskPolicy

Years = Annotated[float, Field(ge=0.0, le=10_000.0)]


class MoscaParameters(DomainModel):
    """Time horizons in years; all values must be finite and non-negative."""

    data_shelf_life_years: Years
    migration_time_years: Years
    quantum_threat_horizon_years: Years

    @model_validator(mode="after")
    def validate_finite(self) -> MoscaParameters:
        if not all(
            math.isfinite(value)
            for value in (
                self.data_shelf_life_years,
                self.migration_time_years,
                self.quantum_threat_horizon_years,
            )
        ):
            raise ValueError("Mosca timeline values must be finite")
        return self


class MoscaEvaluation(DomainModel):
    """A bounded, explainable result of testing X + Y against Z."""

    parameters: MoscaParameters
    required_security_years: Years
    time_margin_years: Annotated[float, Field(ge=-10_000.0, le=10_000.0)]
    exposure_score: Annotated[float, Field(ge=0.0, le=100.0)]
    immediate_vulnerability: bool
    urgency: Literal["critical", "high", "medium", "low"]


class MoscaTargetEvaluation(DomainModel):
    """Worst-case target evaluation plus every individual finding result."""

    finding_evaluations: Mapping[str, MoscaEvaluation]
    aggregate: MoscaEvaluation


class MoscaRiskCalculator:
    """Pure Mosca equation evaluator; it does not estimate any of its input timelines."""

    @staticmethod
    def evaluate(parameters: MoscaParameters) -> MoscaEvaluation:
        required = parameters.data_shelf_life_years + parameters.migration_time_years
        horizon = parameters.quantum_threat_horizon_years
        margin = horizon - required
        immediate = required > horizon
        if horizon == 0.0:
            score = 100.0 if required > 0.0 else 0.0
        else:
            score = min(100.0, max(0.0, (required / horizon) * 100.0))
        urgency: Literal["critical", "high", "medium", "low"]
        if immediate:
            urgency = "critical"
        elif required == horizon:
            urgency = "high"
        elif score >= 50.0:
            urgency = "medium"
        else:
            urgency = "low"
        return MoscaEvaluation(
            parameters=parameters,
            required_security_years=required,
            time_margin_years=margin,
            exposure_score=round(score, 4),
            immediate_vulnerability=immediate,
            urgency=urgency,
        )

    def evaluate_finding(
        self, finding: CryptoFinding, parameters: MoscaParameters
    ) -> MoscaEvaluation:
        """Evaluate one finding; the finding is intentionally not used to invent timelines."""
        del finding
        return self.evaluate(parameters)

    def evaluate_target(
        self, findings: Sequence[CryptoFinding], parameters: Mapping[str, MoscaParameters]
    ) -> MoscaTargetEvaluation:
        """Aggregate by the highest exposure score; missing timelines are rejected explicitly."""
        evaluations = {
            finding.id: self.evaluate_finding(finding, parameters[finding.id])
            for finding in findings
        }
        if not evaluations:
            raise ValueError("target aggregation requires at least one finding")
        aggregate = max(
            evaluations.values(),
            key=lambda item: (item.exposure_score, -item.time_margin_years),
        )
        return MoscaTargetEvaluation(finding_evaluations=evaluations, aggregate=aggregate)


class MoscaRiskEngine:
    """Risk-port adapter using a configured, auditable Mosca timeline assumption."""

    name = "qrypton-mosca"
    version = "0.4.0"

    def __init__(self, *, parameters: MoscaParameters, id_deriver: IdDeriver) -> None:
        self.parameters = parameters
        self.id_deriver = id_deriver
        self.calculator = MoscaRiskCalculator()

    def assess(
        self,
        finding: CryptoFinding,
        business_context: BusinessContext | None,
        policy: RiskPolicy,
    ) -> RiskAssessment:
        evaluation = self.calculator.evaluate_finding(finding, self.parameters)
        finding_provenance = finding.provenance
        business_score = 0.0
        business_impact = Observation[float](state=ObservationState.UNKNOWN)
        if business_context is not None:
            criticality = business_context.criticality.value
            business_score = {
                Criticality.CRITICAL: 90.0,
                Criticality.HIGH: 75.0,
                Criticality.MEDIUM: 55.0,
                Criticality.LOW: 30.0,
                Criticality.UNKNOWN: 0.0,
            }[criticality]
            if business_context.internet_exposed.value:
                business_score = min(100.0, business_score + 10.0)
            business_impact = Observation[float](
                state=ObservationState.OBSERVED,
                value=business_score,
                basis_evidence_ids=finding.evidence_ids,
                rationale="Business criticality and internet exposure weighting.",
            )
        combined_score = max(evaluation.exposure_score, business_score)
        combined_level = (
            RiskLevel.CRITICAL if combined_score >= 90 else
            RiskLevel.HIGH if combined_score >= 75 else
            RiskLevel.MEDIUM if combined_score >= 50 else
            RiskLevel.LOW
        )
        assessment_id = self.id_deriver.derive(
            namespace="risk",
            tenant_id=finding.tenant_id,
            canonical_payload=canonical_json_bytes(
                {
                    "finding_id": finding.id,
                    "policy_id": policy.profile_id,
                    "policy_version": policy.profile_version,
                    "parameters": self.parameters,
                }
            ),
        )
        score = Observation[float](
            state=ObservationState.OBSERVED,
            value=combined_score,
            basis_evidence_ids=finding.evidence_ids,
            rationale="Mosca exposure score derived from X + Y relative to Z.",
        )
        unknown = Observation[float](state=ObservationState.UNKNOWN)
        return RiskAssessment(
            id=assessment_id,
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            business_context_id=business_context.id if business_context else None,
            score=score,
            level=combined_level,
            factors=RiskFactors(
                cryptographic_obsolescence=unknown,
                quantum_exposure=Observation[float](
                    state=ObservationState.OBSERVED,
                    value=evaluation.exposure_score,
                    basis_evidence_ids=finding.evidence_ids,
                ),
                exploitability=unknown,
                business_impact=business_impact,
                evidence_confidence=finding.confidence,
                policy_profile_id=policy.profile_id,
                policy_profile_version=policy.profile_version,
                rationale=(
                    f"Mosca: X+Y={evaluation.required_security_years:g}, "
                    f"Z={self.parameters.quantum_threat_horizon_years:g}, "
                    f"margin={evaluation.time_margin_years:g} years.",
                ),
            ),
            assessed_at=finding_provenance.observed_at,
            engine_name=self.name,
            engine_version=self.version,
            evidence_ids=finding.evidence_ids,
        )

    def persistable_evaluation(self, finding: CryptoFinding) -> PersistedMoscaEvaluation:
        """Copy calculator output into the structured run-persistence record."""
        evaluation = self.calculator.evaluate_finding(finding, self.parameters)
        return PersistedMoscaEvaluation(
            finding_id=finding.id,
            x_data_lifetime_years=self.parameters.data_shelf_life_years,
            y_migration_years=self.parameters.migration_time_years,
            z_crqc_horizon_years=self.parameters.quantum_threat_horizon_years,
            required_security_years=evaluation.required_security_years,
            time_margin_years=evaluation.time_margin_years,
            exposure_score=evaluation.exposure_score,
            urgency=evaluation.urgency,
        )
