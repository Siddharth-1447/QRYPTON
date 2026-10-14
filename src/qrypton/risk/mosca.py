"""Mosca timeline calculations for quantum-migration urgency."""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import Field, model_validator

from qrypton.contracts.enums import Criticality, MoscaUrgency, ObservationState, RiskLevel
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    BusinessContext,
    CryptoFinding,
    DomainModel,
    Evidence,
    Observation,
    PersistedMoscaEvaluation,
    RiskAssessment,
    RiskFactors,
)
from qrypton.policies.pqc import RiskPolicy
from qrypton.risk.taxonomy import classify_finding

Years = Annotated[float, Field(ge=0.0, le=10_000.0)]
# X and Y are each bounded to 10,000 years. Their sum and Z-(X+Y)
# therefore need distinct derived-value bounds, also measured in years.
RequiredYears = Annotated[float, Field(ge=0.0, le=20_000.0)]
MarginYears = Annotated[float, Field(ge=-20_000.0, le=10_000.0)]


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
    required_security_years: RequiredYears
    time_margin_years: MarginYears
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


def _priority_and_score(
    crypto: RiskLevel, quantum: RiskLevel, business: RiskLevel
) -> tuple[RiskLevel, float]:
    """Categorical priority rule: worst technical dimension, bounded impact uplift.

    Known high/critical business impact can raise an already high technical risk
    by one tier. Business context alone is capped at Medium. Confidence and
    Mosca urgency are deliberately excluded.
    """
    ranks = {
        RiskLevel.UNKNOWN: None,
        RiskLevel.INFORMATIONAL: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    business_ranks = ranks
    known = [value for value in (ranks[crypto], ranks[quantum]) if value is not None]
    impact_rank = business_ranks[business]
    if impact_rank is not None:
        known.append(min(impact_rank, 2))
    if not known:
        return RiskLevel.UNKNOWN, 0.0
    priority_rank = max(known)
    if impact_rank is not None and impact_rank >= 3 and priority_rank >= 3:
        priority_rank = min(priority_rank + 1, 4)
    priority = {
        0: RiskLevel.INFORMATIONAL,
        1: RiskLevel.LOW,
        2: RiskLevel.MEDIUM,
        3: RiskLevel.HIGH,
        4: RiskLevel.CRITICAL,
    }[priority_rank]
    # A monotonic ordinal index; categorical dimensions remain authoritative.
    return priority, float(priority_rank * 25)


def _business_impact(
    context: BusinessContext | None,
) -> tuple[RiskLevel, float, str, tuple[str, ...]]:
    """Take the highest evidenced business-impact category; unknown stays unknown."""
    if context is None:
        return RiskLevel.UNKNOWN, 0.0, "Business context was not supplied.", ()

    categories: list[RiskLevel] = []
    reasons: list[str] = []
    evidence_ids: set[str] = set()
    criticality = context.criticality.value
    if context.criticality.state is ObservationState.OBSERVED and criticality not in {
        None,
        Criticality.UNKNOWN,
    }:
        assert criticality is not None
        categories.append(RiskLevel(criticality.value))
        reasons.append(f"criticality={criticality.value}")
        evidence_ids.update(context.criticality.basis_evidence_ids)
    data_classification = context.data_classification.value
    if (
        context.data_classification.state is ObservationState.OBSERVED
        and data_classification is not None
    ):
        data_level = {
            "public": RiskLevel.LOW,
            "internal": RiskLevel.MEDIUM,
            "confidential": RiskLevel.HIGH,
            "restricted": RiskLevel.CRITICAL,
        }[data_classification]
        categories.append(data_level)
        reasons.append(f"data classification={data_classification}")
        evidence_ids.update(context.data_classification.basis_evidence_ids)
    if (
        context.internet_exposed.state is ObservationState.OBSERVED
        and context.internet_exposed.value
    ):
        categories.append(RiskLevel.HIGH)
        reasons.append("internet exposed=true")
        evidence_ids.update(context.internet_exposed.basis_evidence_ids)
    if context.regulatory_scopes and evidence_ids:
        categories.append(RiskLevel.HIGH)
        reasons.append("regulated scope present")
    if not categories:
        return RiskLevel.UNKNOWN, 0.0, "No evidenced business-impact attributes were observed.", ()

    order = {
        RiskLevel.INFORMATIONAL: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
        RiskLevel.UNKNOWN: -1,
    }
    level = max(categories, key=order.__getitem__)
    return level, float(order[level] * 25), "; ".join(reasons), tuple(sorted(evidence_ids))


def _context_completeness(context: BusinessContext | None) -> tuple[float, int]:
    """Fraction of the three impact inputs whose values were actually observed."""
    if context is None:
        return 0.0, 0
    observed = sum(
        (
            context.criticality.state is ObservationState.OBSERVED
            and context.criticality.value not in {None, Criticality.UNKNOWN},
            context.data_classification.state is ObservationState.OBSERVED
            and context.data_classification.value is not None,
            context.internet_exposed.state is ObservationState.OBSERVED
            and context.internet_exposed.value is not None,
        )
    )
    return observed / 3, observed


class MoscaRiskEngine:
    """Canonical per-finding classifier with an independent Mosca timeline output."""

    name = "qrypton-mosca"
    version = "0.5.0"

    def __init__(self, *, parameters: MoscaParameters, id_deriver: IdDeriver) -> None:
        self.parameters = parameters
        self.id_deriver = id_deriver
        self.calculator = MoscaRiskCalculator()

    def _timeline_for(
        self, finding: CryptoFinding, business_context: BusinessContext | None
    ) -> tuple[MoscaParameters, str, str]:
        """Resolve each timeline independently: finding override, asset context, scenario."""
        x_value = finding.mosca_x_data_lifetime_years
        x_source = finding.mosca_x_source if x_value is not None else "unknown"
        if x_value is None and business_context is not None:
            x_value = business_context.mosca_x_data_lifetime_years
            if x_value is not None:
                x_source = "asset"
        if x_value is None:
            x_value = self.parameters.data_shelf_life_years
            x_source = "scenario"

        y_value = finding.mosca_y_migration_years
        y_source = finding.mosca_y_source if y_value is not None else "unknown"
        if y_value is None and business_context is not None:
            y_value = business_context.mosca_y_migration_years
            if y_value is not None:
                y_source = "asset"
        if y_value is None:
            y_value = self.parameters.migration_time_years
            y_source = "scenario"

        return (
            self.parameters.model_copy(
                update={
                    "data_shelf_life_years": x_value,
                    "migration_time_years": y_value,
                }
            ),
            x_source,
            y_source,
        )

    def assess(
        self,
        finding: CryptoFinding,
        business_context: BusinessContext | None,
        policy: RiskPolicy,
        evidence: Sequence[Evidence] | Mapping[str, Evidence] | None = None,
    ) -> RiskAssessment:
        has_classified_criticality = (
            business_context is not None
            and business_context.criticality.state is ObservationState.OBSERVED
            and business_context.criticality.value not in {None, Criticality.UNKNOWN}
        )
        if has_classified_criticality:
            assert business_context is not None
            assert business_context.criticality.value is not None
            business_criticality = business_context.criticality.value
        else:
            business_criticality = Criticality.UNKNOWN
        (
            business_impact_risk,
            business_score,
            business_rationale,
            business_evidence_ids,
        ) = _business_impact(business_context)
        business_impact = (
            Observation[float](
                state=ObservationState.OBSERVED,
                value=business_score,
                basis_evidence_ids=business_evidence_ids,
                rationale=f"Business impact {business_impact_risk.value}: {business_rationale}.",
            )
            if business_impact_risk is not RiskLevel.UNKNOWN
            else Observation[float](
                state=ObservationState.UNKNOWN,
                rationale=(
                    "Business impact is unclassified because business criticality was not "
                    "provided; "
                    "no business score was added to the priority calculation."
                ),
            )
        )

        taxonomy = classify_finding(finding, policy.risk_taxonomy_version)
        obsolescence_val = taxonomy.crypto_score
        quantum_exposure_val = taxonomy.quantum_score
        algorithm_evidence_set = set(finding.algorithm_identification_evidence)
        algorithm_evidence_set.update(finding.algorithm.basis_evidence_ids)
        if finding.algorithm.value is not None:
            algorithm_evidence_set.update(finding.algorithm.value.key_size_bits.basis_evidence_ids)
        algorithm_evidence_ids = tuple(sorted(algorithm_evidence_set))
        score_evidence_ids = tuple(
            sorted(
                set(finding.evidence_ids) | set(business_evidence_ids) | set(algorithm_evidence_ids)
            )
        )
        alg_name = str(
            finding.algorithm.value.canonical_name
            if finding.algorithm and finding.algorithm.value
            else "unknown"
        )
        crypto_risk = taxonomy.crypto_risk
        quantum_risk = taxonomy.quantum_risk
        mosca_applicable = taxonomy.mosca_applicable
        combined_level, priority_score = _priority_and_score(
            crypto_risk, quantum_risk, business_impact_risk
        )
        context_completeness, observed_context_inputs = _context_completeness(business_context)
        assessment_confidence = round(finding.confidence * context_completeness, 4)
        timeline, x_source, y_source = self._timeline_for(finding, business_context)
        mosca_evaluation = self.calculator.evaluate(timeline) if mosca_applicable == "yes" else None
        urgency: Literal["critical", "high", "medium", "low", "not_applicable", "unknown"] = (
            mosca_evaluation.urgency if mosca_evaluation else "not_applicable"
        )
        if mosca_applicable == "unknown":
            urgency = "unknown"
        # Debug Logging (Requirement 3)
        logging.info(
            f"[RiskEngine Debug] Finding {finding.id} ({alg_name}): "
            f"obsolescence={obsolescence_val if obsolescence_val is not None else 'unknown'}, "
            f"quantum_exposure="
            f"{quantum_exposure_val if quantum_exposure_val is not None else 'unknown'}, "
            f"business_impact={business_score:.1f} -> "
            f"priority={combined_level.value} (Mosca urgency={urgency}, score={priority_score:.1f})"
        )

        assessment_id = self.id_deriver.derive(
            namespace="risk",
            tenant_id=finding.tenant_id,
            canonical_payload=canonical_json_bytes(
                {
                    "finding_id": finding.id,
                    "policy_id": policy.profile_id,
                    "policy_version": policy.profile_version,
                    "risk_taxonomy_version": policy.risk_taxonomy_version,
                    "priority_ruleset_version": policy.priority_ruleset_version,
                    "parameters": timeline,
                    "business_criticality": business_criticality,
                    "business_impact_risk": business_impact_risk,
                    "crypto_risk": crypto_risk,
                    "quantum_risk": quantum_risk,
                    "mosca_applicable": mosca_applicable,
                    "business_context_id": business_context.id if business_context else None,
                    "business_evidence_ids": business_evidence_ids,
                    "confidence": finding.confidence,
                    "confidence_reasons": finding.confidence_reasons,
                    "algorithm_identification_confidence": (
                        finding.algorithm_identification_confidence
                    ),
                    "usage_confidence": finding.usage_confidence,
                    "algorithm_identification_evidence": finding.algorithm_identification_evidence,
                    "algorithm_identification_status": finding.algorithm_identification_status,
                    "crypto_role": finding.crypto_role,
                    "algorithm": finding.algorithm,
                }
            ),
        )

        score = (
            Observation[float](
                state=ObservationState.OBSERVED,
                value=priority_score,
                basis_evidence_ids=score_evidence_ids,
                rationale=(
                    "Ordinal score derived from the categorical final-priority rule; "
                    "confidence and Mosca urgency are excluded."
                ),
            )
            if combined_level is not RiskLevel.UNKNOWN
            else Observation[float](
                state=ObservationState.UNKNOWN,
                rationale=(
                    "Final priority is unknown because technical and business evidence "
                    "is insufficient."
                ),
            )
        )
        criticality_label = (
            business_context.criticality.value.value
            if business_context and business_context.criticality.value
            else "unknown"
        )

        return RiskAssessment(
            id=assessment_id,
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            business_context_id=business_context.id if business_context else None,
            score=score,
            level=combined_level,
            mosca_urgency=MoscaUrgency(urgency),
            mosca_applicable=mosca_applicable,
            context_completeness=context_completeness,
            assessment_confidence=assessment_confidence,
            factors=RiskFactors(
                cryptographic_obsolescence=(
                    Observation[float](
                        state=ObservationState.OBSERVED,
                        value=obsolescence_val,
                        basis_evidence_ids=algorithm_evidence_ids,
                        rationale=taxonomy.rationale[0],
                    )
                    if obsolescence_val is not None
                    else Observation[float](
                        state=ObservationState.UNKNOWN,
                        rationale=(
                            "Cryptographic algorithm classification is insufficient "
                            "to determine obsolescence."
                        ),
                    )
                ),
                quantum_exposure=(
                    Observation[float](
                        state=ObservationState.OBSERVED,
                        value=quantum_exposure_val,
                        basis_evidence_ids=algorithm_evidence_ids,
                        rationale=taxonomy.rationale[1],
                    )
                    if quantum_exposure_val is not None
                    else Observation[float](
                        state=ObservationState.UNKNOWN,
                        rationale=(
                            "Quantum applicability is unknown for this algorithm classification."
                        ),
                    )
                ),
                exploitability=Observation[float](state=ObservationState.UNKNOWN),
                business_impact=business_impact,
                evidence_confidence=finding.confidence,
                crypto_risk=crypto_risk,
                quantum_risk=quantum_risk,
                business_impact_risk=business_impact_risk,
                business_criticality=business_criticality,
                risk_taxonomy_version=taxonomy.taxonomy_version,
                priority_ruleset_version=policy.priority_ruleset_version,
                policy_profile_id=policy.profile_id,
                policy_profile_version=policy.profile_version,
                rationale=(
                    (
                        f"Mosca urgency is {urgency}: X={timeline.data_shelf_life_years:g}y "
                        f"(source {x_source}), Y={timeline.migration_time_years:g}y "
                        f"(source {y_source}), "
                        f"Z={timeline.quantum_threat_horizon_years:g} years; "
                        f"margin={mosca_evaluation.time_margin_years:g} years."
                        if mosca_evaluation
                        else (
                            f"Mosca applicability is {mosca_applicable}; "
                            "no timeline urgency was inferred."
                        )
                    ),
                    (
                        f"Mosca inputs: X={timeline.data_shelf_life_years:g}y ({x_source}), "
                        f"Y={timeline.migration_time_years:g}y ({y_source}), "
                        f"Z={timeline.quantum_threat_horizon_years:g}y (scenario)."
                    ),
                    (
                        f"Crypto risk: {crypto_risk.value}; algorithm {alg_name}; "
                        f"role/operation {finding.crypto_role or 'unknown'}; "
                        "identification confidence "
                        f"{finding.algorithm_identification_confidence:.3f}; "
                        f"evidence IDs {', '.join(algorithm_evidence_ids) or 'unavailable'}."
                    ),
                    f"Quantum risk: {quantum_risk.value}; Mosca applicability: {mosca_applicable}.",
                    f"Risk taxonomy: QRYPTON {taxonomy.taxonomy_version}; "
                    f"{' '.join(taxonomy.rationale)}",
                    (
                        f"Business impact: {business_impact.state.value} "
                        f"({business_impact_risk.value}); criticality: "
                        f"{criticality_label}."
                    ),
                    f"Confidence: {finding.confidence:.3f}; reasons: "
                    f"{'; '.join(finding.confidence_reasons)}",
                    (
                        f"Assessment confidence: {assessment_confidence:.4f} = "
                        "detection confidence "
                        f"{finding.confidence:.3f} x context completeness "
                        f"{observed_context_inputs}/3 ({context_completeness:.4f}). "
                        "Context inputs are criticality, data classification, "
                        "and internet exposure."
                    ),
                    (
                        f"Final priority rule: take the highest known crypto/quantum tier; "
                        "business impact alone is capped at Medium and raises an "
                        "existing High tier "
                        f"one level when business impact is High or Critical. Inputs here: "
                        f"crypto={crypto_risk.value}, quantum={quantum_risk.value}, "
                        f"business={business_impact_risk.value}; result={combined_level.value}. "
                        "Confidence and Mosca urgency are not priority inputs."
                    ),
                ),
            ),
            assessed_at=finding.provenance.observed_at,
            engine_name=self.name,
            engine_version=self.version,
            evidence_ids=finding.evidence_ids,
        )

    def persistable_evaluation(
        self,
        finding: CryptoFinding,
        evidence: Sequence[Evidence] | Mapping[str, Evidence] | None = None,
        business_context: BusinessContext | None = None,
    ) -> PersistedMoscaEvaluation:
        """Structured per-finding Mosca timelines persisted with a run."""
        applicable = classify_finding(finding).mosca_applicable
        timeline, x_source, y_source = self._timeline_for(finding, business_context)
        if applicable != "yes":
            return PersistedMoscaEvaluation(
                finding_id=finding.id,
                x_data_lifetime_years=timeline.data_shelf_life_years,
                y_migration_years=timeline.migration_time_years,
                z_crqc_horizon_years=timeline.quantum_threat_horizon_years,
                required_security_years=None,
                time_margin_years=None,
                exposure_score=None,
                urgency="not_applicable" if applicable == "no" else "unknown",
                mosca_applicable=applicable,
                x_source=x_source,
                y_source=y_source,
                z_source="scenario",
                reason=(
                    "Mosca X+Y versus Z applies to classical public-key cryptography only. "
                    f"Recorded inputs: X={timeline.data_shelf_life_years:g}y ({x_source}), "
                    f"Y={timeline.migration_time_years:g}y ({y_source}), "
                    f"Z={timeline.quantum_threat_horizon_years:g}y (scenario)."
                ),
            )
        calc_eval = self.calculator.evaluate(timeline)
        required = calc_eval.required_security_years
        margin = calc_eval.time_margin_years

        del evidence
        urgency = calc_eval.urgency

        return PersistedMoscaEvaluation(
            finding_id=finding.id,
            x_data_lifetime_years=timeline.data_shelf_life_years,
            y_migration_years=timeline.migration_time_years,
            z_crqc_horizon_years=timeline.quantum_threat_horizon_years,
            required_security_years=required,
            time_margin_years=margin,
            exposure_score=calc_eval.exposure_score,
            urgency=urgency,
            mosca_applicable=applicable,
            x_source=x_source,
            y_source=y_source,
            z_source="scenario",
            reason=(
                f"Classical public-key primitive; X={timeline.data_shelf_life_years:g}y, "
                f"Y={timeline.migration_time_years:g}y, "
                f"Z={timeline.quantum_threat_horizon_years:g}y."
            ),
        )
