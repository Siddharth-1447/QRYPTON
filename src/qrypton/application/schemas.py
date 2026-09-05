"""Immutable request and result contracts for a complete QRYPTON run."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.contracts.models import (
    Asset,
    BusinessContext,
    CryptoFinding,
    DomainModel,
    Evidence,
    PersistedMoscaEvaluation,
    Recommendation,
    RiskAssessment,
    ScanTarget,
)
from qrypton.contracts.primitives import (
    EntityId,
    ScannerVersion,
    Sha256Digest,
    TenantId,
    UtcDateTime,
)
from qrypton.policies.pqc import PqcRecommendationPolicy, RiskPolicy
from qrypton.ports.scanners import ScanLimits
from qrypton.recommendations.schemas import PqcRecommendationPlan


class PolicyGate(DomainModel):
    max_allowed_risk: RiskLevel = RiskLevel.MEDIUM
    fail_on_partial: bool = True
    fail_on_scanner_failure: bool = True


class RunFailure(DomainModel):
    stage: Literal[
        "scanner", "normalization", "correlation", "risk", "recommendation", "export", "store"
    ]
    error_code: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    scanner_name: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    message: Annotated[str, Field(min_length=1, max_length=256)]


class ScannerExecutionResult(DomainModel):
    scanner_name: Annotated[str, Field(min_length=1, max_length=128)]
    scanner_version: ScannerVersion
    status: Literal["completed", "partial", "failed"]
    evidence_ids: tuple[EntityId, ...] = ()
    finding_ids: tuple[EntityId, ...] = ()
    diagnostics: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = ()
    failure: RunFailure | None = None

    @model_validator(mode="after")
    def validate_failure(self) -> ScannerExecutionResult:
        if (self.status == "failed") != (self.failure is not None):
            raise ValueError("failed scanner results require a failure and only failures carry one")
        return self


class RunRequest(DomainModel):
    tenant_id: TenantId
    asset: Asset
    target: ScanTarget
    limits: ScanLimits
    selected_scanners: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    risk_policy: RiskPolicy
    recommendation_policy: PqcRecommendationPolicy
    business_context: BusinessContext | None = None
    config_digest: Sha256Digest
    policy_gate: PolicyGate = Field(default_factory=PolicyGate)
    reference_time: UtcDateTime

    @model_validator(mode="after")
    def validate_scope(self) -> RunRequest:
        if self.asset.tenant_id != self.tenant_id or self.target.tenant_id != self.tenant_id:
            raise ValueError("asset and target must belong to the request tenant")
        if self.target.asset_id != self.asset.id:
            raise ValueError("target must belong to the request asset")
        if self.business_context and self.business_context.asset_id != self.asset.id:
            raise ValueError("business context must belong to the request asset")
        return self


class PolicyOutcome(DomainModel):
    passed: bool
    violations: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = ()


class RunResult(DomainModel):
    run_id: EntityId
    tenant_id: TenantId
    status: RunStatus
    started_at: UtcDateTime
    completed_at: UtcDateTime | None = None
    scanner_results: tuple[ScannerExecutionResult, ...] = ()
    failures: tuple[RunFailure, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[CryptoFinding, ...] = ()
    assessments: tuple[RiskAssessment, ...] = ()
    recommendations: tuple[Recommendation, ...] = ()
    recommendation_plans: tuple[PqcRecommendationPlan, ...] = ()
    mosca_evaluations: tuple[PersistedMoscaEvaluation, ...] = ()
    cbom: bytes | None = None
    cbom_digest: Sha256Digest | None = None
    policy_outcome: PolicyOutcome
