"""Dependency container and deterministic Phase 8 execution service."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, cast
from uuid import NAMESPACE_URL, uuid5

from qrypton.application.logging import SafeLogger
from qrypton.application.schemas import (
    PolicyOutcome,
    RunFailure,
    RunRequest,
    RunResult,
    ScannerExecutionResult,
)
from qrypton.contracts.enums import RiskLevel, RunStatus
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    CryptoFinding,
    Evidence,
    PersistedMoscaEvaluation,
    Provenance,
    Recommendation,
    RiskAssessment,
)
from qrypton.exporters.cyclonedx_1_6 import CbomExportContext
from qrypton.ports.correlation import CorrelationEngine
from qrypton.ports.exporters import CBOMExporter
from qrypton.ports.normalizers import EvidenceNormalizer, FindingNormalizer
from qrypton.ports.recommendations import RecommendationEngine
from qrypton.ports.risk import RiskEngine
from qrypton.ports.scanners import ScannerPlugin, ScanRequest
from qrypton.ports.storage import RunStore
from qrypton.recommendations.schemas import PqcRecommendationPlan


class Clock(Protocol):
    def now(self) -> datetime: ...


class FindingCapableNormalizer(EvidenceNormalizer, FindingNormalizer, Protocol):
    pass


@dataclass(frozen=True, slots=True)
class QryptonServices:
    """Explicit dependency composition with no concrete adapters or UI imports."""

    scanners: tuple[ScannerPlugin, ...]
    evidence_normalizers: tuple[EvidenceNormalizer, ...]
    finding_normalizers: tuple[FindingNormalizer, ...]
    risk_engine: RiskEngine
    recommendation_engine: RecommendationEngine
    cbom_exporter: CBOMExporter
    correlation_engine: CorrelationEngine
    store: RunStore
    id_deriver: IdDeriver
    clock: Clock
    logger: SafeLogger


class QryptonOrchestrator:
    """Coordinates adapters without making scanner output ordering observable."""

    def __init__(self, services: QryptonServices, *, max_concurrency: int = 1) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self._services = services
        self._max_concurrency = max_concurrency

    async def run(self, request: RunRequest) -> RunResult:
        run_id = self._run_id(request)
        started_at = self._services.clock.now()
        self._services.store.begin_run(request, run_id=run_id)
        scanners = self._eligible_scanners(request)
        if not scanners:
            return self._finish_failure(
                request, run_id, started_at, "scanner", "no_eligible_scanner"
            )
        self._services.logger.event(
            "run_started",
            fields={"run_id": run_id, "tenant_id": request.tenant_id, "stage": "scanning"},
        )
        semaphore = asyncio.Semaphore(min(self._max_concurrency, len(scanners)))
        executions = await asyncio.gather(
            *(self._scan_one(scanner, request, semaphore) for scanner in scanners)
        )
        scanner_results = tuple(
            sorted((item[0] for item in executions), key=lambda item: item.scanner_name)
        )
        evidence = tuple(
            sorted((item for _, items, _ in executions for item in items), key=lambda item: item.id)
        )
        candidates = tuple(
            sorted((item for _, _, items in executions for item in items), key=lambda item: item.id)
        )
        failures = tuple(
            sorted(
                (item.failure for item in scanner_results if item.failure is not None),
                key=lambda item: (item.stage, item.scanner_name or ""),
            )
        )
        if scanner_results and all(item.status == "failed" for item in scanner_results):
            result = RunResult(
                run_id=run_id,
                tenant_id=request.tenant_id,
                status=RunStatus.FAILED,
                started_at=started_at,
                completed_at=self._services.clock.now(),
                scanner_results=scanner_results,
                failures=failures,
                policy_outcome=PolicyOutcome(passed=False, violations=("all_scanners_failed",)),
            )
            self._services.store.finalize_run(result)
            return result
        try:
            provenance = self._provenance(request, "qrypton-orchestrator", "1.0.0")
            findings = tuple(
                self._services.correlation_engine.correlate(
                    candidates,
                    evidence=evidence,
                    asset=request.asset,
                    target=request.target,
                    provenance=provenance,
                    id_deriver=self._services.id_deriver,
                )
            )
        except Exception:
            return self._finish_partial(
                request,
                run_id,
                started_at,
                scanner_results,
                evidence,
                (),
                failures + (self._failure("correlation", "correlation_failed"),),
            )
        (
            assessments,
            recommendations,
            plans,
            mosca_evaluations,
            downstream_failures,
        ) = self._assess_and_recommend(request, findings)
        failures += downstream_failures
        status = (
            RunStatus.PARTIAL
            if failures or any(item.status == "partial" for item in scanner_results)
            else RunStatus.COMPLETED
        )
        cbom: bytes | None = None
        try:
            context = CbomExportContext(
                serial_number=uuid5(NAMESPACE_URL, run_id), generated_at=request.reference_time
            )
            cbom = self._services.cbom_exporter.export(
                asset=request.asset,
                findings=findings,
                assessments=assessments,
                recommendations=recommendations,
                recommendation_plans=plans,
                evidence=evidence,
                context=context,
            )
        except Exception:
            failures += (self._failure("export", "cbom_export_failed"),)
            status = RunStatus.PARTIAL
        outcome = self._policy_outcome(request, status, scanner_results, assessments)
        result = RunResult(
            run_id=run_id,
            tenant_id=request.tenant_id,
            status=status,
            started_at=started_at,
            completed_at=self._services.clock.now(),
            scanner_results=scanner_results,
            failures=tuple(sorted(failures, key=lambda item: (item.stage, item.error_code))),
            evidence=tuple(
                sorted({item.id: item for item in evidence}.values(), key=lambda item: item.id)
            ),
            findings=tuple(sorted(findings, key=lambda item: item.id)),
            assessments=assessments,
            recommendations=recommendations,
            recommendation_plans=plans,
            mosca_evaluations=mosca_evaluations,
            cbom=cbom,
            cbom_digest=(
                f"sha256:{hashlib.sha256(cbom).hexdigest()}" if cbom is not None else None
            ),
            policy_outcome=outcome,
        )
        self._services.store.persist_artifacts(result)
        self._services.store.finalize_run(result)
        self._services.logger.event(
            "run_finished",
            fields={
                "run_id": run_id,
                "tenant_id": request.tenant_id,
                "status": status.value,
                "count": len(findings),
            },
        )
        return result

    def _eligible_scanners(self, request: RunRequest) -> tuple[ScannerPlugin, ...]:
        names = set(request.selected_scanners)
        return tuple(
            sorted(
                (
                    scanner
                    for scanner in self._services.scanners
                    if request.target.kind in scanner.supported_targets
                    and (not names or scanner.name in names)
                ),
                key=lambda scanner: scanner.name,
            )
        )

    async def _scan_one(
        self, scanner: ScannerPlugin, request: RunRequest, semaphore: asyncio.Semaphore
    ) -> tuple[ScannerExecutionResult, tuple[Evidence, ...], tuple[CryptoFinding, ...]]:
        async with semaphore:
            raw = []
            try:
                scan_request = ScanRequest(
                    tenant_id=request.tenant_id,
                    target=request.target,
                    limits=request.limits,
                    correlation_id=self._run_id(request),
                )
                async for item in scanner.scan(scan_request):
                    raw.append(item)
                normalizer = self._normalizer_for(scanner)
                provenance = self._provenance(request, scanner.name, scanner.version)
                evidence = tuple(
                    sorted(
                        {
                            normalizer.normalize(
                                item,
                                asset=request.asset,
                                target=request.target,
                                provenance=provenance,
                                id_deriver=self._services.id_deriver,
                            ).id: normalizer.normalize(
                                item,
                                asset=request.asset,
                                target=request.target,
                                provenance=provenance,
                                id_deriver=self._services.id_deriver,
                            )
                            for item in raw
                        }.values(),
                        key=lambda item: item.id,
                    )
                )
                findings = tuple(
                    sorted(
                        normalizer.derive_findings(
                            evidence,
                            asset=request.asset,
                            target=request.target,
                            provenance=provenance,
                            id_deriver=self._services.id_deriver,
                        ),
                        key=lambda item: item.id,
                    )
                )
                partial = bool(getattr(scanner, "partial", False))
                result = ScannerExecutionResult(
                    scanner_name=scanner.name,
                    scanner_version=scanner.version,
                    status="partial" if partial else "completed",
                    evidence_ids=tuple(item.id for item in evidence),
                    finding_ids=tuple(item.id for item in findings),
                    diagnostics=("scanner_limited",) if partial else (),
                )
            except Exception:
                result = ScannerExecutionResult(
                    scanner_name=scanner.name,
                    scanner_version=scanner.version,
                    status="failed",
                    failure=self._failure("scanner", "scanner_failed", scanner.name),
                    diagnostics=("scanner_failed",),
                )
                evidence, findings = (), ()
            self._services.store.persist_scanner_result(result)
            return result, evidence, findings

    def _normalizer_for(self, scanner: ScannerPlugin) -> FindingCapableNormalizer:
        token = scanner.name.removeprefix("qrypton-")
        matches = [item for item in self._services.evidence_normalizers if token in item.name]
        if not matches:
            raise ValueError("no compatible normalizer")
        normalizer = matches[0]
        if not hasattr(normalizer, "derive_findings"):
            raise ValueError("normalizer does not derive findings")
        return cast(FindingCapableNormalizer, normalizer)

    def _assess_and_recommend(
        self, request: RunRequest, findings: tuple[CryptoFinding, ...]
    ) -> tuple[
        tuple[RiskAssessment, ...],
        tuple[Recommendation, ...],
        tuple[PqcRecommendationPlan, ...],
        tuple[PersistedMoscaEvaluation, ...],
        tuple[RunFailure, ...],
    ]:
        assessments: list[RiskAssessment] = []
        recommendations: list[Recommendation] = []
        plans: list[PqcRecommendationPlan] = []
        mosca_evaluations: list[PersistedMoscaEvaluation] = []
        failures = []
        for finding in findings:
            try:
                assessment = self._services.risk_engine.assess(
                    finding, request.business_context, request.risk_policy
                )
                assessments.append(assessment)
                persistable = getattr(self._services.risk_engine, "persistable_evaluation", None)
                if persistable is not None:
                    mosca_evaluations.append(persistable(finding))
                engine = self._services.recommendation_engine
                if hasattr(engine, "plan"):
                    planned = engine.plan(finding, assessment, request.recommendation_policy)
                    recommendations.extend(planned.recommendations)
                    plans.append(planned.plan)
                else:
                    recommendations.extend(
                        engine.recommend(finding, assessment, request.recommendation_policy)
                    )
            except Exception:
                failures.append(self._failure("risk", "finding_processing_failed"))
        return (
            tuple(sorted(assessments, key=lambda item: item.id)),
            tuple(sorted(recommendations, key=lambda item: item.id)),
            tuple(sorted(plans, key=lambda item: item.finding_id)),
            tuple(sorted(mosca_evaluations, key=lambda item: item.finding_id)),
            tuple(failures),
        )

    def _run_id(self, request: RunRequest) -> str:
        scanners = tuple(
            sorted(
                (scanner.name, scanner.version)
                for scanner in self._services.scanners
                if not request.selected_scanners or scanner.name in request.selected_scanners
            )
        )
        return self._services.id_deriver.derive(
            namespace="run",
            tenant_id=request.tenant_id,
            canonical_payload=canonical_json_bytes(
                {
                    "schema": 1,
                    "target_id": request.target.id,
                    "target_digest": request.target.content_digest,
                    "config_digest": request.config_digest,
                    "limits": request.limits,
                    "scanners": scanners,
                    "risk_policy": request.risk_policy,
                    "recommendation_policy": request.recommendation_policy,
                    "business_context_id": request.business_context.id
                    if request.business_context
                    else None,
                    "gate": request.policy_gate,
                }
            ),
        )

    def _provenance(self, request: RunRequest, name: str, version: str) -> Provenance:
        return Provenance(
            scanner_name=name,
            scanner_version=version,
            scanner_config_digest=request.config_digest,
            observed_at=request.reference_time,
            source_digest=request.target.content_digest.value,
        )

    @staticmethod
    def _failure(
        stage: Literal[
            "scanner", "normalization", "correlation", "risk", "recommendation", "export", "store"
        ],
        code: str,
        scanner: str | None = None,
    ) -> RunFailure:
        return RunFailure(
            stage=stage,
            error_code=code,
            scanner_name=scanner,
            message="stage failed; inspect sanitized diagnostics",
        )

    def _policy_outcome(
        self,
        request: RunRequest,
        status: RunStatus,
        scanners: tuple[ScannerExecutionResult, ...],
        assessments: tuple[RiskAssessment, ...],
    ) -> PolicyOutcome:
        violations: list[str] = []
        if status is RunStatus.PARTIAL and request.policy_gate.fail_on_partial:
            violations.append("partial_run")
        if (
            any(item.status == "failed" for item in scanners)
            and request.policy_gate.fail_on_scanner_failure
        ):
            violations.append("scanner_failure")
        rank = {
            RiskLevel.INFORMATIONAL: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
            RiskLevel.UNKNOWN: 4,
        }
        if any(
            rank[item.level] > rank[request.policy_gate.max_allowed_risk] for item in assessments
        ):
            violations.append("risk_threshold_exceeded")
        return PolicyOutcome(passed=not violations, violations=tuple(violations))

    def _finish_failure(
        self,
        request: RunRequest,
        run_id: str,
        started_at: datetime,
        stage: Literal[
            "scanner", "normalization", "correlation", "risk", "recommendation", "export", "store"
        ],
        code: str,
    ) -> RunResult:
        result = RunResult(
            run_id=run_id,
            tenant_id=request.tenant_id,
            status=RunStatus.FAILED,
            started_at=started_at,
            completed_at=self._services.clock.now(),
            failures=(self._failure(stage, code),),
            policy_outcome=PolicyOutcome(passed=False, violations=(code,)),
        )
        self._services.store.finalize_run(result)
        return result

    def _finish_partial(
        self,
        request: RunRequest,
        run_id: str,
        started_at: datetime,
        scanners: tuple[ScannerExecutionResult, ...],
        evidence: tuple[Evidence, ...],
        findings: tuple[CryptoFinding, ...],
        failures: tuple[RunFailure, ...],
    ) -> RunResult:
        result = RunResult(
            run_id=run_id,
            tenant_id=request.tenant_id,
            status=RunStatus.PARTIAL,
            started_at=started_at,
            completed_at=self._services.clock.now(),
            scanner_results=scanners,
            failures=failures,
            evidence=evidence,
            findings=findings,
            policy_outcome=PolicyOutcome(
                passed=not request.policy_gate.fail_on_partial, violations=("partial_run",)
            ),
        )
        self._services.store.finalize_run(result)
        return result
