"""Read-only SQLite adapter for DashboardDataProvider."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from qrypton.contracts.enums import ObservationState, RiskLevel, RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import (
    DashboardRunSummary,
    DashboardRunView,
    ExecutivePosture,
    FindingDetail,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
    SafeRunFailure,
)
from qrypton.ui.provider import DashboardDataProvider

CriticalityColumn = Literal["low", "medium", "high", "critical", "unclassified"]
_URGENCY_TIERS = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFORMATIONAL,
    RiskLevel.UNKNOWN,
)
_CRITICALITY_COLUMNS: tuple[CriticalityColumn, ...] = (
    "low",
    "medium",
    "high",
    "critical",
    "unclassified",
)


class SqliteDashboardDataProvider(DashboardDataProvider):
    """Provides pre-aggregated, read-only DTOs from persisted QRYPTON SQLite data."""

    def __init__(self, store: SqliteRunStore | Path | str) -> None:
        if isinstance(store, Path | str):
            self._store = SqliteRunStore(Path(store))
        else:
            self._store = store

    def list_runs(self, *, tenant_id: str | None = None) -> Sequence[DashboardRunSummary]:
        raw_runs = self._store.list_runs(tenant_id=tenant_id)
        summaries: list[DashboardRunSummary] = []
        for tid, rid, status_str in raw_runs:
            try:
                status = RunStatus(status_str)
            except ValueError:
                status = RunStatus.FAILED
            run = self._store.get_run(tenant_id=tid, run_id=rid)
            if run is None:
                summaries.append(
                    DashboardRunSummary(
                        tenant_id=tid,
                        run_id=rid,
                        status=status,
                        record_state="metadata_only",
                    )
                )
                continue
            summaries.append(
                DashboardRunSummary(
                    tenant_id=tid,
                    run_id=rid,
                    status=run.status,
                    record_state="complete",
                    started_at=run.started_at,
                    completed_at=run.completed_at,
                    total_findings=len(run.findings),
                )
            )
        return tuple(summaries)

    def get_run_view(self, *, tenant_id: str, run_id: str) -> DashboardRunView | None:
        run = self._store.get_run(tenant_id=tenant_id, run_id=run_id)
        if run is None:
            return None

        assessment_by_finding = {item.finding_id: item for item in run.assessments}
        mosca_by_finding = {item.finding_id: item for item in run.mosca_evaluations}

        crit = sum(1 for item in run.assessments if item.level == RiskLevel.CRITICAL)
        high = sum(1 for item in run.assessments if item.level == RiskLevel.HIGH)
        med = sum(1 for item in run.assessments if item.level == RiskLevel.MEDIUM)
        low = sum(1 for item in run.assessments if item.level == RiskLevel.LOW)
        info = sum(1 for item in run.assessments if item.level == RiskLevel.INFORMATIONAL)
        assessed_ids = {item.finding_id for item in run.assessments}
        unassessed = sum(1 for item in run.findings if item.id not in assessed_ids)
        unique_assets = len(
            {item.asset_id for item in run.findings} | {item.asset_id for item in run.evidence}
        )
        scanner_failed = sum(1 for item in run.scanner_results if item.status == "failed")
        scanner_partial = sum(1 for item in run.scanner_results if item.status == "partial")
        posture = ExecutivePosture(
            total_findings=len(run.findings),
            unique_asset_ids=unique_assets,
            critical_findings_count=crit,
            high_findings_count=high,
            medium_findings_count=med,
            low_findings_count=low,
            informational_findings_count=info,
            unassessed_findings_count=unassessed,
            run_status=run.status,
            scanner_failed_count=scanner_failed,
            scanner_partial_count=scanner_partial,
            policy_passed=run.policy_outcome.passed,
            policy_violations=run.policy_outcome.violations,
        )

        inventory_rows: list[InventoryRow] = []
        for finding in run.findings:
            assessment = assessment_by_finding.get(finding.id)
            risk_level = assessment.level if assessment is not None else RiskLevel.UNKNOWN
            risk_score = (
                assessment.score.value
                if assessment is not None and assessment.score.state == ObservationState.OBSERVED
                else None
            )
            alg_name: str | None = None
            alg_family: str | None = None
            key_size: int | None = None
            lifecycle: str | None = None
            algorithm = finding.algorithm.value
            if finding.algorithm.state == ObservationState.OBSERVED and algorithm is not None:
                alg_name = algorithm.canonical_name
                alg_family = algorithm.family.value
                lifecycle = algorithm.lifecycle_status.value
                if algorithm.key_size_bits.state == ObservationState.OBSERVED:
                    key_size = algorithm.key_size_bits.value
            if (
                key_size is None
                and finding.key_material.state == ObservationState.OBSERVED
                and finding.key_material.value is not None
                and finding.key_material.value.size_bits.state == ObservationState.OBSERVED
            ):
                key_size = finding.key_material.value.size_bits.value
            inventory_rows.append(
                InventoryRow(
                    finding_id=finding.id,
                    category=finding.category,
                    algorithm_name=alg_name,
                    algorithm_family=alg_family,
                    key_size_bits=key_size,
                    lifecycle_status=lifecycle,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    confidence=finding.confidence,
                    evidence_count=len(finding.evidence_ids),
                    first_observed_at=finding.first_observed_at,
                    last_observed_at=finding.last_observed_at,
                )
            )

        heatmap_dict: dict[tuple[RiskLevel, CriticalityColumn], list[str]] = {
            (urgency, column): [] for urgency in _URGENCY_TIERS for column in _CRITICALITY_COLUMNS
        }
        for finding in run.findings:
            assessment = assessment_by_finding.get(finding.id)
            urgency = assessment.level if assessment is not None else RiskLevel.UNKNOWN
            if urgency not in _URGENCY_TIERS:
                urgency = RiskLevel.UNKNOWN
            heatmap_dict[(urgency, "unclassified")].append(finding.id)
        heatmap_cells = tuple(
            RiskHeatmapCell(
                mosca_urgency=urgency,
                business_criticality=column,
                finding_count=len(ids),
                finding_ids=tuple(ids),
            )
            for (urgency, column), ids in heatmap_dict.items()
        )

        mosca_points: list[MoscaPoint] = []
        for finding in run.findings:
            assessment = assessment_by_finding.get(finding.id)
            stored = mosca_by_finding.get(finding.id)
            if stored is not None:
                mosca_points.append(
                    MoscaPoint(
                        finding_id=finding.id,
                        urgency=RiskLevel(stored.urgency),
                        exposure_score=stored.exposure_score,
                        x_data_lifetime_years=stored.x_data_lifetime_years,
                        y_migration_years=stored.y_migration_years,
                        z_crqc_horizon_years=stored.z_crqc_horizon_years,
                        required_security_years=stored.required_security_years,
                        time_margin_years=stored.time_margin_years,
                        timeline_state="persisted",
                    )
                )
                continue
            mosca_points.append(
                MoscaPoint(
                    finding_id=finding.id,
                    urgency=assessment.level if assessment is not None else RiskLevel.UNKNOWN,
                    exposure_score=(
                        assessment.score.value
                        if assessment is not None
                        and assessment.score.state == ObservationState.OBSERVED
                        else None
                    ),
                    timeline_state="unavailable",
                )
            )

        plan_by_finding = {item.finding_id: item for item in run.recommendation_plans}
        roadmap_rows: list[RoadmapRow] = []
        for rec in run.recommendations:
            plan = plan_by_finding.get(rec.finding_id)
            if plan is not None:
                target_algs = tuple(
                    algorithm.canonical_name for algorithm in plan.target_algorithms
                )
                hybrid = plan.hybrid_mode.value
                blockers = plan.rationale.blocking_conditions
                refs = tuple(dict.fromkeys((*plan.standard_references, *rec.nist_references)))
                role = plan.role.value
            else:
                target_algs = (
                    (rec.replacement_algorithm.value.canonical_name,)
                    if rec.replacement_algorithm.state == ObservationState.OBSERVED
                    and rec.replacement_algorithm.value is not None
                    else ()
                )
                hybrid = None
                blockers = ()
                refs = rec.nist_references
                role = None
            roadmap_rows.append(
                RoadmapRow(
                    finding_id=rec.finding_id,
                    priority=rec.priority,
                    action=rec.action,
                    role=role,
                    target_algorithms=target_algs,
                    hybrid_mode=hybrid,
                    blocking_conditions=blockers,
                    standards_references=refs,
                )
            )
        roadmap_rows.sort(key=lambda item: (item.priority, item.finding_id))

        summary = DashboardRunSummary(
            tenant_id=run.tenant_id,
            run_id=run.run_id,
            status=run.status,
            record_state="complete",
            started_at=run.started_at,
            completed_at=run.completed_at,
            total_findings=len(run.findings),
        )
        return DashboardRunView(
            summary=summary,
            posture=posture,
            inventory=tuple(inventory_rows),
            heatmap_cells=heatmap_cells,
            mosca_points=tuple(mosca_points),
            roadmap=tuple(roadmap_rows),
            has_cbom=self._store.get_cbom(tenant_id=tenant_id, run_id=run_id) is not None,
            cbom_digest=run.cbom_digest,
        )

    def get_finding_detail(
        self, *, tenant_id: str, run_id: str, finding_id: str
    ) -> FindingDetail | None:
        run = self._store.get_run(tenant_id=tenant_id, run_id=run_id)
        if run is None:
            return None
        finding = next((item for item in run.findings if item.id == finding_id), None)
        if finding is None:
            return None
        assessment = next((item for item in run.assessments if item.finding_id == finding_id), None)
        recommendations = tuple(
            item for item in run.recommendations if item.finding_id == finding_id
        )
        evidence = tuple(item for item in run.evidence if item.id in finding.evidence_ids)
        failures = tuple(
            SafeRunFailure(
                stage=item.stage,
                error_code=item.error_code,
                scanner_name=item.scanner_name,
                message=item.message,
            )
            for item in run.failures
        )
        return FindingDetail(
            finding=finding,
            assessment=assessment,
            recommendations=recommendations,
            evidence_provenance=evidence,
            failures=failures,
        )

    def get_persisted_cbom(self, *, tenant_id: str, run_id: str) -> bytes | None:
        return self._store.get_cbom(tenant_id=tenant_id, run_id=run_id)
