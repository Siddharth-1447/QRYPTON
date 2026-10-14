"""Read-only SQLite adapter for DashboardDataProvider."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from qrypton.contracts.crypto_taxonomy import is_post_quantum_finding
from qrypton.contracts.enums import (
    Criticality,
    MoscaUrgency,
    ObservationState,
    RiskLevel,
    RunStatus,
)
from qrypton.contracts.evidence_quality import classify_evidence, classify_finding_evidence
from qrypton.contracts.identity import finding_identity_label
from qrypton.contracts.models import Recommendation
from qrypton.contracts.remediation import rank_remediation
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import (
    DashboardRunSummary,
    DashboardRunView,
    EvidenceAuthenticity,
    ExecutivePosture,
    FindingDetail,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
    SafeRunFailure,
)
from qrypton.ui.investigation import detail_context, inventory_context
from qrypton.ui.provider import DashboardDataProvider

if TYPE_CHECKING:
    from qrypton.ports.storage import PersistedRun

CriticalityColumn = Literal["low", "medium", "high", "critical", "unclassified"]
_URGENCY_TIERS = (
    MoscaUrgency.CRITICAL,
    MoscaUrgency.HIGH,
    MoscaUrgency.MEDIUM,
    MoscaUrgency.LOW,
    MoscaUrgency.NOT_APPLICABLE,
    MoscaUrgency.UNKNOWN,
)
_CRITICALITY_COLUMNS: tuple[CriticalityColumn, ...] = (
    "low",
    "medium",
    "high",
    "critical",
    "unclassified",
)


def _business_criticality(context: object | None) -> CriticalityColumn:
    if context is None:
        return "unclassified"
    observation = getattr(context, "criticality", None)
    if (
        observation is not None
        and observation.state is ObservationState.OBSERVED
        and observation.value
        in {Criticality.LOW, Criticality.MEDIUM, Criticality.HIGH, Criticality.CRITICAL}
    ):
        return cast(CriticalityColumn, observation.value.value)
    return "unclassified"


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
        return self.run_view_from_result(run)

    @staticmethod
    def run_view_from_result(run: PersistedRun) -> DashboardRunView:
        """Build the dashboard/report DTO from an already deserialized snapshot."""
        finding_ids = {item.id for item in run.findings}
        if len(finding_ids) != len(run.findings):
            raise ValueError("persisted run contains duplicate canonical finding IDs")
        linked_assessments = tuple(
            item for item in run.assessments if item.finding_id in finding_ids
        )
        assessment_ids = tuple(item.finding_id for item in linked_assessments)
        if len(set(assessment_ids)) != len(assessment_ids):
            raise ValueError("persisted run contains multiple risk assessments for one finding")
        linked_mosca = tuple(
            item for item in run.mosca_evaluations if item.finding_id in finding_ids
        )
        mosca_ids = tuple(item.finding_id for item in linked_mosca)
        if len(set(mosca_ids)) != len(mosca_ids):
            raise ValueError("persisted run contains multiple Mosca evaluations for one finding")
        assessment_by_finding = {item.finding_id: item for item in linked_assessments}
        mosca_by_finding = {item.finding_id: item for item in linked_mosca}

        persisted_assessments = tuple(assessment_by_finding.values())
        crit = sum(1 for item in persisted_assessments if item.level == RiskLevel.CRITICAL)
        high = sum(1 for item in persisted_assessments if item.level == RiskLevel.HIGH)
        med = sum(1 for item in persisted_assessments if item.level == RiskLevel.MEDIUM)
        low = sum(1 for item in persisted_assessments if item.level == RiskLevel.LOW)
        info = sum(1 for item in persisted_assessments if item.level == RiskLevel.INFORMATIONAL)
        unknown = sum(1 for item in persisted_assessments if item.level == RiskLevel.UNKNOWN)
        assessed_ids = set(assessment_by_finding)
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
            unknown_findings_count=unknown,
            unassessed_findings_count=unassessed,
            run_status=run.status,
            scanner_failed_count=scanner_failed,
            scanner_partial_count=scanner_partial,
            policy_passed=run.policy_outcome.passed,
            policy_violations=run.policy_outcome.violations,
        )

        evidence_by_id = {e.id: e for e in run.evidence}
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
            business_context = run.finding_business_contexts.get(finding.id, run.business_context)
            business_criticality = _business_criticality(business_context)
            inventory_rows.append(
                InventoryRow(
                    **inventory_context(
                        finding, run, evidence_by_id, mosca_by_finding.get(finding.id)
                    ),
                    finding_id=finding.id,
                    category=finding.category,
                    algorithm_name=alg_name,
                    algorithm_family=alg_family,
                    algorithm_variant=finding.algorithm_variant,
                    crypto_role=finding.crypto_role,
                    library_name=(
                        finding.library.value.name.value
                        if finding.library.state == ObservationState.OBSERVED
                        and finding.library.value is not None
                        and finding.library.value.name.state == ObservationState.OBSERVED
                        else None
                    ),
                    identity_status=finding.algorithm_identification_status.value,
                    identity_label=finding_identity_label(finding),
                    identification_confidence=finding.identification_confidence,
                    usage_confidence=finding.usage_confidence,
                    confidence_reasons=finding.confidence_reasons,
                    key_size_bits=key_size,
                    lifecycle_status=lifecycle,
                    quantum_resistant=is_post_quantum_finding(finding),
                    risk_level=risk_level,
                    risk_assessment_state="assessed" if assessment is not None else "unassessed",
                    business_criticality=business_criticality,
                    risk_score=risk_score,
                    confidence=finding.confidence,
                    evidence_count=len(finding.evidence_ids),
                    first_observed_at=finding.first_observed_at,
                    last_observed_at=finding.last_observed_at,
                )
            )

        inventory_rows = rank_remediation(inventory_rows)
        remediation_ranks = {row.finding_id: row.remediation_rank for row in inventory_rows}
        heatmap_dict: dict[tuple[MoscaUrgency, CriticalityColumn], list[str]] = {
            (urgency, column): [] for urgency in _URGENCY_TIERS for column in _CRITICALITY_COLUMNS
        }
        for finding in run.findings:
            assessment = assessment_by_finding.get(finding.id)
            stored = mosca_by_finding.get(finding.id)
            business_context = run.finding_business_contexts.get(finding.id, run.business_context)
            finding_criticality = _business_criticality(business_context)

            # Rows are persisted Mosca urgency (per-finding timelines), not the
            # final priority. Keep the temporal dimension in its own vocabulary.
            urgency = MoscaUrgency.UNKNOWN
            if stored is not None and stored.urgency in MoscaUrgency._value2member_map_:
                urgency = MoscaUrgency(stored.urgency)
            else:
                if assessment is not None and assessment.mosca_urgency.value in {
                    item.value for item in _URGENCY_TIERS
                }:
                    urgency = assessment.mosca_urgency
            heatmap_dict[(urgency, finding_criticality)].append(finding.id)
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
                        urgency=(
                            MoscaUrgency(stored.urgency)
                            if stored.urgency in MoscaUrgency._value2member_map_
                            else MoscaUrgency.UNKNOWN
                        ),
                        mosca_applicable=stored.mosca_applicable,
                        exposure_score=stored.exposure_score,
                        x_data_lifetime_years=stored.x_data_lifetime_years,
                        y_migration_years=stored.y_migration_years,
                        z_crqc_horizon_years=stored.z_crqc_horizon_years,
                        required_security_years=stored.required_security_years,
                        time_margin_years=stored.time_margin_years,
                        timeline_state=(
                            "persisted"
                            if all(
                                value is not None
                                for value in (
                                    stored.x_data_lifetime_years,
                                    stored.y_migration_years,
                                    stored.z_crqc_horizon_years,
                                )
                            )
                            else "unavailable"
                        ),
                    )
                )
                continue
            mosca_points.append(
                MoscaPoint(
                    finding_id=finding.id,
                    urgency=(
                        assessment.mosca_urgency if assessment is not None else MoscaUrgency.UNKNOWN
                    ),
                    mosca_applicable=(
                        assessment.mosca_applicable if assessment is not None else "unknown"
                    ),
                    exposure_score=None,
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
        roadmap_rows.sort(key=lambda item: (
            remediation_ranks.get(item.finding_id) or len(inventory_rows) + 1,
            -item.priority, item.finding_id, item.action,
        ))

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
            has_cbom=run.cbom is not None,
            cbom_digest=run.cbom_digest,
        )

    def get_finding_detail(
        self, *, tenant_id: str, run_id: str, finding_id: str
    ) -> FindingDetail | None:
        run = self._store.get_run(tenant_id=tenant_id, run_id=run_id)
        if run is None:
            return None
        return self.finding_details_from_result(run, finding_ids={finding_id}).get(finding_id)

    @staticmethod
    def finding_details_from_result(
        run: PersistedRun,
        *,
        finding_ids: set[str] | None = None,
    ) -> dict[str, FindingDetail]:
        """Index the snapshot once; no per-finding queries or full-run scans."""
        assessment_by_finding = {item.finding_id: item for item in run.assessments}
        mosca_by_finding = {item.finding_id: item for item in run.mosca_evaluations}
        evidence_by_id = {item.id: item for item in run.evidence}
        recs_by_finding: dict[str, list[Recommendation]] = defaultdict(list)
        for recommendation in run.recommendations:
            recs_by_finding[recommendation.finding_id].append(recommendation)
        failures = tuple(
            SafeRunFailure(
                stage=item.stage,
                error_code=item.error_code,
                scanner_name=item.scanner_name,
                message=item.message,
            )
            for item in run.failures
        )
        details: dict[str, FindingDetail] = {}
        for finding in run.findings:
            if finding_ids is not None and finding.id not in finding_ids:
                continue
            assessment = assessment_by_finding.get(finding.id)
            recommendations = tuple(recs_by_finding[finding.id])
            evidence = tuple(
                evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id
            )
            quality, summary, confidence_applicable = classify_finding_evidence(
                evidence, scanner_name=finding.provenance.scanner_name
            )
            business_context = run.finding_business_contexts.get(finding.id, run.business_context)
            mosca = mosca_by_finding.get(finding.id)
            mosca_point = None
            if mosca is not None:
                urgency = (
                    MoscaUrgency(mosca.urgency)
                    if mosca.urgency in MoscaUrgency._value2member_map_
                    else MoscaUrgency.UNKNOWN
                )
                mosca_point = MoscaPoint(
                    finding_id=finding.id,
                    urgency=urgency,
                    mosca_applicable=mosca.mosca_applicable,
                    exposure_score=mosca.exposure_score,
                    x_data_lifetime_years=mosca.x_data_lifetime_years,
                    y_migration_years=mosca.y_migration_years,
                    z_crqc_horizon_years=mosca.z_crqc_horizon_years,
                    required_security_years=mosca.required_security_years,
                    x_source=mosca.x_source,
                    time_margin_years=mosca.time_margin_years,
                    timeline_state=(
                        "persisted"
                        if all(
                            value is not None
                            for value in (
                                mosca.x_data_lifetime_years,
                                mosca.y_migration_years,
                                mosca.z_crqc_horizon_years,
                            )
                        )
                        else "unavailable"
                    ),
                )
            details[finding.id] = FindingDetail(
                finding=finding,
                investigation_context=detail_context(business_context),
                application_name=run.asset.name if run.asset else None,
                application_run_id=run.run_id,
                evidence_quality={item.id: classify_evidence(item)[0] for item in evidence},
                assessment=assessment,
                business_criticality=_business_criticality(business_context),
                mosca=mosca_point,
                recommendations=recommendations,
                evidence_provenance=evidence,
                failures=failures,
                evidence_authenticity=EvidenceAuthenticity(
                    quality=quality,
                    summary=summary,
                    confidence_applicable=confidence_applicable,
                ),
            )
        return details

    def get_persisted_cbom(self, *, tenant_id: str, run_id: str) -> bytes | None:
        return self._store.get_cbom(tenant_id=tenant_id, run_id=run_id)
