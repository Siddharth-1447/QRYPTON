"""Fixtures and test factories for UI testing."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import HttpUrl, TypeAdapter

from qrypton.application.schemas import PolicyOutcome, RunResult, ScannerExecutionResult
from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    EvidenceKind,
    ObservationState,
    RiskLevel,
    RunStatus,
)
from qrypton.contracts.models import (
    Algorithm,
    CryptoFinding,
    Evidence,
    EvidenceLocation,
    Observation,
    PersistedMoscaEvaluation,
    Provenance,
    Recommendation,
    RiskAssessment,
    RiskFactors,
)
from qrypton.recommendations.schemas import (
    CompatibilityFactors,
    CryptoRole,
    HybridMode,
    PqcRecommendationPlan,
    RecommendationBasis,
    RecommendationRationale,
)
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import DashboardRunSummary, DashboardRunView, FindingDetail
from qrypton.ui.provider import DashboardDataProvider


def sample_provenance() -> Provenance:
    return Provenance(
        scanner_name="qrypton-test-scanner",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{'a' * 64}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def sample_evidence(evidence_id: str, tenant_id: str, asset_id: str, target_id: str) -> Evidence:
    return Evidence(
        id=evidence_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        scan_target_id=target_id,
        kind=EvidenceKind.SOURCE_AST,
        location=EvidenceLocation(),
        confidence=0.95,
        deduplication_fingerprint=f"sha256:{'b' * 64}",
        provenance=sample_provenance(),
    )


def sample_finding(
    finding_id: str,
    tenant_id: str,
    asset_id: str,
    target_id: str,
    evidence_id: str,
    name: str = "RSA",
    key_size: int = 1024,
) -> CryptoFinding:
    alg = Algorithm(
        canonical_name=name,
        family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
        lifecycle_status=AlgorithmStatus.DEPRECATED,
        key_size_bits=Observation(
            state=ObservationState.OBSERVED, value=key_size, basis_evidence_ids=(evidence_id,)
        ),
        security_strength_bits=Observation(state=ObservationState.UNKNOWN),
    )
    return CryptoFinding(
        id=finding_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        scan_target_id=target_id,
        category="algorithm_use",
        algorithm=Observation(
            state=ObservationState.OBSERVED, value=alg, basis_evidence_ids=(evidence_id,)
        ),
        key_material=Observation(state=ObservationState.UNKNOWN),
        certificate=Observation(state=ObservationState.UNKNOWN),
        protocol=Observation(state=ObservationState.UNKNOWN),
        library=Observation(state=ObservationState.UNKNOWN),
        evidence_ids=(evidence_id,),
        confidence=0.9,
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=sample_provenance(),
    )


def sample_assessment(
    assessment_id: str,
    tenant_id: str,
    finding_id: str,
    evidence_id: str,
    level: RiskLevel = RiskLevel.HIGH,
    score: float = 75.0,
) -> RiskAssessment:
    return RiskAssessment(
        id=assessment_id,
        tenant_id=tenant_id,
        finding_id=finding_id,
        score=Observation(
            state=ObservationState.OBSERVED, value=score, basis_evidence_ids=(evidence_id,)
        ),
        level=level,
        factors=RiskFactors(
            cryptographic_obsolescence=Observation(state=ObservationState.UNKNOWN),
            quantum_exposure=Observation(
                state=ObservationState.OBSERVED, value=score, basis_evidence_ids=(evidence_id,)
            ),
            exploitability=Observation(state=ObservationState.UNKNOWN),
            business_impact=Observation(state=ObservationState.UNKNOWN),
            evidence_confidence=0.9,
            policy_profile_id="test-policy",
            policy_profile_version="1.0",
            rationale=("Mosca: X+Y=7, Z=10, margin=3 years.",),
        ),
        assessed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_name="qrypton-mosca",
        engine_version="1.0.0",
        evidence_ids=(evidence_id,),
    )


def sample_recommendation(
    rec_id: str,
    tenant_id: str,
    finding_id: str,
    priority: int = 10,
    action: str = "Migrate to ML-KEM-768",
) -> Recommendation:
    rep_alg = Algorithm(
        canonical_name="ML-KEM-768",
        family=AlgorithmFamily.KEY_AGREEMENT,
        lifecycle_status=AlgorithmStatus.APPROVED,
        key_size_bits=Observation(state=ObservationState.UNKNOWN),
        security_strength_bits=Observation(state=ObservationState.UNKNOWN),
    )
    url = TypeAdapter(HttpUrl).validate_python("https://csrc.nist.gov/pubs/fips/203/final")
    return Recommendation(
        id=rec_id,
        tenant_id=tenant_id,
        finding_id=finding_id,
        kind="migration",  # type: ignore[arg-type]
        priority=priority,
        title="PQC Migration Plan",
        action=action,
        nist_references=(url,),
        policy_profile_id="pqc-v1",
        policy_profile_version="1.0",
        replacement_algorithm=Observation(
            state=ObservationState.OBSERVED,
            value=rep_alg,
            basis_evidence_ids=(f"evidence_{'a' * 52}",),
        ),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=sample_provenance(),
    )


def sample_plan(finding_id: str) -> PqcRecommendationPlan:
    target_alg = Algorithm(
        canonical_name="ML-KEM-768",
        family=AlgorithmFamily.KEY_AGREEMENT,
        lifecycle_status=AlgorithmStatus.APPROVED,
        key_size_bits=Observation(state=ObservationState.UNKNOWN),
        security_strength_bits=Observation(state=ObservationState.UNKNOWN),
    )
    url = TypeAdapter(HttpUrl).validate_python("https://csrc.nist.gov/pubs/fips/203/final")
    return PqcRecommendationPlan(
        finding_id=finding_id,
        role=CryptoRole.KEM,
        target_algorithms=(target_alg,),
        hybrid_mode=HybridMode.REQUIRED,
        standard_references=(url,),
        basis=RecommendationBasis.STANDARDS_BACKED,
        compatibility=CompatibilityFactors(),
        rationale=RecommendationRationale(
            rule_id="RULE-KEM-01",
            role=CryptoRole.KEM,
            basis=RecommendationBasis.STANDARDS_BACKED,
            blocking_conditions=("Requires TLS 1.3 upgrade",),
            confidence=0.9,
        ),
        canonical_recommendation_ids=(f"rec_{'a' * 52}",),
    )


def sample_mosca(finding_id: str, *, urgency: str, score: float) -> PersistedMoscaEvaluation:
    return PersistedMoscaEvaluation(
        finding_id=finding_id,
        x_data_lifetime_years=5.0,
        y_migration_years=2.0,
        z_crqc_horizon_years=10.0,
        required_security_years=7.0,
        time_margin_years=3.0,
        exposure_score=score,
        urgency=urgency,  # type: ignore[arg-type]
    )


def create_sample_run(tenant_id: str, run_id: str, *, include_mosca: bool = True) -> RunResult:
    asset_id = f"asset_{'a' * 52}"
    target_id = f"target_{'a' * 52}"
    ev1 = f"evidence_{'b' * 52}"
    ev2 = f"evidence_{'c' * 52}"
    f1 = f"finding_{'b' * 52}"
    f2 = f"finding_{'c' * 52}"
    evidence_items = (
        sample_evidence(ev1, tenant_id, asset_id, target_id),
        sample_evidence(ev2, tenant_id, asset_id, target_id),
    )
    findings = (
        sample_finding(f1, tenant_id, asset_id, target_id, ev1, "RSA", 1024),
        sample_finding(f2, tenant_id, asset_id, target_id, ev2, "SHA-1", 160),
    )
    assessments = (
        sample_assessment(f"assess_{'b' * 52}", tenant_id, f1, ev1, RiskLevel.CRITICAL, 95.0),
        sample_assessment(f"assess_{'c' * 52}", tenant_id, f2, ev2, RiskLevel.HIGH, 75.0),
    )
    recs = (
        sample_recommendation(
            f"rec_{'b' * 52}", tenant_id, f1, priority=1, action="Replace RSA-1024 with ML-KEM-768"
        ),
        sample_recommendation(
            f"rec_{'c' * 52}", tenant_id, f2, priority=5, action="Replace SHA-1 with SHA-256"
        ),
    )
    scanner_results = (
        ScannerExecutionResult(
            scanner_name="qrypton-source",
            scanner_version="1.0.0",
            status="completed",
            finding_ids=(f1, f2),
            evidence_ids=(ev1, ev2),
        ),
    )
    cbom_data = b'{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:test"}'
    mosca = (
        (
            sample_mosca(f1, urgency="critical", score=95.0),
            sample_mosca(f2, urgency="high", score=75.0),
        )
        if include_mosca
        else ()
    )
    return RunResult(
        run_id=run_id,
        tenant_id=tenant_id,
        status=RunStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 10, 5, tzinfo=UTC),
        scanner_results=scanner_results,
        failures=(),
        evidence=evidence_items,
        findings=findings,
        assessments=assessments,
        recommendations=recs,
        recommendation_plans=(sample_plan(f1),),
        mosca_evaluations=mosca,
        cbom=cbom_data,
        cbom_digest=f"sha256:{'a' * 64}",
        policy_outcome=PolicyOutcome(passed=True, violations=()),
    )


@pytest.fixture
def populated_sqlite_store(tmp_path: Path) -> tuple[SqliteRunStore, str, str]:
    db_path = tmp_path / "test_qrypton.sqlite3"
    store = SqliteRunStore(db_path)
    tenant_id = f"tenant_{'a' * 52}"
    run_id = f"run_{'a' * 52}"
    store.finalize_run(create_sample_run(tenant_id, run_id))
    return store, tenant_id, run_id


class FakeDashboardDataProvider(DashboardDataProvider):
    """In-memory fake provider for rendering and unit tests."""

    def __init__(
        self,
        run_views: dict[tuple[str, str], DashboardRunView],
        *,
        cbom_store: dict[tuple[str, str], bytes] | None = None,
        details: dict[tuple[str, str, str], FindingDetail] | None = None,
    ) -> None:
        self.run_views = run_views
        self.cbom_store = cbom_store or {}
        self.details = details or {}

    def list_runs(self, *, tenant_id: str | None = None) -> Sequence[DashboardRunSummary]:
        result: list[DashboardRunSummary] = []
        for (tid, _), view in self.run_views.items():
            if tenant_id is None or tid == tenant_id:
                result.append(view.summary)
        return result

    def get_run_view(self, *, tenant_id: str, run_id: str) -> DashboardRunView | None:
        return self.run_views.get((tenant_id, run_id))

    def get_finding_detail(
        self, *, tenant_id: str, run_id: str, finding_id: str
    ) -> FindingDetail | None:
        return self.details.get((tenant_id, run_id, finding_id))

    def get_persisted_cbom(self, *, tenant_id: str, run_id: str) -> bytes | None:
        return self.cbom_store.get((tenant_id, run_id))
