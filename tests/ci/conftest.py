"""Shared fixtures for CI integration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from qrypton.application.schemas import PolicyOutcome, RunResult, ScannerExecutionResult
from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    ObservationState,
    RiskLevel,
    RunStatus,
)
from qrypton.contracts.models import (
    Algorithm,
    CryptoFinding,
    Observation,
    Provenance,
    RiskAssessment,
    RiskFactors,
)


def _unknown() -> Observation[Any]:
    return Observation(state=ObservationState.UNKNOWN)


def _provenance() -> Provenance:
    return Provenance(
        scanner_name="test-scanner",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{'a' * 64}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def make_finding(
    *,
    finding_id: str = f"finding_{'a' * 52}",
    algorithm_name: str = "SHA-1",
    family: AlgorithmFamily = AlgorithmFamily.HASH,
    status: AlgorithmStatus = AlgorithmStatus.LEGACY,
    key_size: int | None = None,
    category: str = "algorithm_use",
    tenant_id: str = f"tenant_{'a' * 52}",
) -> CryptoFinding:
    """Create a CryptoFinding with controllable algorithm properties."""
    evidence_id = f"evidence_{'b' * 52}"
    key_obs: Observation[Any] = (
        Observation(
            state=ObservationState.OBSERVED,
            value=key_size,
            basis_evidence_ids=(evidence_id,),
        )
        if key_size is not None
        else _unknown()
    )
    algorithm = Algorithm(
        canonical_name=algorithm_name,
        family=family,
        lifecycle_status=status,
        key_size_bits=key_obs,
        security_strength_bits=_unknown(),
    )
    return CryptoFinding(
        id=finding_id,
        tenant_id=tenant_id,
        asset_id=f"asset_{'a' * 52}",
        scan_target_id=f"target_{'a' * 52}",
        category=category,
        algorithm=Observation(
            state=ObservationState.OBSERVED,
            value=algorithm,
            basis_evidence_ids=(evidence_id,),
        ),
        key_material=_unknown(),
        certificate=_unknown(),
        protocol=_unknown(),
        library=_unknown(),
        evidence_ids=(evidence_id,),
        confidence=0.9,
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=_provenance(),
    )


def make_assessment(
    *,
    finding_id: str = f"finding_{'a' * 52}",
    level: RiskLevel = RiskLevel.HIGH,
    tenant_id: str = f"tenant_{'a' * 52}",
) -> RiskAssessment:
    """Create a RiskAssessment for a finding."""
    evidence_id = f"evidence_{'b' * 52}"
    return RiskAssessment(
        id=f"riskassess_{'a' * 52}",
        tenant_id=tenant_id,
        finding_id=finding_id,
        score=Observation(
            state=ObservationState.OBSERVED, value=7.0, basis_evidence_ids=(evidence_id,)
        ),
        level=level,
        factors=RiskFactors(
            cryptographic_obsolescence=Observation(
                state=ObservationState.OBSERVED, value=8.0, basis_evidence_ids=(evidence_id,)
            ),
            quantum_exposure=Observation(
                state=ObservationState.OBSERVED, value=6.0, basis_evidence_ids=(evidence_id,)
            ),
            exploitability=Observation(
                state=ObservationState.OBSERVED, value=5.0, basis_evidence_ids=(evidence_id,)
            ),
            business_impact=Observation(
                state=ObservationState.OBSERVED, value=7.0, basis_evidence_ids=(evidence_id,)
            ),
            evidence_confidence=0.9,
            policy_profile_id="test-policy",
            policy_profile_version="1",
            rationale=("test rationale",),
        ),
        assessed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_name="test-engine",
        engine_version="1.0.0",
        evidence_ids=(evidence_id,),
    )


def make_run_result(
    *,
    findings: tuple[CryptoFinding, ...] = (),
    assessments: tuple[RiskAssessment, ...] = (),
    scanner_results: tuple[ScannerExecutionResult, ...] = (),
    status: RunStatus = RunStatus.COMPLETED,
    policy_passed: bool = True,
    policy_violations: tuple[str, ...] = (),
) -> RunResult:
    """Create a RunResult with controllable findings and assessments."""
    if not scanner_results:
        scanner_results = (
            ScannerExecutionResult(
                scanner_name="test-scanner",
                scanner_version="1.0.0",
                status="completed",
            ),
        )
    return RunResult(
        run_id=f"run_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        status=status,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        scanner_results=scanner_results,
        findings=findings,
        assessments=assessments,
        policy_outcome=PolicyOutcome(
            passed=policy_passed,
            violations=policy_violations,
        ),
    )


def make_baseline(
    inventory: dict[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    """Create a baseline JSON document."""
    return {
        "schema_version": "1.0",
        "run_id": f"run_{'b' * 52}",
        "inventory": inventory or {},
    }
