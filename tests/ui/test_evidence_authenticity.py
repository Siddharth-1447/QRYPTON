"""Regression tests for evidence-authenticity fixes.

- Reference descriptors (KMS ARN, container image reference) must emit exactly
  one honest ``static.*-reference`` observation: the token engine must never
  mine the system's own descriptor boilerplate for algorithm claims.
- The dashboard provider must surface persisted Mosca urgency and business
  criticality on the heatmap, and label finding evidence authenticity.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from qrypton.application.schemas import PolicyOutcome, RunResult
from qrypton.contracts.enums import (
    Criticality,
    MoscaUrgency,
    ObservationState,
    RunStatus,
    ScanTargetKind,
)
from qrypton.contracts.models import BusinessContext, Observation
from qrypton.ports.scanners import ScanLimits, ScanRequest
from qrypton.scanners.extended import ExtendedStaticScanner
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import (
    create_sample_run,
    sample_evidence,
    sample_finding,
    sample_provenance,
)


def _request(path: Path) -> ScanRequest:
    from qrypton.contracts.models import ScanTarget

    provenance = sample_provenance()
    target = ScanTarget(
        id=f"target_{'d' * 52}",
        tenant_id=f"tenant_{'d' * 52}",
        asset_id=f"asset_{'d' * 52}",
        kind=ScanTargetKind.FILE,
        locator=str(path),
        content_digest=Observation(state=ObservationState.UNKNOWN),
        declared_size_bytes=Observation(state=ObservationState.UNKNOWN),
        requested_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=provenance,
    )
    return ScanRequest(
        tenant_id=f"tenant_{'d' * 52}",
        target=target,
        correlation_id="descriptor-test",
        limits=ScanLimits(
            max_compressed_bytes=1024,
            max_expanded_bytes=1024,
            max_file_count=10,
            max_nesting_depth=2,
            max_layer_count=2,
            max_ast_nodes=100,
            max_evidence_count=10,
            max_wall_time_seconds=10,
            max_memory_bytes=1024,
            max_file_bytes=1024 * 1024,
        ),
    )


def _scan_descriptor(tmp_path: Path, payload: dict[str, str], filename: str) -> list:
    work = tmp_path / "work"
    work.mkdir()
    path = work / filename
    path.write_text(json.dumps(payload), encoding="utf-8")
    scanner = ExtendedStaticScanner(allowed_root=work)

    async def _collect() -> list:
        return [item async for item in scanner.scan(_request(path))]

    return asyncio.run(_collect())


def test_container_reference_descriptor_emits_no_algorithm_claims(tmp_path: Path) -> None:
    observations = _scan_descriptor(
        tmp_path,
        {
            "container_image_reference": "nginx:1.9.15",
            "note": "Container image reference descriptor; static metadata only, "
            "registry not pulled, container never started.",
        },
        "container-image.json",
    )
    assert len(observations) == 1
    only = observations[0]
    assert only.rule_id == "static.container-reference"
    assert only.attributes["subject_kind"] == "library"
    assert "nginx:1.9.15" in str(only.attributes["subject_value"])


def test_kms_descriptor_emits_honest_reference_observation(tmp_path: Path) -> None:
    observations = _scan_descriptor(
        tmp_path,
        {
            "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/1234abcd",
            "note": "KMS key descriptor; static metadata only, no key material accessed.",
        },
        "kms-key.json",
    )
    assert len(observations) == 1
    only = observations[0]
    assert only.rule_id == "static.kms-reference"
    assert only.attributes["subject_kind"] == "library"
    assert only.attributes["subject_value"] == "aws-kms-key"


def _business_context(context_id: str, tenant_id: str, asset_id: str) -> BusinessContext:
    evidence_id = f"evidence_{'e' * 52}"
    return BusinessContext(
        id=context_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        criticality=Observation(
            state=ObservationState.OBSERVED,
            value=Criticality.CRITICAL,
            basis_evidence_ids=(evidence_id,),
        ),
        data_classification=Observation(
            state=ObservationState.OBSERVED,
            value="restricted",
            basis_evidence_ids=(evidence_id,),
        ),
        internet_exposed=Observation(
            state=ObservationState.OBSERVED, value=True, basis_evidence_ids=(evidence_id,)
        ),
        regulatory_scopes=("regulated",),
        owner_reference=Observation(
            state=ObservationState.OBSERVED, value="team", basis_evidence_ids=(evidence_id,)
        ),
        provenance=sample_provenance(),
    )


def test_heatmap_uses_mosca_urgency_and_persisted_criticality(tmp_path: Path) -> None:
    tenant_id = f"tenant_{'f' * 52}"
    run_id = f"run_{'f' * 52}"
    run = create_sample_run(tenant_id, run_id).model_copy(
        update={
            "business_context": _business_context(
                f"ctx_{'f' * 52}", tenant_id, f"asset_{'a' * 52}"
            )
        }
    )
    store = SqliteRunStore(tmp_path / "heatmap.sqlite3")
    store.finalize_run(run)
    view = SqliteDashboardDataProvider(store).get_run_view(tenant_id=tenant_id, run_id=run_id)
    assert view is not None
    # Fixture mosca urgencies are critical + high; persisted criticality is critical.
    by_cell = {
        (cell.mosca_urgency, cell.business_criticality): cell.finding_count
        for cell in view.heatmap_cells
    }
    assert by_cell[(MoscaUrgency.CRITICAL, "critical")] == 1
    assert by_cell[(MoscaUrgency.HIGH, "critical")] == 1
    assert all(
        cell.finding_count == 0
        for cell in view.heatmap_cells
        if cell.business_criticality == "unclassified"
    )


def test_finding_detail_labels_observed_evidence(tmp_path: Path) -> None:
    tenant_id = f"tenant_{'g' * 52}"
    run_id = f"run_{'g' * 52}"
    asset_id = f"asset_{'g' * 52}"
    target_id = f"target_{'g' * 52}"
    evidence_id = f"evidence_{'g' * 52}"
    finding_id = f"finding_{'g' * 52}"
    store = SqliteRunStore(tmp_path / "auth.sqlite3")
    store.finalize_run(
        RunResult(
            run_id=run_id,
            tenant_id=tenant_id,
            status=RunStatus.COMPLETED,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            evidence=(sample_evidence(evidence_id, tenant_id, asset_id, target_id),),
            findings=(
                sample_finding(finding_id, tenant_id, asset_id, target_id, evidence_id),
            ),
            policy_outcome=PolicyOutcome(passed=True, violations=()),
        )
    )
    detail = SqliteDashboardDataProvider(store).get_finding_detail(
        tenant_id=tenant_id, run_id=run_id, finding_id=finding_id
    )
    assert detail is not None
    assert detail.evidence_authenticity is not None
    assert detail.evidence_authenticity.quality == "observed"
    assert detail.evidence_authenticity.confidence_applicable is True
