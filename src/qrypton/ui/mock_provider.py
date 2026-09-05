"""In-memory mock data provider for demonstration, testing, and fallback presentation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Literal

from pydantic import HttpUrl, TypeAdapter

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
    Provenance,
    Recommendation,
    RiskAssessment,
    RiskFactors,
)
from qrypton.ui.contracts import (
    DashboardRunSummary,
    DashboardRunView,
    ExecutivePosture,
    FindingDetail,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
)
from qrypton.ui.provider import DashboardDataProvider

CriticalityColumn = Literal["low", "medium", "high", "critical", "unclassified"]
_URGENCY_TIERS: tuple[RiskLevel, ...] = (
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

DEFAULT_MOCK_TENANT = f"tenant_{'a' * 52}"
DEFAULT_MOCK_RUN = f"run_{'a' * 52}"


def _build_mock_data(
    tenant_id: str = DEFAULT_MOCK_TENANT, run_id: str = DEFAULT_MOCK_RUN
) -> tuple[
    DashboardRunSummary,
    DashboardRunView,
    dict[str, FindingDetail],
    bytes,
]:
    observed_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
    completed_time = datetime(2026, 1, 15, 10, 4, 30, tzinfo=UTC)
    provenance = Provenance(
        scanner_name="qrypton-mock-scanner",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{'0' * 64}",
        observed_at=observed_time,
    )

    raw_findings = [
        {
            "id": f"finding_rsa_{'b' * 52}",
            "asset_id": f"asset_payment_{'a' * 52}",
            "target_id": f"target_auth_{'a' * 52}",
            "evidence_id": f"evidence_rsa_{'b' * 52}",
            "assess_id": f"assess_rsa_{'b' * 52}",
            "rec_id": f"rec_rsa_{'b' * 52}",
            "category": "algorithm_use",
            "alg_name": "RSA",
            "alg_family": AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
            "key_size": 1024,
            "status": AlgorithmStatus.DEPRECATED,
            "risk_level": RiskLevel.CRITICAL,
            "risk_score": 95.0,
            "confidence": 0.98,
            "rec_title": "Migrate RSA-1024 to Post-Quantum Key Encapsulation",
            "rec_action": "Replace deprecated RSA-1024 with NIST FIPS 203 ML-KEM-768",
            "rep_alg": "ML-KEM-768",
            "rep_family": AlgorithmFamily.KEY_AGREEMENT,
            "nist_ref": "https://csrc.nist.gov/pubs/fips/203/final",
            "role": "KEM",
            "hybrid": "required",
            "blockers": ("Requires TLS 1.3 hybrid key exchange support",),
            "priority": 1,
            "mosca": {
                "x": 10.0,
                "y": 3.0,
                "z": 8.0,
                "req": 13.0,
                "margin": -5.0,
                "score": 95.0,
            },
        },
        {
            "id": f"finding_des_{'c' * 52}",
            "asset_id": f"asset_pipeline_{'b' * 52}",
            "target_id": f"target_storage_{'b' * 52}",
            "evidence_id": f"evidence_des_{'c' * 52}",
            "assess_id": f"assess_des_{'c' * 52}",
            "rec_id": f"rec_des_{'c' * 52}",
            "category": "algorithm_use",
            "alg_name": "3DES",
            "alg_family": AlgorithmFamily.SYMMETRIC_CIPHER,
            "key_size": 168,
            "status": AlgorithmStatus.DEPRECATED,
            "risk_level": RiskLevel.HIGH,
            "risk_score": 78.0,
            "confidence": 0.95,
            "rec_title": "Deprecate Triple-DES in Stored Data Pipeline",
            "rec_action": "Migrate data-at-rest encryption from 3DES to AES-256-GCM",
            "rep_alg": "AES-256-GCM",
            "rep_family": AlgorithmFamily.SYMMETRIC_CIPHER,
            "nist_ref": "https://csrc.nist.gov/pubs/sp/800/131a/r2/final",
            "role": "Symmetric Cipher",
            "hybrid": "not_applicable",
            "blockers": ("Database schema re-encryption migration needed",),
            "priority": 2,
            "mosca": {
                "x": 6.0,
                "y": 2.0,
                "z": 10.0,
                "req": 8.0,
                "margin": 2.0,
                "score": 78.0,
            },
        },
        {
            "id": f"finding_sha_{'d' * 52}",
            "asset_id": f"asset_tokens_{'c' * 52}",
            "target_id": f"target_verifier_{'c' * 52}",
            "evidence_id": f"evidence_sha_{'d' * 52}",
            "assess_id": f"assess_sha_{'d' * 52}",
            "rec_id": f"rec_sha_{'d' * 52}",
            "category": "algorithm_use",
            "alg_name": "SHA-1",
            "alg_family": AlgorithmFamily.HASH,
            "key_size": 160,
            "status": AlgorithmStatus.DEPRECATED,
            "risk_level": RiskLevel.MEDIUM,
            "risk_score": 55.0,
            "confidence": 0.92,
            "rec_title": "Replace SHA-1 in Verification Workflows",
            "rec_action": "Upgrade token hashing digests to SHA-256 or SHA-384",
            "rep_alg": "SHA-256",
            "rep_family": AlgorithmFamily.HASH,
            "nist_ref": "https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
            "role": "Digest",
            "hybrid": "optional",
            "blockers": (),
            "priority": 3,
            "mosca": {
                "x": 3.0,
                "y": 1.0,
                "z": 10.0,
                "req": 4.0,
                "margin": 6.0,
                "score": 55.0,
            },
        },
        {
            "id": f"finding_aes_{'e' * 52}",
            "asset_id": f"asset_cache_{'d' * 52}",
            "target_id": f"target_layer_{'d' * 52}",
            "evidence_id": f"evidence_aes_{'e' * 52}",
            "assess_id": f"assess_aes_{'e' * 52}",
            "rec_id": f"rec_aes_{'e' * 52}",
            "category": "algorithm_use",
            "alg_name": "AES-128-CBC",
            "alg_family": AlgorithmFamily.SYMMETRIC_CIPHER,
            "key_size": 128,
            "status": AlgorithmStatus.APPROVED,
            "risk_level": RiskLevel.LOW,
            "risk_score": 25.0,
            "confidence": 0.90,
            "rec_title": "Modernize AES-CBC to Authenticated GCM",
            "rec_action": "Adopt AES-256-GCM for authenticated encryption and quantum margin",
            "rep_alg": "AES-256-GCM",
            "rep_family": AlgorithmFamily.SYMMETRIC_CIPHER,
            "nist_ref": "https://csrc.nist.gov/pubs/sp/800/38/d/final",
            "role": "AEAD Cipher",
            "hybrid": "not_applicable",
            "blockers": (),
            "priority": 4,
            "mosca": {
                "x": 2.0,
                "y": 1.0,
                "z": 12.0,
                "req": 3.0,
                "margin": 9.0,
                "score": 25.0,
            },
        },
        {
            "id": f"finding_pqc_{'f' * 52}",
            "asset_id": f"asset_mesh_{'e' * 52}",
            "target_id": f"target_ingress_{'e' * 52}",
            "evidence_id": f"evidence_pqc_{'f' * 52}",
            "assess_id": f"assess_pqc_{'f' * 52}",
            "rec_id": f"rec_pqc_{'f' * 52}",
            "category": "algorithm_use",
            "alg_name": "ML-KEM-768",
            "alg_family": AlgorithmFamily.KEY_AGREEMENT,
            "key_size": 768,
            "status": AlgorithmStatus.APPROVED,
            "risk_level": RiskLevel.INFORMATIONAL,
            "risk_score": 5.0,
            "confidence": 0.99,
            "rec_title": "NIST FIPS 203 Compliant Deployment",
            "rec_action": "Maintain active ML-KEM-768 key encapsulation deployment",
            "rep_alg": "ML-KEM-768",
            "rep_family": AlgorithmFamily.KEY_AGREEMENT,
            "nist_ref": "https://csrc.nist.gov/pubs/fips/203/final",
            "role": "KEM",
            "hybrid": "required",
            "blockers": (),
            "priority": 5,
            "mosca": {
                "x": 10.0,
                "y": 0.0,
                "z": 15.0,
                "req": 10.0,
                "margin": 5.0,
                "score": 5.0,
            },
        },
    ]

    inventory_rows: list[InventoryRow] = []
    mosca_points: list[MoscaPoint] = []
    roadmap_rows: list[RoadmapRow] = []
    details_map: dict[str, FindingDetail] = {}

    url_adapter = TypeAdapter(HttpUrl)
    nist_url_cache: dict[str, HttpUrl] = {}

    for item in raw_findings:
        fid = item["id"]  # type: ignore[index]
        ev_id = item["evidence_id"]  # type: ignore[index]
        evidence = Evidence(
            id=ev_id,
            tenant_id=tenant_id,
            asset_id=item["asset_id"],  # type: ignore[arg-type]
            scan_target_id=item["target_id"],  # type: ignore[arg-type]
            kind=EvidenceKind.SOURCE_AST,
            location=EvidenceLocation(
                relative_path="src/crypto/demo.py",
                line_start=14,
                line_end=28,
            ),
            confidence=item["confidence"],  # type: ignore[arg-type]
            deduplication_fingerprint=f"sha256:{'b' * 64}",
            provenance=provenance,
        )

        alg = Algorithm(
            canonical_name=item["alg_name"],  # type: ignore[arg-type]
            family=item["alg_family"],  # type: ignore[arg-type]
            lifecycle_status=item["status"],  # type: ignore[arg-type]
            key_size_bits=Observation(
                state=ObservationState.OBSERVED,
                value=item["key_size"],
                basis_evidence_ids=(ev_id,),
            ),
            security_strength_bits=Observation(state=ObservationState.UNKNOWN),
        )

        finding = CryptoFinding(
            id=fid,
            tenant_id=tenant_id,
            asset_id=item["asset_id"],  # type: ignore[arg-type]
            scan_target_id=item["target_id"],  # type: ignore[arg-type]
            category=item["category"],  # type: ignore[arg-type]
            algorithm=Observation(
                state=ObservationState.OBSERVED,
                value=alg,
                basis_evidence_ids=(ev_id,),
            ),
            key_material=Observation(state=ObservationState.UNKNOWN),
            certificate=Observation(state=ObservationState.UNKNOWN),
            protocol=Observation(state=ObservationState.UNKNOWN),
            library=Observation(state=ObservationState.UNKNOWN),
            evidence_ids=(ev_id,),
            confidence=item["confidence"],  # type: ignore[arg-type]
            first_observed_at=observed_time,
            last_observed_at=observed_time,
            provenance=provenance,
        )

        assessment = RiskAssessment(
            id=item["assess_id"],  # type: ignore[arg-type]
            tenant_id=tenant_id,
            finding_id=fid,
            score=Observation(
                state=ObservationState.OBSERVED,
                value=item["risk_score"],
                basis_evidence_ids=(ev_id,),
            ),
            level=item["risk_level"],  # type: ignore[arg-type]
            factors=RiskFactors(
                cryptographic_obsolescence=Observation(state=ObservationState.UNKNOWN),
                quantum_exposure=Observation(
                    state=ObservationState.OBSERVED,
                    value=item["risk_score"],
                    basis_evidence_ids=(ev_id,),
                ),
                exploitability=Observation(state=ObservationState.UNKNOWN),
                business_impact=Observation(state=ObservationState.UNKNOWN),
                evidence_confidence=item["confidence"],  # type: ignore[arg-type]
                policy_profile_id="nist-pqc-v1",
                policy_profile_version="1.0.0",
                rationale=(
                    f"Mosca evaluation: X={item['mosca']['x']}y, Y={item['mosca']['y']}y, "  # type: ignore[index]
                    f"Z={item['mosca']['z']}y. Urgency: {item['risk_level'].value}.",  # type: ignore[union-attr]
                ),
            ),
            assessed_at=observed_time,
            engine_name="qrypton-mosca",
            engine_version="1.0.0",
            evidence_ids=(ev_id,),
        )

        ref_str = item["nist_ref"]  # type: ignore[index]
        if ref_str not in nist_url_cache:
            nist_url_cache[ref_str] = url_adapter.validate_python(ref_str)
        ref_url = nist_url_cache[ref_str]

        rep_alg = Algorithm(
            canonical_name=item["rep_alg"],  # type: ignore[arg-type]
            family=item["rep_family"],  # type: ignore[arg-type]
            lifecycle_status=AlgorithmStatus.APPROVED,
            key_size_bits=Observation(state=ObservationState.UNKNOWN),
            security_strength_bits=Observation(state=ObservationState.UNKNOWN),
        )

        rec = Recommendation(
            id=item["rec_id"],  # type: ignore[arg-type]
            tenant_id=tenant_id,
            finding_id=fid,
            kind="migration",  # type: ignore[arg-type]
            priority=item["priority"],  # type: ignore[arg-type]
            title=item["rec_title"],  # type: ignore[arg-type]
            action=item["rec_action"],  # type: ignore[arg-type]
            nist_references=(ref_url,),
            policy_profile_id="nist-pqc-v1",
            policy_profile_version="1.0.0",
            replacement_algorithm=Observation(
                state=ObservationState.OBSERVED,
                value=rep_alg,
                basis_evidence_ids=(ev_id,),
            ),
            created_at=observed_time,
            provenance=provenance,
        )

        inventory_rows.append(
            InventoryRow(
                finding_id=fid,
                category=item["category"],  # type: ignore[arg-type]
                algorithm_name=item["alg_name"],  # type: ignore[arg-type]
                algorithm_family=item["alg_family"].value,  # type: ignore[union-attr]
                key_size_bits=item["key_size"],  # type: ignore[arg-type]
                lifecycle_status=item["status"].value,  # type: ignore[union-attr]
                risk_level=item["risk_level"],  # type: ignore[arg-type]
                risk_score=item["risk_score"],  # type: ignore[arg-type]
                confidence=item["confidence"],  # type: ignore[arg-type]
                evidence_count=1,
                first_observed_at=observed_time,
                last_observed_at=observed_time,
            )
        )

        mosca_data = item["mosca"]  # type: ignore[index]
        mosca_points.append(
            MoscaPoint(
                finding_id=fid,
                urgency=item["risk_level"],  # type: ignore[arg-type]
                exposure_score=mosca_data["score"],  # type: ignore[index]
                x_data_lifetime_years=mosca_data["x"],  # type: ignore[index]
                y_migration_years=mosca_data["y"],  # type: ignore[index]
                z_crqc_horizon_years=mosca_data["z"],  # type: ignore[index]
                required_security_years=mosca_data["req"],  # type: ignore[index]
                time_margin_years=mosca_data["margin"],  # type: ignore[index]
                timeline_state="persisted",
            )
        )

        roadmap_rows.append(
            RoadmapRow(
                finding_id=fid,
                priority=item["priority"],  # type: ignore[arg-type]
                action=item["rec_action"],  # type: ignore[arg-type]
                role=item["role"],  # type: ignore[arg-type]
                target_algorithms=(item["rep_alg"],),  # type: ignore[arg-type]
                hybrid_mode=item["hybrid"],  # type: ignore[arg-type]
                blocking_conditions=item["blockers"],  # type: ignore[arg-type]
                standards_references=(ref_url,),
            )
        )

        details_map[fid] = FindingDetail(
            finding=finding,
            assessment=assessment,
            recommendations=(rec,),
            evidence_provenance=(evidence,),
            failures=(),
        )

    # Build heatmap grid (urgency x business_criticality)
    heatmap_dict: dict[tuple[RiskLevel, CriticalityColumn], list[str]] = {
        (urgency, column): [] for urgency in _URGENCY_TIERS for column in _CRITICALITY_COLUMNS
    }
    for item in raw_findings:
        heatmap_dict[(item["risk_level"], "unclassified")].append(item["id"])  # type: ignore[index]

    heatmap_cells = tuple(
        RiskHeatmapCell(
            mosca_urgency=urgency,
            business_criticality=column,
            finding_count=len(ids),
            finding_ids=tuple(ids),
        )
        for (urgency, column), ids in heatmap_dict.items()
    )

    summary = DashboardRunSummary(
        tenant_id=tenant_id,
        run_id=run_id,
        status=RunStatus.COMPLETED,
        record_state="complete",
        started_at=observed_time,
        completed_at=completed_time,
        total_findings=len(inventory_rows),
    )

    posture = ExecutivePosture(
        total_findings=len(inventory_rows),
        unique_asset_ids=len({item["asset_id"] for item in raw_findings}),
        critical_findings_count=sum(
            1 for i in raw_findings if i["risk_level"] == RiskLevel.CRITICAL
        ),
        high_findings_count=sum(1 for i in raw_findings if i["risk_level"] == RiskLevel.HIGH),
        medium_findings_count=sum(1 for i in raw_findings if i["risk_level"] == RiskLevel.MEDIUM),
        low_findings_count=sum(1 for i in raw_findings if i["risk_level"] == RiskLevel.LOW),
        informational_findings_count=sum(
            1 for i in raw_findings if i["risk_level"] == RiskLevel.INFORMATIONAL
        ),
        unassessed_findings_count=0,
        run_status=RunStatus.COMPLETED,
        scanner_failed_count=0,
        scanner_partial_count=0,
        policy_passed=True,
        policy_violations=(),
    )

    cbom_bytes = (
        b'{\n'
        b'  "bomFormat": "CycloneDX",\n'
        b'  "specVersion": "1.6",\n'
        b'  "serialNumber": "urn:uuid:14470000-0000-4000-8000-000000000001",\n'
        b'  "version": 1,\n'
        b'  "metadata": {\n'
        b'    "component": {\n'
        b'      "type": "application",\n'
        b'      "name": "QRYPTON-Enterprise-Demo"\n'
        b'    }\n'
        b'  },\n'
        b'  "components": [\n'
        b'    {\n'
        b'      "type": "cryptographic-asset",\n'
        b'      "name": "RSA-1024",\n'
        b'      "cryptoProperties": {\n'
        b'        "assetType": "algorithm",\n'
        b'        "algorithmProperties": {\n'
        b'          "name": "RSA",\n'
        b'          "primitive": "asymmetric-encryption",\n'
        b'          "keyLength": 1024\n'
        b'        }\n'
        b'      }\n'
        b'    },\n'
        b'    {\n'
        b'      "type": "cryptographic-asset",\n'
        b'      "name": "ML-KEM-768",\n'
        b'      "cryptoProperties": {\n'
        b'        "assetType": "algorithm",\n'
        b'        "algorithmProperties": {\n'
        b'          "name": "ML-KEM-768",\n'
        b'          "primitive": "key-exchange",\n'
        b'          "keyLength": 768\n'
        b'        }\n'
        b'      }\n'
        b'    }\n'
        b'  ]\n'
        b'}'
    )

    view = DashboardRunView(
        summary=summary,
        posture=posture,
        inventory=tuple(inventory_rows),
        heatmap_cells=heatmap_cells,
        mosca_points=tuple(mosca_points),
        roadmap=tuple(roadmap_rows),
        has_cbom=True,
        cbom_digest=f"sha256:{'a' * 64}",
    )

    return summary, view, details_map, cbom_bytes


class MockDashboardDataProvider(DashboardDataProvider):
    """Fallback in-memory mock provider providing high-fidelity cryptographic demo data."""

    def __init__(
        self,
        tenant_id: str = DEFAULT_MOCK_TENANT,
        run_id: str = DEFAULT_MOCK_RUN,
    ) -> None:
        self._tenant_id = tenant_id
        self._run_id = run_id
        self._summary, self._view, self._details, self._cbom = _build_mock_data(tenant_id, run_id)

    def list_runs(self, *, tenant_id: str | None = None) -> Sequence[DashboardRunSummary]:
        tid = tenant_id if tenant_id is not None else self._tenant_id
        return (
            DashboardRunSummary(
                tenant_id=tid,
                run_id=self._summary.run_id,
                status=self._summary.status,
                record_state=self._summary.record_state,
                started_at=self._summary.started_at,
                completed_at=self._summary.completed_at,
                total_findings=self._summary.total_findings,
            ),
        )

    def get_run_view(self, *, tenant_id: str, run_id: str) -> DashboardRunView | None:
        summary = DashboardRunSummary(
            tenant_id=tenant_id,
            run_id=run_id,
            status=self._summary.status,
            record_state=self._summary.record_state,
            started_at=self._summary.started_at,
            completed_at=self._summary.completed_at,
            total_findings=self._summary.total_findings,
        )
        return DashboardRunView(
            summary=summary,
            posture=self._view.posture,
            inventory=self._view.inventory,
            heatmap_cells=self._view.heatmap_cells,
            mosca_points=self._view.mosca_points,
            roadmap=self._view.roadmap,
            has_cbom=self._view.has_cbom,
            cbom_digest=self._view.cbom_digest,
        )

    def get_finding_detail(
        self, *, tenant_id: str, run_id: str, finding_id: str
    ) -> FindingDetail | None:
        return self._details.get(finding_id)

    def get_persisted_cbom(self, *, tenant_id: str, run_id: str) -> bytes | None:
        return self._cbom
