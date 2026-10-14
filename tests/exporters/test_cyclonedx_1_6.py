from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from qrypton.application.config import default_risk_policy
from qrypton.contracts.enums import (
    AlgorithmFamily,
    AssetKind,
    Criticality,
    EvidenceKind,
    ObservationState,
)
from qrypton.contracts.errors import CBOMExportError, CBOMValidationError
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import (
    Asset,
    BusinessContext,
    Evidence,
    EvidenceLocation,
    Observation,
    PersistedMoscaEvaluation,
)
from qrypton.exporters.cyclonedx_1_6 import CbomExportContext, CycloneDx16CbomExporter
from qrypton.risk.mosca import MoscaParameters, MoscaRiskEngine
from tests.risk.conftest import finding, provenance
from tests.unit.contracts.conftest import digest


def _asset(kind: AssetKind = AssetKind.APPLICATION) -> Asset:
    return Asset(
        id=f"asset_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        kind=kind,
        external_reference="payments",
        name="Payments",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=provenance(),
    )


def _context() -> CbomExportContext:
    return CbomExportContext(
        serial_number=UUID("12345678-1234-4234-9234-123456789abc"),
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _export(*, evidence: tuple[Evidence, ...] = ()) -> bytes:
    item = finding("sha-1", AlgorithmFamily.HASH)
    return CycloneDx16CbomExporter().export(
        asset=_asset(),
        findings=(item,),
        assessments=(),
        recommendations=(),
        recommendation_plans=(),
        evidence=evidence,
        context=_context(),
    )


def test_minimal_cbom_is_schema_valid_and_deterministic() -> None:
    first = _export()
    second = _export()
    assert first == second
    document = json.loads(first)
    assert document["specVersion"] == "1.6"
    assert document["metadata"]["component"]["type"] == "application"
    assert document["components"][0]["cryptoProperties"]["assetType"] == "algorithm"
    assert document["dependencies"][0]["dependsOn"] == [document["components"][0]["bom-ref"]]


def test_cbom_exposes_additive_assessment_confidence_properties() -> None:
    item = finding("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    assessment = engine.assess(item, None, default_risk_policy(datetime(2026, 1, 1, tzinfo=UTC)))
    document = json.loads(
        CycloneDx16CbomExporter().export(
            asset=_asset(),
            findings=(item,),
            assessments=(assessment,),
            recommendations=(),
            recommendation_plans=(),
            evidence=(),
            context=_context(),
        )
    )
    properties = {
        entry["name"]: entry["value"] for entry in document["components"][0]["properties"]
    }
    assert properties["org.qrypton.risk.assessment-confidence"] == "0.0"
    assert properties["org.qrypton.risk.context-completeness"] == "0.0"
    recorded = json.loads(properties["org.qrypton.risk.assessment"])
    assert recorded["factors"]["evidence_confidence"] == 0.9
    assert recorded["assessment_confidence"] == 0.0
    assert recorded["context_completeness"] == 0.0


def test_duplicate_identical_evidence_is_emitted_once_without_excerpt() -> None:
    item = finding("sha-1", AlgorithmFamily.HASH)
    evidence = Evidence(
        id=item.evidence_ids[0],
        tenant_id=item.tenant_id,
        asset_id=item.asset_id,
        scan_target_id=item.scan_target_id,
        kind=EvidenceKind.SOURCE_LEXICAL,
        location=EvidenceLocation(relative_path="src/crypto.py", line_start=1),
        excerpt="secret should never be exported",
        confidence=0.9,
        deduplication_fingerprint=digest(),
        provenance=provenance(),
    )
    document = json.loads(_export(evidence=(evidence, evidence)))
    values = [
        item["value"]
        for item in document["components"][0]["properties"]
        if item["name"] == "org.qrypton.evidence"
    ]
    assert len(values) == 1
    assert "excerpt" not in values[0]


def test_unsupported_asset_kind_fails_closed() -> None:
    item = finding("sha-1", AlgorithmFamily.HASH)
    with pytest.raises(CBOMExportError):
        CycloneDx16CbomExporter().export(
            asset=_asset(AssetKind.DATASTORE),
            findings=(item,),
            assessments=(),
            recommendations=(),
            recommendation_plans=(),
            evidence=(),
            context=_context(),
        )


def test_cbom_retains_business_context_and_mosca_timelines() -> None:
    item = finding("sha-1", AlgorithmFamily.HASH)
    evidence_id = item.evidence_ids[0]
    business = BusinessContext(
        id=f"context_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        asset_id=f"asset_{'a' * 52}",
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
            state=ObservationState.OBSERVED,
            value=True,
            basis_evidence_ids=(evidence_id,),
        ),
        regulatory_scopes=("pci-dss",),
        owner_reference=Observation(
            state=ObservationState.OBSERVED,
            value="team-crypto",
            basis_evidence_ids=(evidence_id,),
        ),
        provenance=provenance(),
    )
    mosca = PersistedMoscaEvaluation(
        finding_id=item.id,
        x_data_lifetime_years=7.0,
        y_migration_years=4.0,
        z_crqc_horizon_years=8.0,
        required_security_years=11.0,
        time_margin_years=-3.0,
        exposure_score=100.0,
        urgency="critical",
    )
    document = json.loads(
        CycloneDx16CbomExporter().export(
            asset=_asset(),
            findings=(item,),
            assessments=(),
            recommendations=(),
            recommendation_plans=(),
            evidence=(),
            context=_context(),
            business_context=business,
            mosca_evaluations=(mosca,),
        )
    )
    root_props = {
        entry["name"]: entry["value"] for entry in document["metadata"]["component"]["properties"]
    }
    assert root_props["org.qrypton.business.criticality"] == "critical"
    assert root_props["org.qrypton.business.data-classification"] == "restricted"
    assert root_props["org.qrypton.business.internet-exposed"] == "true"
    assert root_props["org.qrypton.business.owner"] == "team-crypto"
    assert json.loads(root_props["org.qrypton.business.regulatory-scopes"]) == ["pci-dss"]
    finding_props = {
        entry["name"]: entry["value"] for entry in document["components"][0]["properties"]
    }
    mosca_doc = json.loads(finding_props["org.qrypton.mosca"])
    assert mosca_doc["urgency"] == "critical"
    assert mosca_doc["x_data_lifetime_years"] == 7.0
    assert mosca_doc["z_crqc_horizon_years"] == 8.0


def test_invalid_document_is_rejected_by_official_schema() -> None:
    with pytest.raises(CBOMValidationError):
        CycloneDx16CbomExporter().validate(b'{"bomFormat":"wrong","specVersion":"1.6"}')
