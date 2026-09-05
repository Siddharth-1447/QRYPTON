from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from qrypton.contracts.enums import AlgorithmFamily, AssetKind, EvidenceKind
from qrypton.contracts.errors import CBOMExportError, CBOMValidationError
from qrypton.contracts.models import Asset, Evidence, EvidenceLocation
from qrypton.exporters.cyclonedx_1_6 import CbomExportContext, CycloneDx16CbomExporter
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
            asset=_asset(AssetKind.HOST),
            findings=(item,),
            assessments=(),
            recommendations=(),
            recommendation_plans=(),
            evidence=(),
            context=_context(),
        )


def test_invalid_document_is_rejected_by_official_schema() -> None:
    with pytest.raises(CBOMValidationError):
        CycloneDx16CbomExporter().validate(b'{"bomFormat":"wrong","specVersion":"1.6"}')
