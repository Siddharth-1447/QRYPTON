"""Dynamic PDF report engine: POST /api/v1/reports/pdf and reportlab sections."""

from __future__ import annotations

import csv
import importlib
import io
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.api.reporting import _target_label, executive_pdf
from qrypton.contracts.enums import AlgorithmFamily
from qrypton.contracts.models import Observation
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run
from tests.workflows.conftest import (
    crypto_source_tree,
    scan_payload,
    settle_scan,
    submit_scan,
)
from tests.workflows.conftest import (
    isolated_backend as _isolated_backend,
)

client = TestClient(app)
isolated_backend = _isolated_backend


@pytest.mark.parametrize(
    ("family", "targets", "expected"),
    [
        ("asymmetric_encryption", ("ML-KEM-768",), "ML-KEM-768"),
        ("signature", ("ML-DSA-65", "SLH-DSA"), "ML-DSA-65, SLH-DSA"),
        ("hash", (), "Collision-resistance review: SHA-3 / SHA-512"),
        ("hash", ("SHA-512",), "SHA-512"),
        ("hash", ("ML-KEM-768", "ML-DSA"), "Collision-resistance review: SHA-3 / SHA-512"),
        ("symmetric_cipher", (), "AEAD / key length review: AES-256-GCM"),
        ("symmetric_cipher", ("AES-256-GCM",), "AES-256-GCM"),
        ("symmetric_cipher", ("ML-KEM",), "AEAD / key length review: AES-256-GCM"),
        ("asymmetric_encryption", (), "Validation / Manual Review Required"),
        ("mac", (), "Validation / Manual Review Required"),
        ("kdf", (), "Validation / Manual Review Required"),
        ("unknown", (), "Validation / Manual Review Required"),
        ("unknown", ("ML-KEM",), "Validation / Manual Review Required"),
    ],
)
def test_pdf_targets_follow_observed_family(family, targets, expected):
    item = SimpleNamespace(algorithm_family=family, identity_status="identified")
    assert _target_label(item, SimpleNamespace(target_algorithms=targets)) == expected


def test_pdf_unidentified_or_missing_finding_requires_review():
    row = SimpleNamespace(target_algorithms=("ML-KEM",))
    item = SimpleNamespace(algorithm_family="hash", identity_status="partially_identified")
    assert _target_label(item, row) == "Validation / Manual Review Required"
    assert _target_label(None, row) == "Validation / Manual Review Required"


def _report_fixture():
    return create_sample_run("tenant_" + "a" * 52, "run_" + "b" * 52)


def test_pdf_page_totals_preserve_cross_reference_offsets():
    run = _report_fixture()
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    pdf = executive_pdf(
        scan_id=run.run_id,
        run=run,
        posture=view.posture,
        inventory=list(view.inventory),
        mosca=[],
        roadmap=list(view.roadmap),
    )
    startxref = re.search(rb"startxref\s+(\d+)\s+%%EOF", pdf)
    assert startxref is not None
    xref = pdf[int(startxref.group(1)) :]
    assert xref.startswith(b"xref\n")
    entries = re.search(rb"xref\s+0\s+(\d+)\s+", xref)
    assert entries is not None
    rows = xref[entries.end() :].splitlines()
    for object_id, row in enumerate(rows[: int(entries.group(1))]):
        offset, _, state = row.split()
        if state == b"n":
            assert pdf[int(offset) :].startswith(f"{object_id} 0 obj".encode())
    pages = len(re.findall(rb"/Type\s*/Page\b", pdf))
    assert pages >= 2
    for page in range(1, pages + 1):
        assert f"Page {page} of {pages}".encode() in pdf


def test_sha256_pdf_roadmap_has_hash_guidance_without_asymmetric_fallback():
    run = _report_fixture()
    finding = run.findings[0]
    algorithm = finding.algorithm.value.model_copy(
        update={
            "canonical_name": "sha-256",
            "family": AlgorithmFamily.HASH,
        }
    )
    finding = finding.model_copy(
        update={"algorithm": finding.algorithm.model_copy(update={"value": algorithm})}
    )
    recommendation = run.recommendations[0].model_copy(
        update={
            "replacement_algorithm": Observation(state="unknown"),
            "action": "Validate collision resistance requirements",
        }
    )
    run = run.model_copy(
        update={
            "findings": (finding,),
            "recommendations": (recommendation,),
            "recommendation_plans": (),
        }
    )
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    pdf = executive_pdf(
        scan_id=run.run_id,
        run=run,
        posture=view.posture,
        inventory=list(view.inventory),
        mosca=[],
        roadmap=list(view.roadmap),
    )
    roadmap = pdf.split(b"NIST PQC Migration Roadmap", 1)[1]
    assert b"SHA-3 / SHA-512" in roadmap
    assert b"ML-KEM" not in roadmap and b"ML-DSA" not in roadmap


def test_roadmap_keeps_highest_priorities_before_truncating(monkeypatch):
    reporting = importlib.import_module("qrypton.api.reporting")
    run = _report_fixture()
    base = run.recommendations[0]
    recs = tuple(
        base.model_copy(update={"priority": priority, "action": f"ActionRank{priority:02d}"})
        for priority in range(1, 46)
    )
    run = run.model_copy(update={"recommendations": recs})
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    assert [row.priority for row in view.roadmap] == list(range(45, 0, -1))
    highest = []
    original = reporting._pqc_target

    def capture(item, by_finding):
        if item.finding_id == base.finding_id:
            highest.append(by_finding[item.finding_id].priority)
        return original(item, by_finding)

    monkeypatch.setattr(reporting, "_pqc_target", capture)
    pdf = executive_pdf(
        scan_id=run.run_id,
        run=run,
        posture=view.posture,
        inventory=list(view.inventory),
        mosca=[],
        roadmap=list(reversed(view.roadmap)),
    )
    assert highest == [45]
    roadmap = pdf.split(b"NIST PQC Migration Roadmap", 1)[1]
    positions = [roadmap.index(f"Priority {priority}:".encode()) for priority in range(45, 5, -1)]
    assert positions == sorted(positions)
    assert b"Priority 5:" not in roadmap
    assert b"5 additional" in roadmap


@pytest.mark.parametrize("explicit_tenant", [False, True])
def test_pdf_loads_requested_run_once_and_builds_all_details(
    tmp_path,
    monkeypatch,
    explicit_tenant,
):
    api = importlib.import_module("qrypton.api.app")
    run = _report_fixture()
    database = tmp_path / "report.sqlite3"
    store = SqliteRunStore(database)
    try:
        store.finalize_run(run)
        store.finalize_run(run.model_copy(update={"run_id": "run_" + "c" * 52}))
    finally:
        store.close()
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "z" * 52)
    reads = []
    original = SqliteRunStore.get_run

    def count_read(self, *, tenant_id, run_id):
        reads.append((tenant_id, run_id))
        return original(self, tenant_id=tenant_id, run_id=run_id)

    def no_per_finding_queries(*args, **kwargs):
        raise AssertionError("Report must use its already deserialized run")

    monkeypatch.setattr(SqliteRunStore, "get_run", count_read)
    monkeypatch.setattr(SqliteDashboardDataProvider, "get_finding_detail", no_per_finding_queries)
    captured = {}

    def capture_pdf(**kwargs):
        captured.update(kwargs)
        return b"%PDF-test"

    monkeypatch.setattr(api, "executive_pdf", capture_pdf)
    api._build_pdf_report(run.run_id, run.tenant_id if explicit_tenant else None)
    assert reads == [(run.tenant_id, run.run_id)]
    assert set(captured["finding_details"]) == {finding.id for finding in run.findings}
    for detail in captured["finding_details"].values():
        assert detail.assessment is not None
        assert detail.evidence_provenance and detail.recommendations and detail.mosca


def _source_scan_id(ctx: dict[str, Any], tmp_path: Path) -> str:
    root = crypto_source_tree(tmp_path / "proj")
    scan_id = submit_scan(
        scan_payload(target_type="source_repo", repository=str(root), branch="main")
    )
    assert settle_scan(scan_id) in ("COMPLETED", "PARTIAL")
    return scan_id


def test_post_pdf_report_contains_all_sections(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    scan_id = _source_scan_id(isolated_backend, tmp_path)
    response = client.post("/api/v1/reports/pdf", json={"run_id": scan_id})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    pdf = response.content
    assert pdf[:5] == b"%PDF-"
    text_markers = [
        b"QRYPTON",
        b"Post-Quantum Cryptography Assessment Report",
        b"FIPS 203",
        b"FIPS 204",
        b"FIPS 205",
        b"Harvest-Now-Decrypt-Later",
        b"Mosca",
        b"RSA-2048",
        b"ML-KEM",
        b"Page 1 of",
    ]
    for marker in text_markers:
        assert marker in pdf, f"PDF missing {marker!r}"
    inventory = client.get(f"/api/v1/inventory?run_id={scan_id}").json()
    assert inventory, "expected findings for the crypto fixture"
    for finding in inventory:
        assert finding["finding_id"].encode() in pdf


def test_post_pdf_report_accepts_scan_id_alias(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    scan_id = _source_scan_id(isolated_backend, tmp_path)
    response = client.post("/api/v1/reports/pdf", json={"scan_id": scan_id})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"


def test_post_pdf_report_rejects_missing_and_unknown_runs(
    isolated_backend: dict[str, Any],
) -> None:
    assert client.post("/api/v1/reports/pdf", json={}).status_code == 422
    # Seed one run so history exists; an unknown id must then 404 explicitly.
    scan_id = submit_scan(
        scan_payload(
            target_type="cloud_kms",
            repository="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )
    )
    assert settle_scan(scan_id) in ("COMPLETED", "PARTIAL")
    unknown = client.post("/api/v1/reports/pdf", json={"run_id": "run_" + "0" * 52})
    assert unknown.status_code == 404
    assert unknown.json().get("detail")


def test_pdf_report_empty_scan_stays_valid(isolated_backend: dict[str, Any]) -> None:
    scan_id = submit_scan(
        scan_payload(
            target_type="cloud_kms",
            repository="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )
    )
    assert settle_scan(scan_id) in ("COMPLETED", "PARTIAL")
    response = client.post("/api/v1/reports/pdf", json={"run_id": scan_id})
    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"
    assert b"QRYPTON" in response.content


def test_legacy_get_report_endpoint_still_serves_pdf(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    scan_id = _source_scan_id(isolated_backend, tmp_path)
    response = client.get(f"/api/v1/scans/{scan_id}/report/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"


def test_persisted_cbom_identity_matches_api_inventory(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    scan_id = _source_scan_id(isolated_backend, tmp_path)
    inventory = client.get(f"/api/v1/inventory?run_id={scan_id}").json()
    cbom_response = client.get(f"/api/v1/scans/{scan_id}/cbom")
    assert cbom_response.status_code == 200
    cbom = json.loads(cbom_response.content)
    components = {
        next(
            (
                item["value"]
                for item in component.get("properties", [])
                if item.get("name") == "org.qrypton.finding.id"
            ),
            None,
        ): component
        for component in cbom["components"]
    }
    assert set(components) == {row["finding_id"] for row in inventory}
    for row in inventory:
        component = components[row["finding_id"]]
        properties = {item["name"]: item["value"] for item in component["properties"]}
        assert properties["org.qrypton.identity.label"] == row["identity_label"]
        assert properties["org.qrypton.identity.status"] == row["identity_status"]
        detail = client.get(f"/api/v1/findings/{row['finding_id']}?run_id={scan_id}")
        assert detail.status_code == 200
        assert json.loads(properties["org.qrypton.finding.canonical"]) == detail.json()["finding"]
        if row["algorithm_family"] is not None:
            assert properties["org.qrypton.algorithm.family"] == row["algorithm_family"]

    csv_response = client.get(f"/api/v1/scans/{scan_id}/cbom/export?format=csv")
    assert csv_response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert {row["Finding ID"] for row in rows} == set(components)
    csv_by_id = {row["Finding ID"]: row for row in rows}
    for finding_id, component in components.items():
        properties = {item["name"]: item["value"] for item in component["properties"]}
        assert (
            csv_by_id[finding_id]["Algorithm Identity"] == properties["org.qrypton.identity.label"]
        )
        assert json.loads(csv_by_id[finding_id]["Canonical Finding (JSON)"]) == json.loads(
            properties["org.qrypton.finding.canonical"]
        )


def test_risk_views_reconcile_for_one_persisted_run(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    scan_id = _source_scan_id(isolated_backend, tmp_path)
    inventory = client.get(f"/api/v1/inventory?run_id={scan_id}").json()
    posture = client.get(f"/api/v1/posture?run_id={scan_id}").json()
    heatmap = client.get(f"/api/v1/heatmap?run_id={scan_id}").json()
    risk_matrix = client.get(f"/api/v1/risk?run_id={scan_id}").json()
    mosca = client.get(f"/api/v1/mosca/eval?run_id={scan_id}").json()

    finding_ids = {item["finding_id"] for item in inventory}
    assert posture["total_findings"] == len(finding_ids)
    assert sum(cell["finding_count"] for cell in heatmap) == len(finding_ids)
    assert {finding_id for cell in heatmap for finding_id in cell["finding_ids"]} == finding_ids
    assert risk_matrix["scan_id"] == scan_id
    assert risk_matrix["cells"] == heatmap
    assert {point["finding_id"] for point in mosca} == finding_ids
    assert posture["critical_findings_count"] + posture["high_findings_count"] + posture[
        "medium_findings_count"
    ] + posture["low_findings_count"] + posture["informational_findings_count"] + posture[
        "unknown_findings_count"
    ] + posture["unassessed_findings_count"] == len(finding_ids)
