"""End-to-end backend tests: five workflows through the existing HTTP API.

Each test submits through POST /api/v1/scans, waits for settlement via
GET /api/v1/scans/{id}, then verifies persistence through a FRESH store
instance plus the existing per-run read APIs. Scanner dispatch is proven
from the persisted RunResult scanner names - never a generic flag.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from qrypton.application.schemas import RunResult
from qrypton.storage.sqlite import SqliteRunStore

from .conftest import (
    build_docker_tar,
    build_minimal_elf,
    build_wheel,
    cbom_root,
    crypto_source_tree,
    fresh_store,
    isolated_backend,  # noqa: F401  (fixture)
    root_properties,
    scan_payload,
    settle_scan,
    submit_scan,
    upload_artifact,
    zip_bytes,
)

TERMINAL_OK = ("COMPLETED", "PARTIAL")


def _persisted(db: Path, tenant: str, scan_id: str) -> RunResult:
    """Read back through a brand-new repository instance (proves persistence)."""
    store = fresh_store(db)
    try:
        result = store.get_run(tenant_id=tenant, run_id=scan_id)  # type: ignore[arg-type]
    finally:
        store.close()
    assert result is not None, f"run {scan_id} missing from persistence"
    return result


def _history_lists_run(db: Path, tenant: str, scan_id: str, status: str) -> None:
    store = fresh_store(db)
    try:
        runs = store.list_runs(tenant_id=tenant)  # type: ignore[arg-type]
    finally:
        store.close()
    assert (tenant, scan_id, status) in runs, f"history has no {status} entry for {scan_id}"


def _check_read_apis(ctx: dict[str, Any], scan_id: str, result: RunResult) -> bytes:
    """Scan History retrieval through the existing per-run endpoints."""
    client = ctx["client"]
    status = client.get(f"/api/v1/scans/{scan_id}").json()
    assert status["status"] == result.status.value.upper().replace("-", "_")

    posture = client.get(f"/api/v1/posture?run_id={scan_id}").json()
    assert posture["total_findings"] == len(result.findings)
    inventory = client.get(f"/api/v1/inventory?run_id={scan_id}").json()
    assert len(inventory) == len(result.findings)

    if result.findings:
        assert result.assessments, "findings without risk assessments"
        mosca = client.get(f"/api/v1/mosca/eval?run_id={scan_id}").json()
        persisted_urgencies = sorted(e.urgency for e in result.mosca_evaluations)
        api_urgencies = sorted(point["urgency"] for point in mosca)
        assert api_urgencies == persisted_urgencies

    cbom_response = client.get(f"/api/v1/scans/{scan_id}/cbom")
    assert cbom_response.status_code == 200
    stored = fresh_store(ctx["db"])
    try:
        stored_cbom = stored.get_cbom(tenant_id=ctx["tenant"], run_id=scan_id)  # type: ignore[arg-type]
    finally:
        stored.close()
    assert stored_cbom is not None and bytes(stored_cbom) == cbom_response.content
    assert f"sha256:{hashlib.sha256(cbom_response.content).hexdigest()}" == result.cbom_digest
    return cbom_response.content


def _check_cbom_root(
    cbom: bytes,
    *,
    expect_kind: str,
    expect_target_tag: str,
    expect_business: bool = True,
) -> dict[str, str]:
    root = cbom_root(cbom)
    assert root["type"] == expect_kind
    props = root_properties(root)
    tags = [props[k] for k in props if k == "org.qrypton.asset.tag"]
    assert expect_target_tag in tags, f"{expect_target_tag} missing from {tags}"
    if expect_business:
        assert props.get("org.qrypton.business.criticality") == "critical"
        assert props.get("org.qrypton.business.data-classification") == "restricted"
    return props


def test_source_code_workflow(isolated_backend: dict[str, Any], tmp_path: Path) -> None:
    """TEST 1 (local fixture): source artifact -> source scanner -> CBOM/risk/history."""
    root = crypto_source_tree(tmp_path / "proj")
    scan_id = submit_scan(
        scan_payload(target_type="source_repo", repository=str(root), branch="main")
    )
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-source"}, f"unexpected scanner set {scanners}"
    assert len(result.findings) >= 1, "crypto fixture produced no findings"
    assert result.cbom, "CBOM missing from persisted RunResult"

    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    history = isolated_backend["client"].get("/api/v1/scans")
    assert history.status_code == 200
    history_row = next(item for item in history.json() if item["scan_id"] == scan_id)
    assert history_row["artifact"] == result.asset.external_reference
    assert history_row["target_type"] == "source_repo"
    assert history_row["total_findings"] == len(result.findings)
    assert history_row["highest_risk"] in {"critical", "high", "medium", "low", "unknown"}
    _check_cbom_root(cbom, expect_kind="application", expect_target_tag="target:source_repo")
    root = cbom_root(cbom)
    tags = [
        item["value"]
        for item in root.get("properties", [])
        if item.get("name") == "org.qrypton.asset.tag"
    ]
    assert "source:local_file" in tags


def test_source_archive_upload_workflow(isolated_backend: dict[str, Any], tmp_path: Path) -> None:
    root = crypto_source_tree(tmp_path / "proj")
    data = zip_bytes({"crypto_service.py": (root / "crypto_service.py").read_bytes()})
    artifact = upload_artifact("proj.zip", data)
    scan_id = submit_scan(
        scan_payload(target_type="source_archive", repository="", artifact_id=artifact["artifact_id"])
    )
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-source"}
    assert len(result.findings) >= 1
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    _check_cbom_root(cbom, expect_kind="application", expect_target_tag="target:source_archive")


def test_binary_workflow_without_repository_url(isolated_backend: dict[str, Any]) -> None:
    """TEST 2: the payload carries NO repository key at all."""
    artifact = upload_artifact("crypto.bin", build_minimal_elf())
    payload = scan_payload(target_type="binary", artifact_id=artifact["artifact_id"])
    assert "repository" not in payload
    scan_id = submit_scan(payload)
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-binary"}, f"binary run misrouted: {scanners}"
    assert "qrypton-source" not in scanners
    assert len(result.findings) >= 1, "binary imports produced no findings"
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    props = _check_cbom_root(cbom, expect_kind="file", expect_target_tag="target:binary")
    assert props.get("org.qrypton.asset.external-reference", "").startswith("crypto.bin")


def test_library_workflow_without_repository_url(isolated_backend: dict[str, Any]) -> None:
    """TEST 3: real .whl bytes; must not route through the source scanner."""
    name, data = build_wheel()
    artifact = upload_artifact(name, data)
    payload = scan_payload(target_type="dependency_manifest", artifact_id=artifact["artifact_id"])
    assert "repository" not in payload
    scan_id = submit_scan(payload)
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-library"}, f"library run misrouted: {scanners}"
    assert "qrypton-source" not in scanners
    assert len(result.findings) >= 1
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    _check_cbom_root(cbom, expect_kind="application", expect_target_tag="target:dependency_manifest")


def test_container_archive_workflow_without_repository_url(isolated_backend: dict[str, Any]) -> None:
    """TEST 4a: real docker-save-style tar reaches the container scanner."""
    name, data = build_docker_tar()
    artifact = upload_artifact(name, data)
    payload = scan_payload(target_type="container_image", artifact_id=artifact["artifact_id"])
    assert "repository" not in payload
    scan_id = submit_scan(payload)
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-container"}, f"container run misrouted: {scanners}"
    assert "qrypton-source" not in scanners
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    _check_cbom_root(cbom, expect_kind="container", expect_target_tag="target:container_image")


def test_container_reference_workflow(isolated_backend: dict[str, Any]) -> None:
    """TEST 4b: image reference without registry pull."""
    scan_id = submit_scan(scan_payload(target_type="container_image", repository="nginx:latest"))
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-container"}
    assert "qrypton-source" not in scanners
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    props = _check_cbom_root(cbom, expect_kind="container", expect_target_tag="target:container_image")
    assert props.get("org.qrypton.asset.external-reference") == "nginx:latest"


def test_kms_valid_identifier_workflow(isolated_backend: dict[str, Any]) -> None:
    """TEST 5A: AWS identifier, no repository key, reaches the KMS scanner."""
    payload = scan_payload(
        target_type="cloud_kms",
        repository="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    )
    scan_id = submit_scan(payload)
    assert settle_scan(scan_id) in TERMINAL_OK

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-kms"}, f"kms run misrouted: {scanners}"
    assert "qrypton-source" not in scanners
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, result.status.value)
    cbom = _check_read_apis(isolated_backend, scan_id, result)
    _check_cbom_root(cbom, expect_kind="application", expect_target_tag="target:cloud_kms")


def test_kms_invalid_missing_and_unknown_fail_explicitly(isolated_backend: dict[str, Any]) -> None:
    """TEST 5B/C: explicit 422 states, no fabricated findings, nothing persisted."""
    client = isolated_backend["client"]
    store = fresh_store(isolated_backend["db"])
    try:
        before = len(store.list_runs(tenant_id=isolated_backend["tenant"]))  # type: ignore[arg-type]
    finally:
        store.close()

    for label, payload in (
        ("invalid", scan_payload(target_type="cloud_kms", repository="not-a-key")),
        ("missing", scan_payload(target_type="cloud_kms", repository="")),
        ("unknown-artifact", scan_payload(target_type="cloud_kms", repository="", artifact_id="0" * 32)),
    ):
        response = client.post("/api/v1/scans", json=payload)
        assert response.status_code == 422, f"{label}: expected 422, got {response.status_code}"
        assert response.json().get("detail"), f"{label}: failure without explanation"

    store = fresh_store(isolated_backend["db"])
    try:
        after = store.list_runs(tenant_id=isolated_backend["tenant"])  # type: ignore[arg-type]
    finally:
        store.close()
    assert len(after) == before, "rejected scans must not create history entries"


def test_failed_scan_persists_and_appears_in_history(
    isolated_backend: dict[str, Any], tmp_path: Path
) -> None:
    """RunResult persistence for failed scans via the REAL background worker."""
    import qrypton.api.app as api_app
    from qrypton.api.app import ScanRequest
    from qrypton.application.config import QryptonConfig, build_orchestrator

    target = tmp_path / "vanishing.bin"
    target.write_bytes(build_minimal_elf())
    request = ScanRequest(
        **scan_payload(target_type="binary", repository=str(target)),
    )
    run_request, _locator = api_app._build_request(request)
    config = QryptonConfig(
        workspace_root=tmp_path,
        database_path=isolated_backend["db"],
        id_secret=b"z" * 32,
    )
    scan_id = build_orchestrator(config).run_id_for(run_request)
    store = SqliteRunStore(isolated_backend["db"])
    try:
        store.begin_run(run_request, run_id=scan_id)  # type: ignore[arg-type]
    finally:
        store.close()
    target.unlink()  # artifact disappears after admission: worker must fail honestly
    api_app._run_scan_in_background(config, run_request)

    result = _persisted(isolated_backend["db"], isolated_backend["tenant"], scan_id)
    assert result.status.value == "failed"
    assert result.findings == (), "failed scans must not fabricate findings"
    _history_lists_run(isolated_backend["db"], isolated_backend["tenant"], scan_id, "failed")
    status = isolated_backend["client"].get(f"/api/v1/scans/{scan_id}").json()
    assert status["status"] == "FAILED"


def test_business_context_identical_across_target_types(isolated_backend: dict[str, Any]) -> None:
    """TEST 6: same context block yields the same CBOM business properties."""
    artifact = upload_artifact("crypto.bin", build_minimal_elf())
    binary_id = submit_scan(
        scan_payload(target_type="binary", artifact_id=artifact["artifact_id"])
    )
    kms_id = submit_scan(
        scan_payload(
            target_type="cloud_kms",
            repository="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )
    )
    assert settle_scan(binary_id) in TERMINAL_OK
    assert settle_scan(kms_id) in TERMINAL_OK

    client = isolated_backend["client"]
    business = []
    for scan_id in (binary_id, kms_id):
        root = cbom_root(client.get(f"/api/v1/scans/{scan_id}/cbom").content)
        props = root_properties(root)
        business.append({k: v for k, v in props.items() if k.startswith("org.qrypton.business.")})
    assert business[0] == business[1]
    assert business[0]["org.qrypton.business.criticality"] == "critical"
