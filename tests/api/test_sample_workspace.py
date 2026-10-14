"""Acceptance checks for the opt-in synthetic payment workspace."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.storage.sqlite import SqliteRunStore


def test_sample_workspace_uses_real_pipeline_and_removes_only_sample(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = tmp_path / "sample.sqlite3"
    monkeypatch.setenv("QRYPTON_DB", str(database))
    tenant = "tenant_" + "a" * 52
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant)
    client = TestClient(app)

    response = client.post("/api/v1/sample-workspace")
    assert response.status_code == 200, response.text
    current_id = response.json()["run_id"]
    earlier_id = response.json()["earlier_run_id"]
    assert current_id != earlier_id
    comparison = client.get(f"/api/v1/scan-comparison?before={earlier_id}&after={current_id}")
    assert comparison.status_code == 200, comparison.text
    assert all(
        comparison.json()["categories"][key] for key in ("New", "Resolved", "Changed", "Persistent")
    )
    search = client.get("/api/v1/workspace-search?q=internet-facing%20RSA%20critical")
    assert search.status_code == 200
    assert any(
        row["kind"] == "Finding" and "rsa" in row["label"].casefold() for row in search.json()
    )
    assert client.post("/api/v1/sample-workspace").json()["run_id"] == current_id

    history = client.get("/api/v1/scans?limit=5").json()
    assert [row["scan_id"] for row in history] == [current_id, earlier_id]
    assert all(row["sample_data"] for row in history)
    assert history[0]["critical_findings_count"] > history[1]["critical_findings_count"]
    dashboard = client.get(f"/api/v1/dashboard?run_id={current_id}")
    assert dashboard.status_code == 200
    assert dashboard.json()["posture"]["total_findings"] == history[0]["total_findings"]
    assert any(
        item["algorithm_name"] == "ml-kem" and item["quantum_resistant"]
        for item in dashboard.json()["inventory"]
    )

    store = SqliteRunStore(database)
    try:
        current = store.get_run(tenant_id=tenant, run_id=current_id)
        assert current is not None and current.cbom
        evidence_paths = {
            item.id: Path(str(item.location.relative_path)).name for item in current.evidence
        }
        cases: dict[str, list[tuple[str, str, str]]] = {}
        assessments = {item.finding_id: item for item in current.assessments}
        for finding in current.findings:
            paths = {evidence_paths[item] for item in finding.evidence_ids}
            assert len(paths) == 1
            algorithm = (
                finding.algorithm.value.canonical_name if finding.algorithm.value else "unknown"
            )
            assessment = assessments[finding.id]
            cases.setdefault(paths.pop(), []).append(
                (algorithm, assessment.level.value, assessment.mosca_urgency.value)
            )
        assert ("rsa", "critical", "critical") in cases["checkout.py"]
        assert ("rsa", "high", "low") in cases["internal_test_tool.py"]
        assert any(
            algorithm == "ecdsa" and level == "high"
            for algorithm, level, _ in cases["settlement.py"]
        )
        assert any(
            algorithm == "ecdh" and level == "high"
            for algorithm, level, _ in cases["settlement.py"]
        )
        assert ("ml-kem", "low", "not_applicable") in cases["hybrid_gateway.py"]
        assert any(level == "unknown" for _, level, _ in cases["unowned_callback.py"])
        assert current.finding_business_contexts.keys() <= {
            finding.id for finding in current.findings
        }
        finding_id = current.findings[0].id
    finally:
        store.close()

    assert client.get(f"/api/v1/findings/{finding_id}?run_id={current_id}").status_code == 200

    cbom = client.get(f"/api/v1/scans/{current_id}/cbom/export?format=json")
    assert cbom.status_code == 200
    document = json.loads(cbom.content)
    assert {
        item["value"]
        for item in document["metadata"]["component"]["properties"]
        if item["name"] == "org.qrypton.asset.tag"
    } >= {"sample-data"}
    assert client.get(f"/api/v1/scans/{current_id}/cbom/export?format=csv").status_code == 200
    assert client.get(f"/api/v1/scans/{current_id}/report/pdf").status_code == 200
    assert client.delete("/api/v1/sample-workspace").json() == {"removed": 2}
    assert client.get("/api/v1/scans?limit=5").json() == []
