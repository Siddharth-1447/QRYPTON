"""History summaries match canonical runs without reading evidence models."""

from collections import Counter

from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.api.scan_history import export_summary, scan_history_page
from qrypton.contracts.models import Asset
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run


def test_summary_fields_match_persisted_scan_and_skip_full_deserialization(tmp_path, monkeypatch):
    database = tmp_path / "history.sqlite3"
    tenant = "tenant_" + "a" * 52
    run = create_sample_run(tenant, "run_" + "b" * 52)
    store = SqliteRunStore(database)
    store.finalize_run(run)
    rows, total = scan_history_page(store._connection, tenant, 50, 0)
    assert total == 1
    row = rows[0]
    assert row["started_at"] == run.started_at
    assert row["completed_at"] == run.completed_at
    assert row["total_findings"] == len(run.findings)
    assert row["artifact"] == (run.asset.external_reference if run.asset else "unavailable")
    assert row["status"] == run.status.value.upper()
    assessments = {assessment.finding_id: assessment for assessment in run.assessments}
    counts = Counter(assessment.level.value for assessment in assessments.values())
    for tier in ("critical", "high", "medium", "low", "informational", "unknown"):
        assert row[f"{tier}_findings_count"] == counts[tier]
    assert row["unassessed_findings_count"] == sum(f.id not in assessments for f in run.findings)
    store.close()


def test_export_summary_matches_canonical_posture_without_full_projection(tmp_path, monkeypatch):
    database = tmp_path / "export.sqlite3"
    tenant = "tenant_" + "a" * 52
    run = create_sample_run(tenant, "run_" + "b" * 52)
    store = SqliteRunStore(database)
    store.finalize_run(run)
    preview = export_summary(store._connection, tenant, run.run_id)
    posture = SqliteDashboardDataProvider.run_view_from_result(run).posture
    assert preview["asset_count"] == posture.unique_asset_ids
    assert preview["finding_count"] == posture.total_findings
    for tier in ("critical", "high", "medium", "low", "informational", "unknown", "unassessed"):
        assert preview["risk_summary"][tier] == getattr(posture, f"{tier}_findings_count")
    assert preview["cbom_available"] == (run.cbom is not None)
    assert export_summary(store._connection, "tenant_" + "z" * 52, run.run_id) is None
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant)

    def no_full_scan(*args, **kwargs):
        raise AssertionError("Preview must not materialize a full scan")

    monkeypatch.setattr(SqliteRunStore, "get_run", no_full_scan)
    client = TestClient(app)
    assert client.get(f"/api/v1/scans/{run.run_id}/export-preview").status_code == 200

    def no_full_scan(*args, **kwargs):
        raise AssertionError("History must not materialize the full assessment")

    monkeypatch.setattr(SqliteRunStore, "get_run", no_full_scan)
    monkeypatch.setenv("QRYPTON_DB", str(database))
    client = TestClient(app)
    response = client.get("/api/v1/scans?limit=50")
    assert response.status_code == 200
    assert response.headers["x-total-count"] == "1"
    assert response.json()[0]["scan_id"] == run.run_id


def test_pagination_tenant_isolation_and_metadata_only_rows(tmp_path):
    store = SqliteRunStore(tmp_path / "history.sqlite3")
    tenant, other = "tenant_" + "a" * 52, "tenant_" + "c" * 52
    store.finalize_run(create_sample_run(tenant, "run_" + "b" * 52))
    store.finalize_run(create_sample_run(other, "run_" + "d" * 52))
    store._connection.execute(
        "INSERT INTO qrypton_runs(tenant_id,run_id,status) VALUES(?,?,?)",
        (tenant, "run_" + "e" * 52, "queued"),
    )
    store._connection.commit()
    rows, total = scan_history_page(store._connection, tenant, 1, 0)
    assert total == 2
    assert len(rows) == 1
    assert rows[0]["status"] == "QUEUED"
    assert rows[0]["total_findings"] == 0
    assert rows[0]["highest_risk"] is None
    assert rows[0]["artifact"] == "unavailable"
    rows, total = scan_history_page(store._connection, tenant, 1, 1)
    assert rows[0]["run_id"] == "run_" + "b" * 52
    assert total == 2
    assert scan_history_page(store._connection, "tenant_" + "z" * 52, 50, 0) == ([], 0)
    store.close()


def test_comparison_choices_are_lightweight_and_tenant_scoped(tmp_path, monkeypatch):
    from tests.ui.conftest import sample_provenance

    database = tmp_path / "choices.sqlite3"
    tenant = "tenant_" + "a" * 52
    run = create_sample_run(tenant, "run_" + "b" * 52)
    run = run.model_copy(
        update={
            "asset": Asset(
                id="asset_" + "a" * 52,
                tenant_id=tenant,
                kind="application",
                name="Payments",
                external_reference="payments",
                created_at=run.started_at,
                updated_at=run.started_at,
                provenance=sample_provenance(),
            )
        }
    )
    store = SqliteRunStore(database)
    store.finalize_run(run)
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant)

    def forbid(*args, **kwargs):
        raise AssertionError("Choices must not deserialize full scans")

    monkeypatch.setattr(SqliteRunStore, "get_run", forbid)
    client = TestClient(app)
    response = client.get("/api/v1/scan-comparison/options")
    assert response.status_code == 200
    assert response.json()[0]["id"] == run.run_id
    assert response.json()[0]["asset_id"] == run.asset.id
    assert "findings" not in response.json()[0]
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "c" * 52)
    assert client.get("/api/v1/scan-comparison/options").json() == []
