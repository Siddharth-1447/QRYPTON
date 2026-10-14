"""Persistence, scope, atomicity and observation semantics of inventory investigation."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import BusinessContextPayload, ScanRequest, _build_request, app
from qrypton.contracts.enums import ObservationState
from qrypton.contracts.models import EvidenceLocation, Observation
from qrypton.storage.investigation import InventoryViewConfig, InvestigationStore
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run

TENANT = "tenant_" + "a" * 52
RUN = "run_" + "b" * 52
FINDING = "finding_" + "b" * 52
OTHER_FINDING = "finding_" + "c" * 52


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, TestClient]:
    database = tmp_path / "inventory.db"
    store = SqliteRunStore(database)
    store.finalize_run(create_sample_run(TENANT, RUN).model_copy(update={"recommendations": ()}))
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(database))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT)
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv(
        "QRYPTON_ACCESS_TOKENS",
        json.dumps(
            {
                hashlib.sha256(token.encode()).hexdigest(): {
                    "subject": "test-engineer",
                    "role": "Security Engineer",
                }
            }
        ),
    )
    return database, TestClient(app, headers={"Authorization": f"Bearer {token}"})


def test_bulk_actions_survive_reopen_and_reconcile_all_read_endpoints(workspace) -> None:
    database, client = workspace
    original = client.get(f"/api/v1/inventory?run_id={RUN}").json()
    for action, extra in [("roadmap", {}), ("owner", {"owner": "Platform Security"})]:
        result = client.patch(
            "/api/v1/inventory/actions",
            json={
                "run_id": RUN,
                "finding_ids": [FINDING, OTHER_FINDING, FINDING],
                "action": action,
                **extra,
            },
        )
        assert result.status_code == 200
        assert result.json() == {"updated": 2}
    reopened = InvestigationStore(database)
    try:
        assert reopened.decisions(TENANT, RUN)[FINDING].owner == "Platform Security"
        assert reopened.decisions("other", RUN) == {}
    finally:
        reopened.close()
    dashboard = client.get(f"/api/v1/dashboard?run_id={RUN}").json()
    inventory = client.get(f"/api/v1/inventory?run_id={RUN}").json()
    assert inventory == dashboard["inventory"]
    for before, after in zip(original, inventory, strict=True):
        assert after["assigned_owner"] == "Platform Security"
        assert after["migration_status"] == "New"
        assert after["in_roadmap"] is True
        for key in ("risk_level", "risk_score", "evidence_rows", "observations"):
            assert before[key] == after[key]
    detail = client.get(f"/api/v1/findings/{FINDING}?run_id={RUN}").json()
    assert detail["migration_status"] == "New"
    roadmap = client.get(f"/api/v1/roadmap?run_id={RUN}").json()
    assert {row["finding_id"] for row in roadmap} == {FINDING, OTHER_FINDING}
    assert all(row["assigned_owner"] == "Platform Security" for row in roadmap)
    assert all("Analyst added" in row["action"] for row in roadmap)


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"action": "owner"}, 422),
        ({"action": "owner", "owner": " "}, 422),
        ({"action": "status", "status": "invalid"}, 422),
        ({"action": "status", "status": "migrated", "tenant_id": "other"}, 422),
        ({"action": "roadmap", "finding_ids": [FINDING, "finding_" + "z" * 52]}, 404),
        ({"action": "roadmap", "run_id": "run_" + "z" * 52}, 404),
        ({"action": "roadmap", "finding_ids": []}, 422),
    ],
)
def test_invalid_batch_does_not_partially_write(workspace, payload, code) -> None:
    database, client = workspace
    response = client.patch(
        "/api/v1/inventory/actions",
        json={
            "run_id": RUN,
            "finding_ids": [FINDING],
            **payload,
        },
    )
    assert response.status_code == code
    store = InvestigationStore(database)
    try:
        assert store.decisions(TENANT, RUN) == {}
    finally:
        store.close()


def test_other_tenant_cannot_modify_a_run(workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    _, client = workspace
    monkeypatch.setenv("QRYPTON_TENANT_ID", "tenant_" + "c" * 52)
    response = client.patch(
        "/api/v1/inventory/actions",
        json={
            "run_id": RUN,
            "finding_ids": [FINDING],
            "action": "roadmap",
        },
    )
    assert response.status_code == 404


def test_saved_view_persists_updates_by_name_and_is_tenant_scoped(workspace) -> None:
    database, client = workspace
    state = InventoryViewConfig(
        q="payments",
        exposure="yes",
        timeline="overflow",
        view="raw",
        expanded=["f:one"],
    ).model_dump()
    saved = client.post("/api/v1/inventory/views", json={"name": "Payments team", "state": state})
    assert saved.status_code == 200
    view_id = saved.json()["id"]
    assert client.get("/api/v1/inventory/views").json()[0]["state"] == state
    updated = client.post(
        "/api/v1/inventory/views",
        json={
            "name": "Payments team",
            "state": {**state, "risk": "critical"},
        },
    )
    assert updated.json()["id"] == view_id
    reopened = InvestigationStore(database)
    try:
        assert reopened.views(TENANT)[0].state.risk == "critical"
        assert reopened.views("other") == []
        assert not reopened.delete_view("other", view_id)
    finally:
        reopened.close()
    assert client.delete(f"/api/v1/inventory/views/{view_id}").status_code == 200
    assert client.get("/api/v1/inventory/views").json() == []
    assert client.delete(f"/api/v1/inventory/views/{view_id}").status_code == 404
    invalid = client.post("/api/v1/inventory/views", json={"name": " ", "state": state})
    assert invalid.status_code == 422


def test_projection_keeps_observed_false_zero_and_absence_distinct(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "crypto.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    request, _ = _build_request(
        ScanRequest(
            target_type="source_repo",
            repository=str(source),
            data_lifetime=0,
            migration_time=2,
            crqc_horizon=10,
            business_context=BusinessContextPayload(
                system_name="Payments",
                environment="production",
                business_criticality="high",
                data_lifetime=0,
                internet_exposure=False,
            ),
        )
    )
    run = create_sample_run(TENANT, RUN)
    findings = list(run.findings)
    algorithm = findings[0].algorithm.value
    assert algorithm is not None
    algorithm = algorithm.model_copy(
        update={
            "key_size_bits": Observation(
                state=ObservationState.CONFIRMED_ABSENT,
                basis_evidence_ids=findings[0].evidence_ids,
                rationale="Explicit inspection established no key-size field.",
            )
        }
    )
    findings[0] = findings[0].model_copy(
        update={
            "algorithm": Observation(
                state=ObservationState.OBSERVED,
                value=algorithm,
                basis_evidence_ids=findings[0].evidence_ids,
            )
        }
    )
    evidence = list(run.evidence)
    evidence[0] = evidence[0].model_copy(
        update={
            "location": EvidenceLocation(relative_path="crypto.py", line_start=2),
        }
    )
    enriched = run.model_copy(
        update={
            "asset": request.asset.model_copy(update={"id": findings[0].asset_id}),
            "business_context": request.business_context,
            "findings": tuple(findings),
            "evidence": tuple(evidence),
        }
    )
    view = SqliteDashboardDataProvider.run_view_from_result(enriched)
    row = view.inventory[0]
    assert row.application == "Payments"
    assert row.environment == "production"
    assert row.observations["exposure"].value is False
    assert row.observations["data_lifetime"].value == 0
    assert row.observations["key_size"].state == ObservationState.CONFIRMED_ABSENT
    assert row.observations["mode"].state == ObservationState.NOT_OBSERVED
    assert row.evidence_rows[0].location == "crypto.py · line 2"
    assert not row.missing_business_context
    absent_context = enriched.model_copy(update={"business_context": None})
    missing_row = SqliteDashboardDataProvider.run_view_from_result(absent_context).inventory[0]
    assert missing_row.observations["exposure"].state == ObservationState.UNKNOWN


def test_roadmap_addition_preserves_an_existing_migration_status(workspace) -> None:
    database, _ = workspace
    store = InvestigationStore(database)
    try:
        store.apply(TENANT, RUN, [FINDING], "status", status="migrated")
        store.apply(TENANT, RUN, [FINDING], "roadmap")
        assert store.decisions(TENANT, RUN)[FINDING].migration_status == "Mitigated"
        with pytest.raises(ValueError):
            store.apply(TENANT, RUN, [], "roadmap")
    finally:
        store.close()
