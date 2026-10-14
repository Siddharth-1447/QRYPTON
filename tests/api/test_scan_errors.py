"""Scan failures retain actionable diagnostics without disclosing exception text."""

from __future__ import annotations

import importlib
import sqlite3
import urllib.error
from unittest.mock import Mock

import pytest

from qrypton.api.app import ScanRequest
from qrypton.api.scan_errors import public_failure_message, resolution_failure_code
from qrypton.contracts.enums import ObservationState, RunStatus
from qrypton.storage.sqlite import SqliteRunStore
from tests.api.test_worker_lifecycle import (
    PRIVATE_ERROR,
    RUN_ID,
    execute,
    persisted_failure,
)
from tests.api.test_worker_lifecycle import (
    worker_context as _worker_context,
)

worker_context = _worker_context
api = importlib.import_module("qrypton.api.app")


@pytest.mark.parametrize(
    ("cause", "code"),
    [
        (
            urllib.error.HTTPError("https://private.test/secret", 404, PRIVATE_ERROR, {}, None),
            "target_not_found",
        ),
        (
            urllib.error.HTTPError("https://private.test/secret", 403, PRIVATE_ERROR, {}, None),
            "target_access_denied",
        ),
        (
            urllib.error.HTTPError("https://private.test/secret", 429, PRIVATE_ERROR, {}, None),
            "target_service_unavailable",
        ),
        (
            urllib.error.HTTPError("https://private.test/secret", 503, PRIVATE_ERROR, {}, None),
            "target_service_unavailable",
        ),
        (urllib.error.URLError(TimeoutError(PRIVATE_ERROR)), "target_acquisition_timeout"),
        (urllib.error.URLError(PRIVATE_ERROR), "target_network_error"),
        (PermissionError(PRIVATE_ERROR), "target_access_denied"),
        (FileNotFoundError(PRIVATE_ERROR), "target_file_missing"),
        (RuntimeError(PRIVATE_ERROR), "target_resolution_failed"),
    ],
)
def test_wrapped_acquisition_failure_reaches_polling_safely(
    worker_context, monkeypatch, cause, code
):
    database, request = worker_context
    wrapped = ValueError(PRIVATE_ERROR)
    wrapped.__cause__ = cause
    monkeypatch.setattr(api, "_build_request", Mock(side_effect=wrapped))
    execute(request)
    result = persisted_failure(database)
    assert result.failures[0].error_code == code
    response = api.get_scan(RUN_ID, tenant_id=result.tenant_id)
    assert response["failure_stage"] == "resolve"
    assert response["error_code"] == code
    assert public_failure_message(code) in response["message"]
    assert RUN_ID in response["message"]
    assert "private.test" not in response["message"] and "sensitive" not in response["message"]


def test_legacy_resolution_failure_provides_recovery_guidance():
    assert "branch" in public_failure_message("target_resolution_failed", "resolve")
    assert "archive" in public_failure_message("target_resolution_failed", "resolve")


def test_unknown_error_code_does_not_echo_untrusted_content():
    assert PRIVATE_ERROR not in public_failure_message(PRIVATE_ERROR)


def test_cyclic_exception_chain_is_bounded():
    error = RuntimeError(PRIVATE_ERROR)
    error.__cause__ = error
    assert resolution_failure_code(error) == "target_resolution_failed"


@pytest.mark.parametrize("structured", [False, True])
@pytest.mark.parametrize("unclassified", ["unclassified", " Unclassified ", ""])
def test_default_wizard_context_completes_without_fabricated_classification(
    worker_context,
    structured,
    unclassified,
):
    database, request = worker_context
    context = {
        "system_name": "Workflow QA",
        "owner": "test-fixture",
        "environment": unclassified,
        "business_criticality": unclassified,
        "data_sensitivity": unclassified,
        "regulatory_relevance": unclassified,
        "migration_complexity": unclassified,
        "internet_exposure": None,
    }
    payload = request.model_dump() | context
    if structured:
        payload["business_context"] = context
    execute(ScanRequest.model_validate(payload))
    store = SqliteRunStore(database)
    try:
        result = store.get_run(tenant_id="tenant_" + "a" * 52, run_id=RUN_ID)
    finally:
        store.close()
    assert result is not None and result.status is RunStatus.COMPLETED
    assert result.business_context.data_classification.state is ObservationState.UNKNOWN
    assert result.business_context.criticality.state is ObservationState.UNKNOWN
    assert result.business_context.regulatory_scopes == ()
    assert result.business_context.environment is None
    assert result.business_context.migration_complexity is None
    assert api._scan_stage(RUN_ID) is None
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM qrypton_runs").fetchone()[0] == "completed"
