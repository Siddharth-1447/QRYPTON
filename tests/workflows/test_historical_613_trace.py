"""Read-only regression checks for the available 613-finding persisted trace.

The historical database is local runtime data and is not checked in. The test
skips with an explicit reason in clean checkouts where that artifact is absent.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from qrypton.application.schemas import RunResult

_RUN_ID = "run_rijjek6ih47m3hwenq7spc5erwiiynciq4cwvcicrnvwsk5pcpjq"


def test_historical_613_finding_trace_retains_persisted_identity_and_links() -> None:
    database = Path(__file__).resolve().parents[2] / "qrypton.sqlite3"
    if not database.is_file():
        pytest.skip("historical 613-finding database artifact is not available in this checkout")

    uri = f"{database.as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        record = connection.execute(
            "SELECT tenant_id, result_json, cbom FROM qrypton_runs WHERE run_id = ?",
            (_RUN_ID,),
        ).fetchone()
    if record is None:
        pytest.skip("historical 613-finding run is not present in the available database")

    tenant_id, result_json, cbom_bytes = record
    result = RunResult.model_validate_json(result_json)
    assert result.run_id == _RUN_ID
    assert result.tenant_id == tenant_id
    assert result.status.value == "completed"
    assert len(result.findings) == 613
    assert len(result.assessments) == len(result.mosca_evaluations) == 613
    assert result.business_context is not None

    finding_by_id = {item.id: item for item in result.findings}
    evidence_ids = {item.id for item in result.evidence}
    assessments = {item.finding_id: item for item in result.assessments}
    mosca = {item.finding_id: item for item in result.mosca_evaluations}
    assert len(finding_by_id) == 613
    assert set(assessments) == set(mosca) == set(finding_by_id)
    for finding_id, finding in finding_by_id.items():
        assessment = assessments[finding_id]
        assert set(finding.evidence_ids) <= evidence_ids
        assert assessment.evidence_ids == finding.evidence_ids
        assert assessment.factors.evidence_confidence == finding.confidence
        assert assessment.business_context_id == result.business_context.id
        assert assessment.final_priority is assessment.level
        timeline = mosca[finding_id]
        if assessment.mosca_applicable == "unknown":
            # Legacy assessment JSON predates structured Mosca fields.
            assert assessment.mosca_urgency.value == "unknown"
        else:
            assert timeline.urgency == assessment.mosca_urgency.value
        if timeline.mosca_applicable == "yes":
            assert timeline.required_security_years == (
                timeline.x_data_lifetime_years + timeline.y_migration_years
            )
            assert timeline.time_margin_years == (
                timeline.z_crqc_horizon_years - timeline.required_security_years
            )

    assert isinstance(cbom_bytes, bytes)
    assert f"sha256:{hashlib.sha256(cbom_bytes).hexdigest()}" == result.cbom_digest
    cbom = json.loads(cbom_bytes)
    cbom_finding_ids = {
        prop["value"]
        for component in cbom["components"]
        for prop in component.get("properties", ())
        if prop.get("name") == "org.qrypton.finding.id"
    }
    assert cbom_finding_ids == set(finding_by_id)

    # This artifact predates independent crypto/quantum risk fields. Defaults
    # must remain explicit UNKNOWN instead of being reconstructed from old text.
    assert all(item.factors.crypto_risk.value == "unknown" for item in result.assessments)
    assert all(item.factors.quantum_risk.value == "unknown" for item in result.assessments)
