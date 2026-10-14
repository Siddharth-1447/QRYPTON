"""Inventory projection uses indexed evidence without scanning the whole run."""

import pytest

from qrypton.contracts.models import BusinessContext, Observation
from qrypton.ui.investigation import inventory_context
from tests.ui.conftest import create_sample_run, sample_provenance


class IndexedEvidence(dict):
    def __iter__(self):
        raise AssertionError("Projection must not enumerate the shared evidence index")


@pytest.mark.parametrize("basis,expected", [("evidence", "confirmed_absent"),
                                          ("context", "confirmed_absent"),
                                          ("missing", "unknown"), ("mixed", "unknown")])
def test_absence_validation_uses_indexed_membership(basis, expected):
    run = create_sample_run("tenant_" + "a" * 52, "run_" + "b" * 52)
    context_id = "context_" + "a" * 52
    ids = {"evidence": (run.evidence[0].id,), "context": (context_id,),
           "missing": ("evidence_" + "z" * 52,),
           "mixed": (run.evidence[0].id, "evidence_" + "z" * 52)}[basis]
    context = BusinessContext(
        id=context_id, tenant_id=run.tenant_id, asset_id=run.findings[0].asset_id,
        criticality=Observation(state="unknown"),
        data_classification=Observation(state="unknown"),
        internet_exposed=Observation(state="confirmed_absent", basis_evidence_ids=ids),
        owner_reference=Observation(state="unknown"), provenance=sample_provenance(),
    )
    run = run.model_copy(update={"business_context": context})
    index = IndexedEvidence({evidence.id: evidence for evidence in run.evidence})
    result = inventory_context(run.findings[0], run, index, None)
    observation = result["observations"]["exposure"]
    assert observation.state.value == expected
    assert observation.evidence_ids == (ids if expected == "confirmed_absent" else ())
