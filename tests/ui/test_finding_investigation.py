"""Investigation values must stay identical to persisted assessment/context values."""

from qrypton.contracts.evidence_quality import classify_evidence
from qrypton.contracts.models import BusinessContext, Observation
from qrypton.ui.investigation import detail_context
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.ui.conftest import create_sample_run, sample_provenance


def test_detail_preserves_engine_and_timeline_values() -> None:
    run = create_sample_run("tenant_" + "a" * 52, "run_" + "b" * 52)
    details = SqliteDashboardDataProvider.finding_details_from_result(run)
    for finding in run.findings:
        detail = details[finding.id]
        assert detail.assessment == next(a for a in run.assessments if a.finding_id == finding.id)
        assert detail.application_run_id == run.run_id
        assert detail.application_name is None
        for evidence in detail.evidence_provenance:
            assert detail.evidence_quality[evidence.id] == classify_evidence(evidence)[0]
        persisted = next(m for m in run.mosca_evaluations if m.finding_id == finding.id)
        assert detail.mosca is not None
        for field in ("x_data_lifetime_years", "y_migration_years", "z_crqc_horizon_years",
                      "required_security_years", "time_margin_years", "x_source"):
            assert getattr(detail.mosca, field) == getattr(persisted, field)


def test_missing_business_context_is_not_invented() -> None:
    assert detail_context(None) == {}
    run = create_sample_run("tenant_" + "a" * 52, "run_" + "b" * 52)
    context = BusinessContext(
        id="context_" + "a" * 52, tenant_id=run.tenant_id,
        asset_id=run.findings[0].asset_id,
        criticality=Observation(state="unknown"),
        data_classification=Observation(
            state="observed", value="restricted", basis_evidence_ids=(run.evidence[0].id,),
        ),
        internet_exposed=Observation(
            state="observed", value=False, basis_evidence_ids=(run.evidence[0].id,),
        ),
        owner_reference=Observation(state="unknown"),
        migration_complexity="high", provenance=sample_provenance(),
    )
    projected = detail_context(context)
    assert projected["exposure"].value == context.internet_exposed.value
    assert projected["data_sensitivity"].value == context.data_classification.value
    assert projected["migration_complexity"].value == context.migration_complexity
