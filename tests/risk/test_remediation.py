"""Decision-ordering invariants, including volume independence and unknown inputs."""

from datetime import UTC, datetime

from qrypton.application.config import default_risk_policy
from qrypton.contracts.enums import AlgorithmFamily
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import BusinessContext, Observation
from qrypton.policies.pqc import PqcRecommendationPolicy
from qrypton.recommendations.engine import PqcRecommendationEngine
from qrypton.risk.mosca import MoscaParameters, MoscaRiskEngine
from qrypton.risk.remediation import rank_remediation
from qrypton.ui.contracts import InventoryObservation
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from tests.risk.conftest import finding, provenance
from tests.ui.conftest import create_sample_run


def test_real_engine_equal_scores_do_not_hide_sensitive_long_lived_exposed_finding() -> None:
    engine = MoscaRiskEngine(
        parameters=MoscaParameters(
            data_shelf_life_years=5,
            migration_time_years=2,
            quantum_threat_horizon_years=10,
        ),
        id_deriver=HmacIdDeriver(b"a" * 32),
    )
    policy = default_risk_policy(datetime(2026, 10, 9, tzinfo=UTC))
    recommendation_policy = PqcRecommendationPolicy(
        profile_id="ranking-test",
        profile_version="1.0.0",
        published_at=datetime(2026, 10, 9, tzinfo=UTC),
        nist_references=(),
    )
    recommendation_engine = PqcRecommendationEngine(
        id_deriver=HmacIdDeriver(b"a" * 32),
        provenance=provenance(),
    )
    recommendations = []
    findings, assessments, contexts = [], [], {}
    for suffix in ("b", "c", "d", "e", "f", "g", "z"):
        sensitive = suffix == "z"
        target = finding(
            "RSA-2048" if sensitive else "MD5",
            AlgorithmFamily.ASYMMETRIC_ENCRYPTION if sensitive else AlgorithmFamily.HASH,
        ).model_copy(
            update={
                "id": "finding_" + suffix * 52,
                "crypto_role": "encryption" if sensitive else "hashing",
            }
        )
        context = BusinessContext(
            id="context_" + suffix * 52,
            tenant_id=target.tenant_id,
            asset_id=target.asset_id,
            criticality=Observation(
                state="observed",
                value="critical" if sensitive else "low",
                basis_evidence_ids=target.evidence_ids,
            ),
            data_classification=Observation(
                state="observed",
                value="restricted" if sensitive else "public",
                basis_evidence_ids=target.evidence_ids,
            ),
            internet_exposed=Observation(
                state="observed",
                value=sensitive,
                basis_evidence_ids=target.evidence_ids,
            ),
            owner_reference=Observation(state="unknown"),
            mosca_x_data_lifetime_years=20 if sensitive else 0.1,
            environment="production" if sensitive else "development",
            provenance=provenance(),
        )
        findings.append(target)
        assessments.append(engine.assess(target, context, policy))
        recommendations.extend(
            recommendation_engine.recommend(
                target,
                assessments[-1],
                recommendation_policy,
            )
        )
        contexts[target.id] = context
    assert {assessment.score.value for assessment in assessments} == {100}
    run = create_sample_run(findings[0].tenant_id, "run_" + "b" * 52).model_copy(
        update={
            "findings": tuple(findings),
            "assessments": tuple(assessments),
            "finding_business_contexts": contexts,
            "mosca_evaluations": (),
            "recommendations": tuple(recommendations),
            "recommendation_plans": (),
        }
    )
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    rows = view.inventory
    assert view.roadmap[0].finding_id == findings[-1].id
    assert view.roadmap[0].priority == 100
    assert rows[0].finding_id == findings[-1].id
    assert rows[0].risk_score == 100
    assert rows[0].remediation_ruleset_version == "1.0.0"
    assert "20 years" in rows[0].remediation_reason
    assert "internet-facing" in rows[0].remediation_reason
    crowded = [
        rows[0],
        *[rows[-1].model_copy(update={"finding_id": f"weak_{i}"}) for i in range(1000)],
    ]
    assert rank_remediation(crowded)[0].finding_id == rows[0].finding_id
    assert rank_remediation(list(reversed(crowded))) == rank_remediation(crowded)


def test_unknown_exposure_never_becomes_internet_facing_and_zero_is_recorded() -> None:
    run = create_sample_run("tenant_" + "a" * 52, "run_" + "b" * 52)
    row = SqliteDashboardDataProvider.run_view_from_result(run).inventory[0]
    projected = rank_remediation(
        [
            row.model_copy(
                update={
                    "observations": {
                        "exposure": InventoryObservation(state="unknown"),
                        "data_lifetime": InventoryObservation(state="observed", value=0),
                    }
                }
            )
        ]
    )[0]
    assert "unknown sensitivity, exposure" in projected.remediation_reason
    assert "0 years" in projected.remediation_reason
    assert "on an internet-facing" not in projected.remediation_reason
