"""Tests for CI baseline delta detection."""

from __future__ import annotations

from qrypton.ci import build_ci_result, run_inventory
from qrypton.contracts.enums import RiskLevel
from tests.ci.conftest import make_assessment, make_baseline, make_finding, make_run_result


def test_new_finding_detected() -> None:
    """A finding present in the current run but absent from the baseline is 'new'."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    baseline = make_baseline(inventory={})
    ci = build_ci_result(result, baseline)
    assert len(ci["delta"]) == 1
    delta = ci["delta"][0]
    assert delta["change"] == "new"
    assert delta["risk_level"] == "high"
    assert len(ci["introduced"]) == 1


def test_removed_finding_detected() -> None:
    """A finding in the baseline but absent from the current run is 'removed'."""
    result = make_run_result(findings=(), assessments=())
    fp = "sha256:" + "f" * 64
    baseline = make_baseline(inventory={fp: {"risk_level": "high", "category": "algorithm_use"}})
    ci = build_ci_result(result, baseline)
    deltas = [d for d in ci["delta"] if d["change"] == "removed"]
    assert len(deltas) == 1
    assert deltas[0]["fingerprint"] == fp
    # Removed findings should NOT appear in introduced
    assert all(i["fingerprint"] != fp for i in ci["introduced"])


def test_changed_finding_risk_upgrade_is_introduced() -> None:
    """A finding whose risk escalated compared to baseline is 'changed' and 'introduced'."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.CRITICAL)
    result = make_run_result(findings=(f,), assessments=(a,))
    inventory = run_inventory(result)
    fp = next(iter(inventory))
    baseline = make_baseline(inventory={fp: {"risk_level": "medium", "category": "algorithm_use"}})
    ci = build_ci_result(result, baseline)
    changed = [d for d in ci["delta"] if d["change"] == "changed"]
    assert len(changed) == 1
    assert changed[0]["risk_level"] == "critical"
    assert any(i["fingerprint"] == fp for i in ci["introduced"])


def test_changed_finding_risk_downgrade_not_introduced() -> None:
    """A finding whose risk decreased is 'changed' but NOT 'introduced'."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.LOW)
    result = make_run_result(findings=(f,), assessments=(a,))
    inventory = run_inventory(result)
    fp = next(iter(inventory))
    baseline = make_baseline(
        inventory={fp: {"risk_level": "critical", "category": "algorithm_use"}}
    )
    ci = build_ci_result(result, baseline)
    changed = [d for d in ci["delta"] if d["change"] == "changed"]
    assert len(changed) == 1
    assert not any(i["fingerprint"] == fp for i in ci["introduced"])


def test_unchanged_finding_omitted_from_delta() -> None:
    """A finding identical to baseline does not appear in delta."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    inventory = run_inventory(result)
    baseline = make_baseline(inventory=inventory)
    ci = build_ci_result(result, baseline)
    assert len(ci["delta"]) == 0
    assert len(ci["introduced"]) == 0


def test_baseline_drift_empty_inventory() -> None:
    """An empty baseline inventory means all current findings are 'new'."""
    f1 = make_finding(finding_id=f"finding_{'a' * 52}", algorithm_name="SHA-1")
    f2 = make_finding(finding_id=f"finding_{'b' * 52}", algorithm_name="MD5")
    a1 = make_assessment(finding_id=f1.id, level=RiskLevel.HIGH)
    a2 = make_assessment(finding_id=f2.id, level=RiskLevel.CRITICAL)
    result = make_run_result(findings=(f1, f2), assessments=(a1, a2))
    baseline = make_baseline(inventory={})
    ci = build_ci_result(result, baseline)
    new_deltas = [d for d in ci["delta"] if d["change"] == "new"]
    assert len(new_deltas) == len(ci["delta"])
    assert len(ci["introduced"]) == len(new_deltas)


def test_no_baseline_treats_all_as_new() -> None:
    """When baseline is None, all findings appear as new."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    ci = build_ci_result(result, None)
    assert ci["baseline"] is None
    assert len(ci["delta"]) == 1
    assert ci["delta"][0]["change"] == "new"
