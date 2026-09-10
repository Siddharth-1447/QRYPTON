"""Tests for secret and evidence redaction in CI output."""

from __future__ import annotations

import pytest

from qrypton.ci import build_ci_result, dump_ci_result
from qrypton.contracts.enums import RiskLevel
from tests.ci.conftest import make_assessment, make_baseline, make_finding, make_run_result


def test_ci_output_contains_no_evidence_ids() -> None:
    """The serialized CI result must not contain evidence_ids."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    baseline = make_baseline()
    ci = build_ci_result(result, baseline)
    raw = dump_ci_result(ci)
    text = raw.decode("utf-8")
    assert "evidence_ids" not in text
    assert "evidence_" not in text or "evidence_confidence" in text  # allow factor name


def test_ci_output_contains_no_excerpts() -> None:
    """The serialized CI result must not contain excerpt data."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    ci = build_ci_result(result, make_baseline())
    raw = dump_ci_result(ci)
    text = raw.decode("utf-8")
    assert "excerpt" not in text


def test_ci_output_contains_no_locators() -> None:
    """The serialized CI result must not contain file locators."""
    f = make_finding()
    a = make_assessment(finding_id=f.id, level=RiskLevel.HIGH)
    result = make_run_result(findings=(f,), assessments=(a,))
    ci = build_ci_result(result, make_baseline())
    raw = dump_ci_result(ci)
    text = raw.decode("utf-8")
    assert "locator" not in text
    assert "relative_path" not in text


def test_dump_rejects_forbidden_keys() -> None:
    """dump_ci_result raises ValueError if forbidden keys are present."""
    bad_doc = {"schema_version": "1.0", "evidence_ids": ["leak"]}
    with pytest.raises(ValueError, match="forbidden key"):
        dump_ci_result(bad_doc)


def test_dump_rejects_nested_forbidden_keys() -> None:
    """Forbidden keys nested inside the document are also caught."""
    bad_doc = {"schema_version": "1.0", "data": {"excerpt": "leaked source code"}}
    with pytest.raises(ValueError, match="forbidden key"):
        dump_ci_result(bad_doc)
