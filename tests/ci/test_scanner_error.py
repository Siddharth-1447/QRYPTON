"""Tests for scanner error reporting in CI output."""

from __future__ import annotations

from qrypton.application.schemas import RunFailure, ScannerExecutionResult
from qrypton.ci import build_ci_result
from qrypton.ci.exit_codes import ExitCode
from qrypton.contracts.enums import RunStatus
from tests.ci.conftest import make_baseline, make_run_result


def test_scanner_error_reported_in_json() -> None:
    """A failed scanner shows scanner.failed >= 1 in CI result."""
    failed_scanner = ScannerExecutionResult(
        scanner_name="test-scanner",
        scanner_version="1.0.0",
        status="failed",
        failure=RunFailure(
            stage="scanner",
            error_code="scan_timeout",
            scanner_name="test-scanner",
            message="Scanner timed out",
        ),
    )
    result = make_run_result(
        scanner_results=(failed_scanner,),
        status=RunStatus.FAILED,
        policy_passed=False,
        policy_violations=("scanner failure",),
    )
    ci = build_ci_result(result, make_baseline(), exit_code=ExitCode.SCANNER_FAILURE)
    assert ci["scanner"]["failed"] >= 1
    assert ci["exit_code"] == 4
    assert ci["exit_reason"] == "scanner_failure"


def test_partial_scan_reported() -> None:
    """A partial scanner shows scanner.partial >= 1 in CI result."""
    partial_scanner = ScannerExecutionResult(
        scanner_name="test-scanner",
        scanner_version="1.0.0",
        status="partial",
    )
    result = make_run_result(scanner_results=(partial_scanner,))
    ci = build_ci_result(result, make_baseline())
    assert ci["scanner"]["partial"] >= 1


def test_scanner_failure_exit_code_distinct_from_policy() -> None:
    """Scanner failure (exit 4) is distinct from policy violation (exit 3)."""
    assert ExitCode.SCANNER_FAILURE != ExitCode.POLICY_VIOLATION
    assert ExitCode.SCANNER_FAILURE == 4
    assert ExitCode.POLICY_VIOLATION == 3


def test_successful_scan_reports_zero_failures() -> None:
    """A clean scan reports zero scanner failures and partials."""
    result = make_run_result()
    ci = build_ci_result(result, make_baseline())
    assert ci["scanner"]["failed"] == 0
    assert ci["scanner"]["partial"] == 0
    assert ci["exit_code"] == 0
    assert ci["exit_reason"] == "success"
