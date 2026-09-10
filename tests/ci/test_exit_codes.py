"""Tests for CI exit code semantics."""

from __future__ import annotations

from qrypton.ci.exit_codes import ExitCode


def test_exit_code_values_are_stable() -> None:
    """Exit codes are a public contract; values must never change."""
    assert ExitCode.SUCCESS == 0
    assert ExitCode.INVOCATION_ERROR == 2
    assert ExitCode.POLICY_VIOLATION == 3
    assert ExitCode.SCANNER_FAILURE == 4
    assert ExitCode.BASELINE_ERROR == 5
    assert ExitCode.ARTIFACT_ERROR == 6


def test_exit_code_one_is_reserved() -> None:
    """Exit code 1 must not be defined — it is reserved for unexpected errors."""
    assert all(member.value != 1 for member in ExitCode)


def test_exit_codes_are_unique() -> None:
    """No two exit codes may share the same integer value."""
    values = [member.value for member in ExitCode]
    assert len(values) == len(set(values))


def test_exit_codes_are_valid_process_codes() -> None:
    """All exit codes must be in the 0-127 range for POSIX compatibility."""
    for member in ExitCode:
        assert 0 <= member.value <= 127
