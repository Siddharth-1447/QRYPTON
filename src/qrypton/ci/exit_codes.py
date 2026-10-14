"""Deterministic exit codes for QRYPTON CI integration.

These are the stable interface that CI systems (GitHub Actions, Jenkins,
GitLab CI, etc.) use to interpret scan outcomes. Each code maps to
exactly one semantic class so scripts can ``case`` on $? without ambiguity.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes for ``qrypton ci scan``."""

    SUCCESS = 0
    # 1 is reserved for generic/unexpected errors
    INVOCATION_ERROR = 2
    POLICY_VIOLATION = 3
    SCANNER_FAILURE = 4
    BASELINE_ERROR = 5
    ARTIFACT_ERROR = 6
    RUN_CONFLICT = 7
