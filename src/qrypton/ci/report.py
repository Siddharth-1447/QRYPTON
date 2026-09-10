"""Sanitized, deterministic CI delta and policy reporting for QRYPTON runs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from qrypton.application.schemas import RunResult
from qrypton.ci.exit_codes import ExitCode
from qrypton.ci.fingerprint import finding_fingerprint

CI_SCHEMA_VERSION = "1.0"

# Allowlisted top-level keys for the CI result document.
_ALLOWED_KEYS = frozenset({
    "schema_version", "exit_code", "exit_reason", "run_id", "status",
    "policy", "scanner", "inventory", "delta", "introduced",
    "baseline", "scope",
})

# Keys that must never appear in serialized output.
_FORBIDDEN_KEYS = frozenset({
    "evidence_ids", "locator", "excerpt", "relative_path",
    "evidence", "id_secret", "secret",
})


def _risk_rank(level: str) -> int:
    ranks = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 5}
    return ranks.get(level, 5)


def _risk_by_finding(result: RunResult) -> Mapping[str, str]:
    return {item.finding_id: item.level.value for item in result.assessments}


def run_inventory(result: RunResult) -> dict[str, dict[str, str]]:
    """Build a fingerprint → {risk_level, category} inventory from a run result."""
    risks = _risk_by_finding(result)
    inventory: dict[str, dict[str, str]] = {}
    for finding in result.findings:
        fingerprint = finding_fingerprint(finding)
        previous = inventory.get(fingerprint)
        risk = risks.get(finding.id, "unknown")
        if previous is None or _risk_rank(risk) > _risk_rank(previous["risk_level"]):
            inventory[fingerprint] = {"risk_level": risk, "category": finding.category}
    return inventory


def build_ci_result(
    result: RunResult,
    baseline: Mapping[str, object] | None,
    *,
    changed_from: str | None = None,
    exit_code: ExitCode = ExitCode.SUCCESS,
) -> dict[str, object]:
    """Generate an artifact-safe result; it never includes evidence or source locations."""
    current = run_inventory(result)
    baseline_entries = {} if baseline is None else baseline.get("inventory", {})
    if not isinstance(baseline_entries, dict):
        raise ValueError("baseline inventory must be an object")
    baseline_inventory: dict[str, dict[object, object]] = {
        str(key): value for key, value in baseline_entries.items() if isinstance(value, dict)
    }
    deltas: list[dict[str, str]] = []
    for fingerprint in sorted(set(current) | set(baseline_inventory)):
        now = current.get(fingerprint)
        before = baseline_inventory.get(fingerprint, {})
        has_baseline = fingerprint in baseline_inventory
        if not has_baseline and now is not None:
            change = "new"
        elif now is None:
            change = "removed"
        elif now is not None and str(before.get("risk_level", "unknown")) != now["risk_level"]:
            change = "changed"
        else:
            change = "unchanged"
        if change != "unchanged":
            deltas.append(
                {
                    "fingerprint": fingerprint,
                    "change": change,
                    "risk_level": (
                        now["risk_level"]
                        if now is not None
                        else str(before.get("risk_level", "unknown"))
                    ),
                }
            )
    introduced = [
        item
        for item in deltas
        if item["change"] == "new"
        or (
            item["change"] == "changed"
            and _risk_rank(item["risk_level"])
            > _risk_rank(
                str(baseline_inventory.get(item["fingerprint"], {}).get("risk_level", "unknown"))
            )
        )
    ]

    exit_reason_map = {
        ExitCode.SUCCESS: "success",
        ExitCode.INVOCATION_ERROR: "invocation_error",
        ExitCode.POLICY_VIOLATION: "policy_violation",
        ExitCode.SCANNER_FAILURE: "scanner_failure",
        ExitCode.BASELINE_ERROR: "baseline_error",
        ExitCode.ARTIFACT_ERROR: "artifact_error",
    }

    return {
        "schema_version": CI_SCHEMA_VERSION,
        "exit_code": int(exit_code),
        "exit_reason": exit_reason_map.get(exit_code, "unknown"),
        "run_id": result.run_id,
        "status": result.status.value,
        "policy": {
            "passed": result.policy_outcome.passed,
            "violations": list(result.policy_outcome.violations),
        },
        "scanner": {
            "failed": sum(item.status == "failed" for item in result.scanner_results),
            "partial": sum(item.status == "partial" for item in result.scanner_results),
        },
        "inventory": current,
        "delta": deltas,
        "introduced": introduced,
        "baseline": None
        if baseline is None
        else {"schema_version": baseline.get("schema_version"), "run_id": baseline.get("run_id")},
        "scope": {"changed_from": changed_from, "mode": "full_repository"},
    }


def _check_no_forbidden_keys(data: Any, path: str = "") -> None:
    """Post-serialization assertion: no secrets or evidence in output."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key in _FORBIDDEN_KEYS:
                raise ValueError(f"forbidden key {key!r} found at {path}.{key}")
            _check_no_forbidden_keys(value, f"{path}.{key}")
    elif isinstance(data, list):
        for index, value in enumerate(data):
            _check_no_forbidden_keys(value, f"{path}[{index}]")


def dump_ci_result(document: Mapping[str, object]) -> bytes:
    """Serialize a CI result to compact JSON bytes with safety assertions."""
    _check_no_forbidden_keys(dict(document))
    return (
        json.dumps(document, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        + b"\n"
    )
