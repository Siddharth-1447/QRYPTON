"""Deterministic output tests across repeated runs for QRYPTON.

Verifies that repeated execution over identical inputs yields byte-for-byte
identical scan outputs, path orderings, and risk assessments.
"""

from __future__ import annotations

from pathlib import Path

from qrypton.ports.scanners import ScanLimits
from qrypton.risk.engine import evaluate_qrypton_risk
from qrypton.risk.schemas import BusinessContext, MoscaInput
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.traversal import iter_source_files


def _limits(*, max_file_count: int = 100) -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=100_000_000,
        max_expanded_bytes=500_000_000,
        max_file_count=max_file_count,
        max_nesting_depth=3,
        max_layer_count=25,
        max_ast_nodes=100_000,
        max_evidence_count=10_000,
        max_wall_time_seconds=30.0,
        max_memory_bytes=512_000_000,
        max_file_bytes=10_000_000,
    )


def test_source_traversal_path_ordering_is_deterministic(tmp_path: Path) -> None:
    """iter_source_files must produce identical, sorted file listings regardless of creation order."""
    root = tmp_path / "repo"
    root.mkdir()

    filenames = ["z_file.py", "a_file.py", "m_file.py", "b_file.py", "1_file.py"]
    for fname in filenames:
        (root / fname).write_text("import rsa", encoding="utf-8")

    policy = SourceScanPolicy(allowed_root=root)

    results = []
    for _ in range(5):
        res = iter_source_files(root, policy=policy, limits=_limits())
        paths = [f.relative_path for f in res.files]
        results.append(paths)

    first = results[0]
    assert first == sorted(filenames)
    for run in results[1:]:
        assert run == first


def test_deterministic_risk_evaluator_repeated_runs() -> None:
    """evaluate_qrypton_risk produces identical risk scores and tiers across multiple invocations."""
    mosca = MoscaInput(x_data_lifetime_years=10.0, y_migration_years=5.0, z_crqc_horizon_years=12.0)
    business = BusinessContext(
        data_sensitivity=4,
        system_criticality=4,
        exposure_level=3,
        regulatory_importance=3,
        migration_complexity=3,
    )

    runs = []
    for _ in range(10):
        result = evaluate_qrypton_risk(mosca, business)
        runs.append((result.risk_level, result.explanation.urgency_tier, result.explanation.urgency_ratio))

    first_run = runs[0]
    for run in runs[1:]:
        assert run == first_run
