"""Performance benchmark tests for synthetic repositories in QRYPTON.

Verifies throughput, execution SLAs, and timeout/limit enforcement across
small and medium synthetic repository structures.
"""

from __future__ import annotations

import time
from pathlib import Path

from qrypton.ports.scanners import ScanLimits
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


def test_small_synthetic_repository_performance(tmp_path: Path) -> None:
    """Small synthetic repository (50 files) completes traversal in under 1.5s."""
    root = tmp_path / "small_repo"
    root.mkdir()
    for i in range(50):
        (root / f"module_{i}.py").write_text(
            f"import hashlib\n\ndef func_{i}():\n    return hashlib.sha256(b'test').hexdigest()\n",
            encoding="utf-8",
        )

    policy = SourceScanPolicy(allowed_root=root)

    start_time = time.monotonic()
    result = iter_source_files(root, policy=policy, limits=_limits(max_file_count=100))
    duration = time.monotonic() - start_time

    assert len(result.files) == 50
    assert duration < 1.5, f"Small benchmark took {duration:.3f}s, target SLA is < 1.5s"


def test_medium_synthetic_repository_performance(tmp_path: Path) -> None:
    """Medium synthetic repository (200 files in subdirectories) completes in under 3.0s."""
    root = tmp_path / "med_repo"
    root.mkdir()
    for d in range(10):
        subdir = root / f"dir_{d}"
        subdir.mkdir()
        for f in range(20):
            (subdir / f"file_{f}.py").write_text(
                "from Crypto.Cipher import AES\n"
                "key = b'0123456789abcdef'\n"
                f"cipher_{f} = AES.new(key, AES.MODE_ECB)\n",
                encoding="utf-8",
            )

    policy = SourceScanPolicy(allowed_root=root)

    start_time = time.monotonic()
    result = iter_source_files(root, policy=policy, limits=_limits(max_file_count=500))
    duration = time.monotonic() - start_time

    assert len(result.files) == 200
    assert duration < 3.0, f"Medium benchmark took {duration:.3f}s, target SLA is < 3.0s"


def test_limits_default_contract_values() -> None:
    """ScanLimits contract establishes safe limits."""
    limits = _limits()
    assert limits.max_file_bytes > 0
    assert limits.max_file_count > 0
    assert limits.max_wall_time_seconds > 0
    assert limits.max_memory_bytes > 0
    assert limits.max_nesting_depth >= 1
