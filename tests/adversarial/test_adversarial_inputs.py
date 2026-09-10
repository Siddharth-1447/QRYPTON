"""Adversarial input handling tests for QRYPTON.

Verifies system resilience against malformed syntax, corrupt binaries,
path traversal, symlink escape, oversized files, excessive file counts, and NUL injection.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from qrypton.contracts.enums import ObservationState, ScanTargetKind
from qrypton.contracts.models import Observation, Provenance, ScanTarget
from qrypton.ports.scanners import ScanLimits, ScanRequest
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.traversal import iter_source_files, resolve_source_root


def _digest() -> str:
    return f"sha256:{'a' * 64}"


def _limits(*, max_file_count: int = 100, max_file_bytes: int = 10_000_000) -> ScanLimits:
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
        max_file_bytes=max_file_bytes,
    )


def _make_target(path: Path, kind: ScanTargetKind = ScanTargetKind.SOURCE_TREE) -> ScanTarget:
    provenance = Provenance(
        scanner_name="adversarial_test",
        scanner_version="1.0.0",
        scanner_config_digest=_digest(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    evidence_id = f"evidence_{'a' * 52}"
    return ScanTarget(
        id=f"target_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        asset_id=f"asset_{'a' * 52}",
        kind=kind,
        locator=str(path),
        content_digest=Observation(
            state=ObservationState.OBSERVED, value=_digest(), basis_evidence_ids=(evidence_id,)
        ),
        declared_size_bytes=Observation(
            state=ObservationState.OBSERVED, value=4, basis_evidence_ids=(evidence_id,)
        ),
        requested_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=provenance,
    )


def test_null_byte_locator_rejected(tmp_path: Path) -> None:
    """Target locators containing NUL bytes must raise ValueError immediately."""
    policy = SourceScanPolicy(allowed_root=tmp_path)
    target = _make_target(tmp_path)
    target = target.model_copy(update={"locator": str(tmp_path) + "\x00invalid"})
    with pytest.raises(ValueError, match="contains NUL"):
        resolve_source_root(target, policy=policy)


def test_path_traversal_outside_allowed_root_rejected(tmp_path: Path) -> None:
    """Target locators pointing outside allowed_root must be rejected."""
    root = tmp_path / "inside"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    policy = SourceScanPolicy(allowed_root=root)
    target = _make_target(outside)

    with pytest.raises(ValueError, match="lies outside allowed_root"):
        resolve_source_root(target, policy=policy)


def test_symlink_escape_skipped_in_source_traversal(tmp_path: Path) -> None:
    """Symlinks pointing outside allowed_root or inside must never be followed."""
    root = tmp_path / "root"
    root.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    (secret_dir / "secret.py").write_text("secret_key = 'leaked'", encoding="utf-8")

    symlink = root / "escaped_link.py"
    try:
        symlink.symlink_to(secret_dir / "secret.py")
    except OSError:
        pytest.skip("Symlinks not supported on this platform without admin rights")

    (root / "valid.py").write_text("import rsa", encoding="utf-8")

    policy = SourceScanPolicy(allowed_root=root)
    res = iter_source_files(root, policy=policy, limits=_limits(max_file_count=10))

    relative_paths = [f.relative_path for f in res.files]
    assert "valid.py" in relative_paths
    assert "escaped_link.py" not in relative_paths
    assert any("skipped symlink" in w for w in res.warnings)


def test_oversized_source_file_skipped(tmp_path: Path) -> None:
    """Files exceeding max_source_file_bytes are skipped gracefully."""
    root = tmp_path / "root"
    root.mkdir()
    oversized = root / "huge.py"
    oversized.write_bytes(b"x" * 2000)

    policy = SourceScanPolicy(allowed_root=root, max_source_file_bytes=1000)
    res = iter_source_files(root, policy=policy, limits=_limits())

    assert len(res.files) == 0
    assert any("skipped oversized file" in w for w in res.warnings)
    assert res.partial is True


def test_excessive_member_count_halts_traversal(tmp_path: Path) -> None:
    """Traversal stops cleanly when max_file_count is exceeded."""
    root = tmp_path / "root"
    root.mkdir()
    for i in range(15):
        (root / f"file_{i:02d}.py").write_text("x = 1", encoding="utf-8")

    policy = SourceScanPolicy(allowed_root=root)
    res = iter_source_files(root, policy=policy, limits=_limits(max_file_count=5))

    assert len(res.files) == 5
    assert any("file-count limit reached" in w for w in res.warnings)
    assert res.partial is True


def test_corrupt_binary_handling(tmp_path: Path) -> None:
    """Corrupt or non-binary files passed to LocalBinaryScanner do not crash."""
    binary_path = tmp_path / "corrupt.elf"
    binary_path.write_bytes(b"\x7fELF\x00\x00\x00\xff garbage truncated file content")

    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    target = _make_target(binary_path, kind=ScanTargetKind.ELF)
    request = ScanRequest(
        tenant_id=target.tenant_id,
        target=target,
        correlation_id="corrupt-bin-test",
        limits=_limits(),
    )

    async def _run() -> list[object]:
        return [obs async for obs in scanner.scan(request)]

    obs = asyncio.run(_run())
    assert isinstance(obs, list)
    assert scanner.partial is True
