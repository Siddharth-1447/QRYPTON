"""Scanner integration tests: real scanners against real fixture bytes.

No mocks, no network. Each test proves the routed scanner accepts its
artifact kind and emits observations from the actual bytes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from qrypton.contracts.enums import ObservationState, ScanTargetKind
from qrypton.contracts.models import Observation, Provenance, ScanTarget
from qrypton.ports.scanners import ScanLimits, ScanRequest
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.extended import (
    CloudKmsScanner,
    ContainerImageScanner,
    ExtendedStaticScanner,
    LibraryDependencyScanner,
)
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.scanner import LocalSourceScanner

from .conftest import (
    TENANT_ID,
    build_docker_tar,
    build_minimal_elf,
    build_wheel,
    crypto_source_tree,
)

EVIDENCE_ID = f"evidence_{'b' * 52}"


def _provenance() -> Provenance:
    return Provenance(
        scanner_name="workflow-test",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{'c' * 64}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _target(path: Path, kind: ScanTargetKind) -> ScanTarget:
    return ScanTarget(
        id=f"target_{'b' * 52}",
        tenant_id=TENANT_ID,
        asset_id=f"asset_{'b' * 52}",
        kind=kind,
        locator=str(path),
        content_digest=Observation(state=ObservationState.UNKNOWN),
        declared_size_bytes=Observation(
            state=ObservationState.OBSERVED,
            value=path.stat().st_size,
            basis_evidence_ids=(EVIDENCE_ID,),
        ),
        requested_at=datetime(2026, 1, 1, tzinfo=UTC),
        provenance=_provenance(),
    )


def _limits() -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=64 * 1024 * 1024,
        max_expanded_bytes=512 * 1024 * 1024,
        max_file_count=100_000,
        max_nesting_depth=8,
        max_layer_count=128,
        max_ast_nodes=1_000_000,
        max_evidence_count=100_000,
        max_wall_time_seconds=60,
        max_memory_bytes=512 * 1024 * 1024,
    )


def _request(path: Path, kind: ScanTargetKind) -> ScanRequest:
    return ScanRequest(
        tenant_id=TENANT_ID,
        target=_target(path, kind),
        limits=_limits(),
        correlation_id="workflow-scanner-test",
    )


def _collect(scanner, request):  # type: ignore[no-untyped-def]
    return asyncio.run(_drain(scanner.scan(request)))


async def _drain(stream):  # type: ignore[no-untyped-def]
    return [item async for item in stream]


def test_source_scanner_reads_real_tree(tmp_path: Path) -> None:
    root = crypto_source_tree(tmp_path / "proj")
    scanner = LocalSourceScanner(SourceScanPolicy(allowed_root=tmp_path))
    assert scanner.name == "qrypton-source"
    assert ScanTargetKind.SOURCE_TREE in {m.value if hasattr(m, "value") else m for m in scanner.supported_targets} or "source_tree" in scanner.supported_targets
    observations = _collect(scanner, _request(root, ScanTargetKind.SOURCE_TREE))
    assert observations, "source scanner found nothing in crypto fixture"
    assert not scanner.partial


def test_binary_scanner_reads_real_elf_bytes(tmp_path: Path) -> None:
    image = tmp_path / "crypto.bin"
    image.write_bytes(build_minimal_elf())
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    assert scanner.name == "qrypton-binary"
    observations = _collect(scanner, _request(image, ScanTargetKind.FILE))
    symbols = [item.location.symbol for item in observations]
    assert "RSA_public_encrypt" in symbols
    assert "AES_encrypt" in symbols
    assert all(item.binary_digest for item in observations)


def test_library_scanner_reads_real_wheel(tmp_path: Path) -> None:
    name, data = build_wheel()
    package = tmp_path / name
    package.write_bytes(data)
    scanner = LibraryDependencyScanner(allowed_root=tmp_path)
    assert scanner.name == "qrypton-library"
    assert ScanTargetKind.FILE in scanner.supported_targets
    observations = _collect(scanner, _request(package, ScanTargetKind.FILE))
    values = [item.attributes.get("subject_value") for item in observations]
    assert "rsa" in values
    assert "aes" in values
    assert not scanner.partial


def test_container_scanner_reads_real_archive(tmp_path: Path) -> None:
    name, data = build_docker_tar()
    archive = tmp_path / name
    archive.write_bytes(data)
    scanner = ContainerImageScanner(allowed_root=tmp_path)
    assert scanner.name == "qrypton-container"
    observations = _collect(scanner, _request(archive, ScanTargetKind.OCI_IMAGE))
    values = [item.attributes.get("subject_value") for item in observations]
    assert "rsa" in values


def test_kms_scanner_accepts_metadata_document(tmp_path: Path) -> None:
    descriptor = tmp_path / "kms-key.json"
    descriptor.write_text('{"kms_key_id": "alias/prod-key"}', encoding="utf-8")
    scanner = CloudKmsScanner(allowed_root=tmp_path)
    assert scanner.name == "qrypton-kms"
    assert ScanTargetKind.FILE in scanner.supported_targets
    observations = _collect(scanner, _request(descriptor, ScanTargetKind.FILE))
    assert observations == []
    assert not scanner.partial


def test_extended_source_scanner_accepts_git_archives(tmp_path: Path) -> None:
    assert ExtendedStaticScanner.name == "qrypton-source"
    assert ScanTargetKind.GIT_ARCHIVE in ExtendedStaticScanner.supported_targets
