from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from qrypton.contracts.enums import ObservationState, ScanTargetKind
from qrypton.contracts.models import EvidenceLocation, Observation, Provenance, ScanTarget
from qrypton.ports.scanners import ScanLimits, ScanRequest
from qrypton.scanners.binary.entropy import shannon_entropy
from qrypton.scanners.binary.formats import BinarySection, ParsedBinary
from qrypton.scanners.binary.scanner import LocalBinaryScanner


def _digest() -> str:
    return f"sha256:{'a' * 64}"


def _target(path: Path) -> ScanTarget:
    provenance = Provenance(
        scanner_name="test",
        scanner_version="1.0.0",
        scanner_config_digest=_digest(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    evidence_id = f"evidence_{'a' * 52}"
    return ScanTarget(
        id=f"target_{'a' * 52}",
        tenant_id=f"tenant_{'a' * 52}",
        asset_id=f"asset_{'a' * 52}",
        kind=ScanTargetKind.ELF,
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


def _request(path: Path, *, max_file_bytes: int = 1024) -> ScanRequest:
    return ScanRequest(
        tenant_id=f"tenant_{'a' * 52}",
        target=_target(path),
        correlation_id="binary-test",
        limits=ScanLimits(
            max_compressed_bytes=1,
            max_expanded_bytes=1,
            max_file_count=1,
            max_nesting_depth=0,
            max_layer_count=1,
            max_ast_nodes=1,
            max_evidence_count=10,
            max_wall_time_seconds=10,
            max_memory_bytes=1024,
            max_file_bytes=max_file_bytes,
        ),
    )


async def _collect(scanner: LocalBinaryScanner, request: ScanRequest) -> list[object]:
    return [item async for item in scanner.scan(request)]


def test_entropy_detects_random_like_section() -> None:
    high = bytes(range(256)) * 4
    assert shannon_entropy(BytesIO(high), offset=0, size=len(high)) == 8.0
    assert shannon_entropy(BytesIO(b"\0" * 1024), offset=0, size=1024) == 0.0


def test_scanner_extracts_crypto_import_from_mocked_binary_metadata(tmp_path: Path) -> None:
    image = tmp_path / "app"
    image.write_bytes(b"ELF!")
    parsed = ParsedBinary(
        format="elf",
        imports=("RSA_public_encrypt", "puts"),
        exports=(),
        libraries=("libcrypto.so.3",),
        sections=(BinarySection(".data", 0, 4),),
    )
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    with patch("qrypton.scanners.binary.scanner.parse_binary", return_value=parsed):
        observations = asyncio.run(_collect(scanner, _request(image)))
    assert [item.location.symbol for item in observations] == [
        "RSA_public_encrypt",
        "libcrypto.so.3",
    ]
    assert observations[0].attributes["subject_value"] == "RSA_public_encrypt"


def test_scanner_skips_file_exceeding_max_file_bytes(tmp_path: Path) -> None:
    image = tmp_path / "large"
    image.write_bytes(b"x" * 16)
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    assert asyncio.run(_collect(scanner, _request(image, max_file_bytes=8))) == []
    assert scanner.warnings == ("skipped oversized binary",)


def test_entropy_finding_from_mocked_section_bytes(tmp_path: Path) -> None:
    image = tmp_path / "app"
    image.write_bytes(bytes(range(256)) * 2)
    parsed = ParsedBinary("elf", (), (), (), (BinarySection(".rodata", 0, 512),))
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    with patch("qrypton.scanners.binary.scanner.parse_binary", return_value=parsed):
        observations = asyncio.run(_collect(scanner, _request(image)))
    assert observations[0].location == EvidenceLocation(
        relative_path="app", byte_start=0, byte_end=512, symbol=".rodata"
    )
    assert observations[0].attributes["entropy_bits_per_byte"] == 8.0
