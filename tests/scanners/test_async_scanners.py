"""Watchdog regressions: real traversal/extraction and controlled slow CPU stages."""

from __future__ import annotations

import asyncio
import io
import tarfile
import threading
import time
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from qrypton.contracts.enums import ObservationState, ScanTargetKind
from qrypton.contracts.models import Observation, Provenance, ScanTarget
from qrypton.ports.scanners import ScanLimits, ScanRequest
from qrypton.scanners.binary import scanner as binary_module
from qrypton.scanners.binary.entropy import shannon_entropy
from qrypton.scanners.binary.formats import BinarySection, ParsedBinary
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.extended import ExtendedStaticScanner
from qrypton.scanners.source import scanner as source_module
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.scanner import LocalSourceScanner


def request_for(path: Path, kind: ScanTargetKind) -> ScanRequest:
    now = datetime.now(UTC)
    return ScanRequest(
        tenant_id="tenant_" + "a" * 52,
        target=ScanTarget(
            id="target_" + "b" * 52,
            tenant_id="tenant_" + "a" * 52,
            asset_id="asset_" + "c" * 52,
            kind=kind,
            locator=str(path),
            content_digest=Observation(state=ObservationState.UNKNOWN),
            declared_size_bytes=Observation(state=ObservationState.UNKNOWN),
            requested_at=now,
            provenance=Provenance(
                scanner_name="async-test",
                scanner_version="1.0",
                scanner_config_digest="sha256:" + "a" * 64,
                observed_at=now,
            ),
        ),
        limits=ScanLimits(
            max_compressed_bytes=64 * 1024 * 1024,
            max_expanded_bytes=128 * 1024 * 1024,
            max_file_count=10_000,
            max_nesting_depth=30,
            max_layer_count=128,
            max_ast_nodes=100_000,
            max_evidence_count=10_000,
            max_wall_time_seconds=60,
            max_memory_bytes=256 * 1024 * 1024,
        ),
        correlation_id="async-test",
    )


async def drain(stream: AsyncIterator[object]) -> list[object]:
    return [item async for item in stream]


def test_deep_source_discovery_times_out_and_stops_walking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "tree"
    directory = root
    for _ in range(20):
        directory /= "d"
        directory.mkdir(parents=True)
        for index in range(25):
            (directory / f"{index}.py").write_text("import hashlib\n")
    started, stopped = threading.Event(), threading.Event()
    original_read = Path.read_bytes
    original_walk = source_module.iter_source_files
    reads = 0

    def slow_read(path: Path) -> bytes:
        nonlocal reads
        if path.suffix == ".py":
            reads += 1
            started.set()
            time.sleep(0.002)
        return original_read(path)

    def tracked_walk(*args, **kwargs):
        try:
            return original_walk(*args, **kwargs)
        finally:
            stopped.set()

    monkeypatch.setattr(Path, "read_bytes", slow_read)
    monkeypatch.setattr(source_module, "iter_source_files", tracked_walk)
    scanner = LocalSourceScanner(SourceScanPolicy(allowed_root=tmp_path))

    async def run() -> None:
        task = asyncio.create_task(
            drain(scanner.scan(request_for(root, ScanTargetKind.SOURCE_TREE)))
        )
        try:
            assert await asyncio.to_thread(started.wait, 2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, timeout=0.02)
            assert await asyncio.to_thread(stopped.wait, 2)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    assert 0 < reads < 500


def test_source_ast_work_does_not_block_watchdog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    started, release = threading.Event(), threading.Event()
    original = source_module.analyze_python_ast
    worker_threads: list[int] = []

    def slow_parser(*args, **kwargs):
        worker_threads.append(threading.get_ident())
        started.set()
        release.wait(2)
        yield from original(*args, **kwargs)

    monkeypatch.setattr(source_module, "analyze_python_ast", slow_parser)
    scanner = LocalSourceScanner(SourceScanPolicy(allowed_root=tmp_path))

    async def run() -> None:
        task = asyncio.create_task(
            drain(scanner.scan(request_for(tmp_path, ScanTargetKind.SOURCE_TREE)))
        )
        try:
            assert await asyncio.to_thread(started.wait, 2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, timeout=0.02)
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    assert worker_threads and threading.get_ident() not in worker_threads


@pytest.mark.parametrize("archive_type", ["zip", "tar"])
def test_archive_cancellation_removes_partial_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    archive_type: str,
) -> None:
    archive_path = tmp_path / f"source.{archive_type}"
    if archive_type == "zip":
        with zipfile.ZipFile(archive_path, "w") as archive:
            for index in range(300):
                archive.writestr(f"d/{index}.py", "rsa\n")
    else:
        with tarfile.open(archive_path, "w") as archive:
            for index in range(300):
                info = tarfile.TarInfo(f"d/{index}.py")
                info.size = 4
                archive.addfile(info, io.BytesIO(b"rsa\n"))
    output = tmp_path / "extracted"
    output.mkdir()
    monkeypatch.setattr("qrypton.scanners.extended.tempfile.mkdtemp", lambda **kwargs: str(output))
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)
    original_open = Path.open
    writes = 0

    async def run() -> None:
        first_write = asyncio.Event()

        def tracked_open(path: Path, *args, **kwargs):
            nonlocal writes
            if args and args[0] == "wb" and path.is_relative_to(output):
                writes += 1
                first_write.set()
                time.sleep(0.001)
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", tracked_open)
        task = asyncio.create_task(
            drain(scanner.scan(request_for(archive_path, ScanTargetKind.GIT_ARCHIVE)))
        )
        try:
            await asyncio.wait_for(first_write.wait(), timeout=2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, timeout=0.005)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    assert 0 < writes < 300
    assert not output.exists()


def test_large_binary_entropy_runs_in_executor_with_responsive_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "large.elf"
    path.write_bytes(bytes(range(256)) * (11 * 4096))  # 11 MiB
    section = BinarySection(".data", 0, path.stat().st_size)
    monkeypatch.setattr(
        binary_module,
        "parse_binary",
        Mock(return_value=ParsedBinary("elf", (), (), (), (section,))),
    )
    started, release = threading.Event(), threading.Event()
    threads: list[int] = []
    streams = []

    def tracked_entropy(stream, **kwargs):
        threads.append(threading.get_ident())
        streams.append(stream)
        started.set()
        assert release.wait(2), "event loop did not respond during entropy calculation"
        return shannon_entropy(stream, **kwargs)

    monkeypatch.setattr(binary_module, "shannon_entropy", tracked_entropy)
    scanner = LocalBinaryScanner(allowed_root=tmp_path)

    async def run():
        task = asyncio.create_task(drain(scanner.scan(request_for(path, ScanTargetKind.ELF))))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            release.set()
            return await asyncio.wait_for(task, timeout=5)
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    observations = asyncio.run(run())
    assert threads and threading.get_ident() not in threads
    assert streams and all(stream.closed for stream in streams)
    assert observations[0].attributes["entropy_bits_per_byte"] == 8.0


def test_binary_timeout_signals_entropy_worker_and_closes_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "binary"
    path.write_bytes(bytes(range(256)))
    parsed = ParsedBinary("elf", (), (), (), (BinarySection(".data", 0, 256),))
    monkeypatch.setattr(binary_module, "parse_binary", Mock(return_value=parsed))
    started = threading.Event()
    cancellations: list[bool] = []
    streams = []

    def slow_entropy(stream, **kwargs):
        streams.append(stream)
        started.set()
        cancellations.append(kwargs["cancelled"].wait(2))
        return shannon_entropy(stream, **kwargs)

    monkeypatch.setattr(binary_module, "shannon_entropy", slow_entropy)
    scanner = LocalBinaryScanner(allowed_root=tmp_path)

    async def run() -> None:
        task = asyncio.create_task(drain(scanner.scan(request_for(path, ScanTargetKind.ELF))))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, timeout=0.02)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    assert cancellations == [True]
    assert streams and all(stream.closed for stream in streams)


def test_entropy_stops_between_chunks() -> None:
    cancelled = threading.Event()

    class CancellingStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            cancelled.set()
            return super().read(size)

    with pytest.raises(InterruptedError, match="cancelled"):
        shannon_entropy(
            CancellingStream(bytes(range(256))),
            offset=0,
            size=256,
            chunk_size=64,
            cancelled=cancelled,
        )


def test_dense_metadata_matches_yield_and_preserve_line_numbers(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("rsa\n" * 1000)
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)

    async def run() -> None:
        first_match = asyncio.Event()
        observations = []
        progress: list[int] = []

        async def heartbeat() -> None:
            await first_match.wait()
            progress.append(len(observations))

        observer = asyncio.create_task(heartbeat())
        async for observation in scanner.scan(request_for(path, ScanTargetKind.FILE)):
            observations.append(observation)
            first_match.set()
        await observer
        assert 0 < progress[0] < 1000
        assert [item.location.line_start for item in observations] == list(range(1, 1001))

    asyncio.run(run())


def test_binary_nonmatching_symbols_allow_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "binary"
    path.write_bytes(b"ELF!")
    parsed = ParsedBinary("elf", tuple(f"puts_{index}" for index in range(1024)), (), (), ())
    monkeypatch.setattr(binary_module, "parse_binary", Mock(return_value=parsed))
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    inspected = 0

    async def run() -> None:
        first_symbol = asyncio.Event()

        def nonmatching_symbol(symbol: str) -> bool:
            nonlocal inspected
            inspected += 1
            first_symbol.set()
            time.sleep(0.001)
            return False

        monkeypatch.setattr(scanner, "_is_crypto_symbol", nonmatching_symbol)
        task = asyncio.create_task(drain(scanner.scan(request_for(path, ScanTargetKind.ELF))))
        try:
            await asyncio.wait_for(first_symbol.wait(), timeout=2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, timeout=0.005)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(run())
    assert 0 < inspected < 1024
