"""Fail-closed archive recognition and hardened Maven dependency regressions."""

from __future__ import annotations

import asyncio
import io
import tarfile
from pathlib import Path

import pytest

from qrypton.contracts.enums import ObservationState, ScanTargetKind
from qrypton.ports.scanners import ScanRequest, SourceObservation
from qrypton.scanners.extended import ExtendedStaticScanner, LibraryDependencyScanner
from tests.scanners.test_async_scanners import request_for
from tests.scanners.test_source_normalization import context, normalize  # noqa: F401


def collect(scanner: ExtendedStaticScanner, request: ScanRequest) -> list[SourceObservation]:
    async def drain() -> list[SourceObservation]:
        return [item async for item in scanner.scan(request)]

    async def bounded() -> list[SourceObservation]:
        return await asyncio.wait_for(drain(), timeout=3)

    return asyncio.run(bounded())


def tar_bytes(payload: bytes = b"RSA", mode: str = "w") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        member = tarfile.TarInfo("crypto.conf")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


@pytest.mark.parametrize(
    ("name", "data", "kind"),
    [
        ("bad.tar", b"not tar RSA", ScanTargetKind.FILE),
        ("bad.tar.gz", tar_bytes(mode="w:gz")[:20], ScanTargetKind.FILE),
        ("trailer.tar.gz", tar_bytes(mode="w:gz")[:-8], ScanTargetKind.FILE),
        ("bad.zip", b"not zip RSA", ScanTargetKind.FILE),
        ("empty.tar", b"", ScanTargetKind.FILE),
        ("upload.bin", b"not tar RSA", ScanTargetKind.GIT_ARCHIVE),
        ("magic.bin", b"PK\x03\x04not zip RSA", ScanTargetKind.FILE),
    ],
)
def test_invalid_archive(tmp_path: Path, name: str, data: bytes, kind: ScanTargetKind) -> None:
    path = tmp_path / name
    path.write_bytes(data)
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)
    assert collect(scanner, request_for(path, kind)) == []
    assert scanner.partial
    assert scanner.error_code == "invalid_archive"
    assert scanner.failure_reason
    assert "invalid_archive" in scanner.warnings[0]


def test_nested_corruption_discards_all_extraction(tmp_path: Path) -> None:
    path = tmp_path / "outer.tar"
    with tarfile.open(path, "w") as archive:
        for name, data in [("crypto.conf", b"RSA"), ("bad.zip", b"not zip")]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)
    assert collect(scanner, request_for(path, ScanTargetKind.FILE)) == []
    assert scanner.partial
    assert scanner.error_code == "invalid_archive"


@pytest.mark.parametrize(
    ("name", "data"), [("good.tar", tar_bytes()), ("text.txt", b"RSA")], ids=["tar", "text"]
)
def test_valid_archive_and_text(tmp_path: Path, name: str, data: bytes) -> None:
    path = tmp_path / name
    path.write_bytes(data)
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)
    observations = collect(scanner, request_for(path, ScanTargetKind.FILE))
    assert [item.attributes["subject_value"] for item in observations] == ["rsa"]
    assert not scanner.partial
    assert scanner.error_code is None


@pytest.mark.parametrize("version", ["1.78", "${bc.version}"])
def test_bouncy_castle_pom(tmp_path: Path, version: str, context: dict) -> None:  # noqa: F811
    path = tmp_path / "pom.xml"
    path.write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency>'
        "<groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>"
        f"<version>{version}</version><scope>runtime</scope>"
        "</dependency></dependencies></project>",
        encoding="utf-8",
    )
    scanner = LibraryDependencyScanner(allowed_root=tmp_path)
    observations = collect(scanner, request_for(path, ScanTargetKind.FILE))
    assert len(observations) == 1
    observation = observations[0]
    assert observation.attributes["artifact_id"] == "bcprov-jdk18on"
    assert observation.attributes["scope"] == "runtime"
    _, finding = normalize(observation, context)
    assert finding.library.value.name.value == "Bouncy Castle"
    assert finding.library.value.ecosystem.value == "maven"
    assert finding.algorithm.state is ObservationState.UNKNOWN
    if version.startswith("${"):
        assert finding.library.value.version.state is ObservationState.UNKNOWN
    else:
        assert finding.library.value.version.value == "1.78"
    assert not scanner.partial


@pytest.mark.parametrize(
    "data",
    [
        b"<project><dependency>RSA",
        b'<!DOCTYPE project [<!ENTITY a "RSA"><!ENTITY b "&a;&a;&a;">]><project>&b;</project>',
        b'<!DOCTYPE project SYSTEM "file:///etc/passwd"><project/>',
        ('<!DOCTYPE project [<!ENTITY a "RSA">]><project>&a;</project>').encode("utf-16"),
        b"<project>" + b" " * (2 * 1024 * 1024) + b"</project>",
    ],
    ids=["malformed", "entities", "external-dtd", "utf16-dtd", "size-cap"],
)
def test_invalid_or_hostile_pom(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "pom.xml"
    path.write_bytes(data)
    scanner = LibraryDependencyScanner(allowed_root=tmp_path)
    assert collect(scanner, request_for(path, ScanTargetKind.FILE)) == []
    assert scanner.partial
    assert scanner.error_code == "manifest_parse_error"
    assert scanner.failure_reason
    assert "manifest_parse_error" in scanner.warnings[0]


def test_bounded_gzip_bomb_remains_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bomb.tar.gz"
    path.write_bytes(tar_bytes(b"x" * 262144, "w:gz"))
    scanner = ExtendedStaticScanner(allowed_root=tmp_path)
    request = request_for(path, ScanTargetKind.FILE)
    request = request.model_copy(
        update={"limits": request.limits.model_copy(update={"max_expanded_bytes": 65536})}
    )
    with pytest.raises(ValueError, match="expansion limit"):
        collect(scanner, request)
