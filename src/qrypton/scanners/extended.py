"""Static adapters for non-tree discovery targets.

All adapters operate on caller-provided local bytes. They never clone, pull, execute,
or mutate a target. Archive extraction is bounded and rejects traversal paths.
"""

from __future__ import annotations

import hashlib
import re
import tarfile
import tempfile
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

from qrypton.contracts.enums import EvidenceKind, ScanTargetKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import ScanRequest, SourceObservation

_ALGORITHMS = {
    "rsa": "rsa",
    "sha1": "sha-1",
    "sha-256": "sha-256",
    "sha256": "sha-256",
    "md5": "md5",
    "des": "des",
    "3des": "3des",
    "ecdh": "ecdh",
    "ecdsa": "ecdsa",
    "ed25519": "ed25519",
    "x25519": "x25519",
    "aes": "aes",
    "chacha20": "chacha20",
    "ml-kem": "ml-kem",
    "kyber": "ml-kem",
    "ml-dsa": "ml-dsa",
    "dilithium": "ml-dsa",
}
_TOKEN = re.compile(
    r"(?i)(?<![A-Za-z0-9-])(" + "|".join(map(re.escape, _ALGORITHMS)) + r")(?![A-Za-z0-9-])"
)


class ExtendedStaticScanner:
    name = "qrypton-source"
    version = "0.4.0"
    supported_targets = frozenset(
        {
            ScanTargetKind.GIT_ARCHIVE,
            ScanTargetKind.OCI_IMAGE,
            ScanTargetKind.DOCKER_ARCHIVE,
            "file",
        }
    )

    def __init__(self, *, allowed_root: Path) -> None:
        self.allowed_root = allowed_root.resolve(strict=True)
        self.warnings: tuple[str, ...] = ()
        self.partial = False

    def _path(self, request: ScanRequest) -> Path:
        path = Path(request.target.locator).resolve(strict=True)
        try:
            path.relative_to(self.allowed_root)
        except ValueError as error:
            raise ValueError("target locator lies outside allowed_root") from error
        if not path.is_file() or path.is_symlink():
            raise ValueError("target must be a regular local file")
        return path

    def _extract(self, path: Path, limits: ScanRequest) -> Path:
        work = Path(tempfile.mkdtemp(prefix="qrypton-static-"))
        max_bytes = limits.limits.max_expanded_bytes
        total = 0

        def safe(destination: Path, member: str) -> Path:
            if not member or member.startswith("/") or "\\" in member:
                raise ValueError("archive contains unsafe path")
            target = (destination / member).resolve()
            target.relative_to(destination.resolve())
            return target

        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.is_dir():
                            continue
                        target = safe(work, info.filename)
                        total += info.file_size
                        if total > max_bytes:
                            raise ValueError("archive expansion limit exceeded")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.read(info))
                return work
            if tarfile.is_tarfile(path):
                with tarfile.open(path, mode="r:*") as archive:
                    for member in archive.getmembers():
                        if not member.isfile():
                            continue
                        target = safe(work, member.name)
                        total += member.size
                        if total > max_bytes:
                            raise ValueError("archive expansion limit exceeded")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is not None:
                            target.write_bytes(source.read(max_bytes - total + member.size))
                return work
        except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
            raise ValueError(f"archive inspection failed: {error}") from error
        # A manifest/KMS document is inspected as one bounded text artifact.
        data = path.read_bytes()
        if len(data) > limits.limits.max_file_bytes:
            raise ValueError("target exceeds file limit")
        (work / path.name).write_bytes(data)
        return work

    async def scan(self, request: ScanRequest) -> AsyncIterator[SourceObservation]:
        path = self._path(request)
        root = self._extract(path, request)
        try:
            emitted = 0
            for candidate in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
                if (
                    not candidate.is_file()
                    or candidate.stat().st_size > request.limits.max_file_bytes
                ):
                    continue
                raw = candidate.read_bytes()
                text = raw.decode("utf-8", errors="replace")
                relative = candidate.relative_to(root).as_posix()
                digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
                for match in _TOKEN.finditer(text):
                    if emitted >= request.limits.max_evidence_count:
                        self.partial = True
                        self.warnings = ("evidence limit reached",)
                        return
                    line = text.count("\n", 0, match.start()) + 1
                    token = match.group(1).casefold()
                    yield SourceObservation(
                        kind=EvidenceKind.PACKAGE_METADATA
                        if path.suffix in {".json", ".yaml", ".yml", ".lock"}
                        else EvidenceKind.SOURCE_LEXICAL,
                        location=EvidenceLocation(
                            relative_path=relative, line_start=line, line_end=line
                        ),
                        payload_digest=digest,
                        attributes={
                            "language": "metadata",
                            "detector_type": "static_metadata",
                            "rule_id": "static.crypto-token",
                            "subject_kind": "algorithm",
                            "subject_value": _ALGORITHMS[token],
                        },
                        confidence=0.75,
                        language="python",
                        detector_type="python_lexical",
                        rule_id="static.crypto-token",
                        source_file_digest=digest,
                    )
                    emitted += 1
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)
        self.partial = False
        self.warnings = ()


class LibraryDependencyScanner(ExtendedStaticScanner):
    """Library/dependency target scanner: manifests, packages, wheels, JARs.

    Same static archive/token engine as :class:`ExtendedStaticScanner`; the
    distinct name routes LIBRARY targets to their own scanner and keeps the
    original target type visible through normalization into the CBOM.
    """

    name = "qrypton-library"
    version = "0.4.0"
    supported_targets = frozenset({ScanTargetKind.FILE})


class ContainerImageScanner(ExtendedStaticScanner):
    """Container target scanner: OCI/Docker archives and image references.

    Layers, files, packages, libraries, and configuration are read statically;
    registries are never pulled and containers are never started.
    """

    name = "qrypton-container"
    version = "0.4.0"
    supported_targets = frozenset(
        {ScanTargetKind.OCI_IMAGE, ScanTargetKind.DOCKER_ARCHIVE}
    )


class CloudKmsScanner(ExtendedStaticScanner):
    """Cloud KMS target scanner: key metadata exports and key descriptors.

    Only key identifiers and metadata documents are inspected; key material is
    never requested or accessed.
    """

    name = "qrypton-kms"
    version = "0.4.0"
    supported_targets = frozenset({ScanTargetKind.FILE})


__all__ = [
    "CloudKmsScanner",
    "ContainerImageScanner",
    "ExtendedStaticScanner",
    "LibraryDependencyScanner",
]
