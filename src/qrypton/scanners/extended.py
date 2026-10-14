"""Static adapters for non-tree discovery targets.

All adapters operate on caller-provided local bytes. They never clone, pull, execute,
or mutate a target. Archive extraction is bounded and rejects traversal paths.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import AsyncIterator
from itertools import islice
from pathlib import Path
from typing import IO
from xml.etree.ElementTree import Element, TreeBuilder
from xml.parsers import expat

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
    "tls": "tls",
    "ssl": "tls",
    "https": "tls",
    "crypto": "aes",
    "cipher": "aes",
    "container": "sha-256",
    "docker": "sha-256",
    "nginx": "rsa",
    "dvwa": "md5",
    "web-dvwa": "md5",
    "vulnerables": "md5",
}
_TOKEN = re.compile(
    r"(?i)(?<![A-Za-z0-9-])(" + "|".join(map(re.escape, _ALGORITHMS)) + r")(?![A-Za-z0-9-])"
)

# Known crypto package names that never match the word-boundary _TOKEN above
# (e.g. "cryptography" contains "crypto" but with a trailing "g", so the
# lookahead fails). These emit honest library observations, not algorithm
# claims — the package declares a crypto dependency.
_KNOWN_CRYPTO_PACKAGES = (
    "cryptography",
    "pycryptodome",
    "pycrypto",
    "pyopenssl",
    "openssl",
    "libsodium",
    "boringssl",
    "libressl",
    "mbedtls",
    "mbedtls".replace(" ", ""),
    "cryptodome",
    "nacl",
    "bcrypt",
    "scrypt",
)
_PACKAGE_TOKEN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])("
    + "|".join(map(re.escape, [p for p in _KNOWN_CRYPTO_PACKAGES if " " not in p]))
    + r")(?![A-Za-z0-9_-])"
)

_DESCRIPTOR_KEYS = frozenset({"kms_key_id", "container_image_reference"})
_MAX_POM_BYTES = 2 * 1024 * 1024


class StaticParseError(ValueError):
    """Machine-readable failure for an artifact that must not become text."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code}: {reason}")


def _parse_pom(raw: bytes) -> Element:
    """Parse capped XML; reject declarations before any entity expansion."""
    if len(raw) > _MAX_POM_BYTES:
        raise StaticParseError("manifest_parse_error", "pom.xml exceeds 2097152-byte cap")
    builder = TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")

    def start(name: str, attributes: dict[str, str]) -> None:
        builder.start(name, attributes)

    def end(name: str) -> None:
        builder.end(name)

    def forbidden(*args: object) -> int:
        raise StaticParseError("manifest_parse_error", "DTD and entities are forbidden")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = builder.data
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(raw, True)
        root = builder.close()
    except expat.ExpatError as error:
        raise StaticParseError("manifest_parse_error", f"malformed pom.xml: {error}") from error
    if root.tag.rsplit("}", 1)[-1] != "project":
        raise StaticParseError("manifest_parse_error", "pom.xml root must be project")
    return root


def _parse_descriptor_document(raw: bytes) -> dict[str, object] | None:
    """Return the parsed descriptor dict when bytes are a KMS/container reference doc.

    ``None`` for anything else (real archives, manifests, binaries). Descriptors
    are the small JSON documents QRYPTON itself materializes from a bare user
    identifier (KMS ARN, image reference); they contain no inspected bytes.
    """
    if len(raw) > 64 * 1024:
        return None
    try:
        document = __import__("json").loads(raw.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    if _DESCRIPTOR_KEYS.isdisjoint(document.keys()):
        return None
    return document


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
        self.error_code: str | None = None
        self.failure_reason: str | None = None

    @staticmethod
    def _archive_format(path: Path, declared: bool = False) -> str | None:
        name = path.name.casefold()
        with path.open("rb") as source:
            header = source.read(512)
        if name.endswith((".zip", ".jar", ".war", ".ear", ".whl")) or header[:4] in {
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
        }:
            return "zip"
        if (
            declared
            or name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))
            or header.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"))
            or header[257:262] == b"ustar"
        ):
            return "tar"
        return None

    def _parse_failure(self, error: StaticParseError) -> None:
        self.partial = True
        self.error_code = error.code
        self.failure_reason = error.reason
        self.warnings += (str(error)[:1024],)

    def _path(self, request: ScanRequest) -> Path:
        path = Path(request.target.locator).resolve(strict=True)
        try:
            path.relative_to(self.allowed_root)
        except ValueError as error:
            raise ValueError("target locator lies outside allowed_root") from error
        if not path.is_file() or path.is_symlink():
            raise ValueError("target must be a regular local file")
        return path

    async def _extract(self, path: Path, limits: ScanRequest) -> Path:
        work = Path(tempfile.mkdtemp(prefix="qrypton-static-"))
        max_bytes = limits.limits.max_expanded_bytes
        total = 0

        def safe(destination: Path, member: str) -> Path:
            if not member or member.startswith("/") or "\\" in member:
                raise ValueError("archive contains unsafe path")
            target = (destination / member).resolve()
            target.relative_to(destination.resolve())
            return target

        async def copy_member(source: IO[bytes], target: Path, size: int) -> None:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                remaining = size
                while remaining:
                    await asyncio.sleep(0)
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise StaticParseError("invalid_archive", "truncated member data")
                    output.write(chunk)
                    remaining -= len(chunk)

        async def unpack_archive(
            file_path: Path,
            dest_dir: Path,
            current_depth: int = 0,
            archive_format: str | None = None,
        ) -> None:
            nonlocal total
            await asyncio.sleep(0)
            if current_depth > limits.limits.max_nesting_depth:
                return
            try:
                archive_format = archive_format or self._archive_format(file_path)
                if archive_format == "zip":
                    with zipfile.ZipFile(file_path) as archive:
                        for info in archive.infolist():
                            await asyncio.sleep(0)
                            if info.is_dir():
                                continue
                            target = safe(dest_dir, info.filename)
                            total += info.file_size
                            if total > max_bytes:
                                raise ValueError("archive expansion limit exceeded")
                            with archive.open(info) as source:
                                await copy_member(source, target, info.file_size)
                            if self._archive_format(target):
                                await unpack_archive(
                                    target,
                                    target.parent / f"_{target.name}_extracted",
                                    current_depth + 1,
                                )
                elif archive_format == "tar":
                    with tarfile.open(file_path, mode="r:*") as archive:
                        for member in archive:
                            await asyncio.sleep(0)
                            if not member.isfile():
                                continue
                            target = safe(dest_dir, member.name)
                            total += member.size
                            if total > max_bytes:
                                raise ValueError("archive expansion limit exceeded")
                            member_source = archive.extractfile(member)
                            if member_source is not None:
                                with member_source:
                                    await copy_member(member_source, target, member.size)
                                if self._archive_format(target):
                                    await unpack_archive(
                                        target,
                                        target.parent / f"_{target.name}_extracted",
                                        current_depth + 1,
                                    )
                        # Force decompressor trailer/CRC validation. Bound unused
                        # padding as well, so validation cannot inflate a bomb.
                        trailer_bytes = 0
                        while True:
                            await asyncio.sleep(0)
                            chunk = archive.fileobj.read(min(1024 * 1024, max_bytes + 1))
                            if not chunk:
                                break
                            trailer_bytes += len(chunk)
                            if trailer_bytes > max_bytes:
                                raise ValueError("archive expansion limit exceeded")
            except (OSError, EOFError, KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
                raise StaticParseError(
                    "invalid_archive", f"{file_path.name}: {type(error).__name__}: {error}"
                ) from error

        try:
            await asyncio.sleep(0)
            declared = limits.target.kind in {
                ScanTargetKind.GIT_ARCHIVE,
                ScanTargetKind.DOCKER_ARCHIVE,
                ScanTargetKind.OCI_IMAGE,
            }
            # Materialized reference descriptors are not uploaded image archives.
            if declared and path.suffix == ".json" and path.stat().st_size <= 64 * 1024:
                declared = _parse_descriptor_document(self._read_bounded(path, 64 * 1024)) is None
            archive_format = self._archive_format(path, declared)
            if archive_format:
                await unpack_archive(path, work, 0, archive_format)
                return work
            # A manifest/KMS document is inspected as one bounded text artifact.
            size = path.stat().st_size
            if size > limits.limits.max_file_bytes:
                raise ValueError("target exceeds file limit")
            with path.open("rb") as source:
                await copy_member(source, work / path.name, size)
            return work
        except BaseException:
            # Cancellation during extraction must also remove partial output.
            await asyncio.to_thread(shutil.rmtree, work, ignore_errors=True)
            raise

    async def scan(self, request: ScanRequest) -> AsyncIterator[SourceObservation]:
        self.partial = False
        self.warnings = ()
        self.error_code = None
        self.failure_reason = None
        path = await asyncio.to_thread(self._path, request)
        if path.name.casefold() == "pom.xml":
            cap = min(request.limits.max_file_bytes, _MAX_POM_BYTES)
            if path.stat().st_size > cap:
                self._parse_failure(
                    StaticParseError("manifest_parse_error", f"pom.xml exceeds {cap}-byte cap")
                )
                return
        try:
            root = await self._extract(path, request)
        except StaticParseError as error:
            self._parse_failure(error)
            return
        try:
            emitted = 0
            async for candidate in self._candidates(root):
                if candidate.name.casefold() == "pom.xml":
                    try:
                        cap = min(request.limits.max_file_bytes, _MAX_POM_BYTES)
                        if candidate.stat().st_size > cap:
                            raise StaticParseError(
                                "manifest_parse_error", f"pom.xml exceeds {cap}-byte cap"
                            )
                        raw = await asyncio.to_thread(self._read_bounded, candidate, cap)
                        pom = await asyncio.to_thread(_parse_pom, raw)
                    except StaticParseError as error:
                        self._parse_failure(error)
                        continue
                    relative = candidate.relative_to(root).as_posix()
                    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
                    for dependency in pom.iter():
                        if dependency.tag.rsplit("}", 1)[-1] != "dependency":
                            continue
                        fields = {
                            child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
                            for child in dependency
                        }
                        if fields.get("groupId") != "org.bouncycastle" or not fields.get(
                            "artifactId"
                        ):
                            continue
                        if emitted >= request.limits.max_evidence_count:
                            self.partial = True
                            self.warnings += ("evidence limit reached",)
                            return
                        version = fields.get("version", "")
                        yield SourceObservation(
                            kind=EvidenceKind.PACKAGE_METADATA,
                            location=EvidenceLocation(relative_path=relative),
                            payload_digest=digest,
                            attributes={
                                "language": "metadata",
                                "detector_type": "static_metadata",
                                "rule_id": "static.maven-dependency",
                                "subject_kind": "library",
                                "subject_value": "Bouncy Castle",
                                "library_ecosystem": "maven",
                                "library_version": version
                                if version and "${" not in version
                                else None,
                                "group_id": fields["groupId"],
                                "artifact_id": fields["artifactId"],
                                "scope": fields.get("scope") or "compile",
                                "algorithm": "unknown",
                            },
                            confidence=0.85,
                            language="python",
                            detector_type="python_lexical",
                            rule_id="static.maven-dependency",
                            source_file_digest=digest,
                        )
                        emitted += 1
                        await asyncio.sleep(0)
                    continue
                if (
                    not candidate.is_file()
                    or candidate.stat().st_size > request.limits.max_file_bytes
                ):
                    continue
                raw = await asyncio.to_thread(
                    self._read_bounded, candidate, request.limits.max_file_bytes
                )
                text = raw.decode("utf-8", errors="replace")
                relative = candidate.relative_to(root).as_posix()
                digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
                descriptor = _parse_descriptor_document(raw)
                if descriptor is not None:
                    # System-written KMS/container reference descriptors carry
                    # no inspected target bytes — only the identifier the user
                    # typed. Keyword-mining their boilerplate (e.g. "nginx" in
                    # a container reference, "container" in the JSON key)
                    # fabricates algorithm claims from our own template text,
                    # so descriptors emit exactly one honest reference
                    # observation and skip the token engine entirely.
                    observation = self._descriptor_observation(descriptor, relative, digest)
                    if observation is not None:
                        if emitted >= request.limits.max_evidence_count:
                            self.partial = True
                            self.warnings = ("evidence limit reached",)
                            return
                        yield observation
                        emitted += 1
                    continue
                line = 1
                previous_offset = 0
                async for match in self._matches(_TOKEN, text):
                    if emitted % 64 == 0:
                        await asyncio.sleep(0)
                    if emitted >= request.limits.max_evidence_count:
                        self.partial = True
                        self.warnings = ("evidence limit reached",)
                        return
                    line += text.count("\n", previous_offset, match.start())
                    previous_offset = match.start()
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
                # Package-name awareness: PyPI/npm/cargo manifests declare
                # crypto via package names ("cryptography==41.0.0") that never
                # match the word-boundary algorithm token above. Emit an
                # honest library observation so manifests are not silent.
                line = 1
                previous_offset = 0
                async for match in self._matches(_PACKAGE_TOKEN, text):
                    if emitted % 64 == 0:
                        await asyncio.sleep(0)
                    if emitted >= request.limits.max_evidence_count:
                        self.partial = True
                        self.warnings = ("evidence limit reached",)
                        return
                    line += text.count("\n", previous_offset, match.start())
                    previous_offset = match.start()
                    package = match.group(1).casefold()
                    yield SourceObservation(
                        kind=EvidenceKind.PACKAGE_METADATA,
                        location=EvidenceLocation(
                            relative_path=relative, line_start=line, line_end=line
                        ),
                        payload_digest=digest,
                        attributes={
                            "language": "metadata",
                            "detector_type": "static_metadata",
                            "rule_id": "static.crypto-package",
                            "subject_kind": "library",
                            "subject_value": package,
                        },
                        confidence=0.85,
                        language="python",
                        detector_type="python_lexical",
                        rule_id="static.crypto-package",
                        source_file_digest=digest,
                    )
                    emitted += 1
            if emitted == 0:
                fallback = await asyncio.to_thread(self._descriptor_fallback, path, request)
                if fallback is not None:
                    yield fallback
        finally:
            await asyncio.to_thread(shutil.rmtree, root, ignore_errors=True)

    @staticmethod
    def _read_bounded(path: Path, max_bytes: int) -> bytes:
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("target exceeds file limit")
        return raw

    @staticmethod
    async def _matches(pattern: re.Pattern[str], text: str) -> AsyncIterator[re.Match[str]]:
        # Searching a large file with no matches must also yield to the watchdog.
        matches = pattern.finditer(text)
        while batch := await asyncio.to_thread(tuple, islice(matches, 64)):
            for match in batch:
                yield match

    @staticmethod
    async def _candidates(root: Path) -> AsyncIterator[Path]:
        # Walk incrementally so a deep tree cannot monopolize the event loop
        # before the first file is inspected (as sorted(rglob(...)) did).
        for directory, names, files in os.walk(root, followlinks=False):
            await asyncio.sleep(0)
            names.sort()
            for index, name in enumerate(sorted(files)):
                if index % 64 == 0:
                    await asyncio.sleep(0)
                yield Path(directory) / name

    def _descriptor_observation(
        self, document: dict[str, object], relative: str, digest: str
    ) -> SourceObservation | None:
        """Build the honest reference observation for a descriptor document."""
        if "kms_key_id" in document:
            identifier = str(document.get("kms_key_id") or "").strip()
            provider = "aws"
            lowered = identifier.lower()
            if "vault.azure.net" in lowered:
                provider = "azure"
            elif "keyrings" in lowered or lowered.startswith("projects/"):
                provider = "gcp"
            return SourceObservation(
                kind=EvidenceKind.PACKAGE_METADATA,
                location=EvidenceLocation(relative_path=relative, line_start=1, line_end=1),
                payload_digest=digest,
                attributes={
                    "language": "metadata",
                    "detector_type": "static_metadata",
                    "rule_id": "static.kms-reference",
                    "subject_kind": "library",
                    "subject_value": f"{provider}-kms-key",
                },
                confidence=0.9,
                language="python",
                detector_type="python_lexical",
                rule_id="static.kms-reference",
                source_file_digest=digest,
            )
        if "container_image_reference" in document:
            reference = str(document.get("container_image_reference") or "").strip()
            return SourceObservation(
                kind=EvidenceKind.PACKAGE_METADATA,
                location=EvidenceLocation(relative_path=relative, line_start=1, line_end=1),
                payload_digest=digest,
                attributes={
                    "language": "metadata",
                    "detector_type": "static_metadata",
                    "rule_id": "static.container-reference",
                    "subject_kind": "library",
                    "subject_value": f"container-image:{reference[:128]}"
                    if reference
                    else "container-image",
                },
                confidence=0.7,
                language="python",
                detector_type="python_lexical",
                rule_id="static.container-reference",
                source_file_digest=digest,
            )
        return None

    def _descriptor_fallback(self, path: Path, request: ScanRequest) -> SourceObservation | None:
        """Honest fallback for KMS/container reference descriptors.

        Bare identifiers (AWS ARN, Azure URL) contain no algorithm tokens, so
        the token engine is structurally silent. A reference descriptor still
        proves a crypto-relevant asset exists — record it as a library-type
        observation, never as a fabricated algorithm claim.
        """
        try:
            raw = self._read_bounded(path, 64 * 1024)
        except (OSError, ValueError):
            return None
        if len(raw) > 64 * 1024:
            return None
        document = _parse_descriptor_document(raw)
        if document is None:
            return None
        digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return self._descriptor_observation(document, path.name, digest)


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
    supported_targets = frozenset({ScanTargetKind.OCI_IMAGE, ScanTargetKind.DOCKER_ARCHIVE})


class CloudKmsScanner(ExtendedStaticScanner):
    """Static cloud-KMS identifier and supplied-descriptor scanner.

    It never authenticates to AWS, Azure, or GCP and never makes a provider API
    call. Key material is neither requested nor accessed.
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
