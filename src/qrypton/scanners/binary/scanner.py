"""Read-only executable scanner with strict file and evidence limits."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator
from pathlib import Path
from threading import Event

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import BinaryObservation, ScanRequest
from qrypton.scanners.binary.entropy import shannon_entropy
from qrypton.scanners.binary.formats import BinarySection, parse_binary

_CRYPTO_TOKENS = (
    "aes",
    "argon",
    "bcrypt",
    "blowfish",
    "camellia",
    "cert",
    "chacha",
    "crypt",
    "3des",
    "des_",
    "_des",
    "dh_",
    "_dh",
    "diffie",
    "dsa",
    "ec_",
    "ecdsa",
    "ecdh",
    "ed25519",
    "evp_",
    "hkdf",
    "hmac",
    "md5",
    "ncrypt",
    "pbkdf",
    "pkcs",
    "pfx",
    "rc2",
    "rc4",
    "rsa",
    "sha",
    "scrypt",
    "tls",
    "x25519",
    "x509",
)
_EXCLUDED_SUBSTRINGS = (
    "description",
    "destination",
    "descriptor",
    "desired",
    "width",
    "header",
    "handle",
    "marshal",
    "unshare",
    "shape",
    "shared",
    "reparse",
    "universal",
    "srwlock",
    "rich",
)
_ENTROPY_THRESHOLD = 7.5


class LocalBinaryScanner:
    """Parse one approved local ELF, PE, or Mach-O image without executing it."""

    name = "qrypton-binary"
    version = "0.3.0"
    supported_targets = frozenset({"elf", "pe", "mach_o", "file"})

    def __init__(
        self, *, allowed_root: Path, entropy_threshold: float = _ENTROPY_THRESHOLD
    ) -> None:
        self.allowed_root = allowed_root.resolve(strict=True)
        if not 0.0 <= entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be between 0 and 8")
        self.entropy_threshold = entropy_threshold
        self.warnings: tuple[str, ...] = ()
        self.partial = False

    async def scan(self, request: ScanRequest) -> AsyncIterator[BinaryObservation]:
        cancelled = Event()
        try:
            async for observation in self._scan(request, cancelled):
                yield observation
        finally:
            cancelled.set()

    async def _scan(
        self, request: ScanRequest, cancelled: Event
    ) -> AsyncIterator[BinaryObservation]:
        path = await asyncio.to_thread(self._resolve, request)
        warnings: list[str] = []
        self.partial = False
        if path.is_symlink():
            self.warnings = ("skipped symlink target",)
            self.partial = True
            return
        try:
            size = (await asyncio.to_thread(path.stat)).st_size
        except OSError:
            self.warnings = ("unreadable binary metadata",)
            self.partial = True
            return
        if size > request.limits.max_file_bytes:
            self.warnings = ("skipped oversized binary",)
            self.partial = True
            return
        deadline = time.monotonic() + request.limits.max_wall_time_seconds
        digest = await asyncio.to_thread(
            self._digest, path, request.limits.max_file_bytes, cancelled
        )
        try:
            parsed = await asyncio.to_thread(parse_binary, path)
        except (OSError, ValueError) as error:
            # Malformed/truncated headers must not go silent: fall through to
            # the bounded strings scan below so `strings | grep -i aes`
            # parity holds. Structured parse is preferred, strings are backup.
            warnings.append(f"binary parsing skipped: {error}; trying strings fallback")
            parsed = None
            self.partial = True
        emitted = 0
        if parsed is not None:
            if parsed.partial:
                self.partial = True
                warnings.extend(parsed.warnings)
            for kind, values in (("import", parsed.imports), ("export", parsed.exports)):
                for symbol_index, symbol in enumerate(values):
                    if symbol_index % 64 == 0:
                        await asyncio.sleep(0)
                    if not self._is_crypto_symbol(symbol):
                        continue
                    if emitted >= request.limits.max_evidence_count:
                        warnings.append("binary evidence limit reached")
                        self.partial = True
                        self.warnings = tuple(warnings)
                        return
                    emitted += 1
                    yield self._symbol_observation(
                        parsed.format, digest, symbol, kind, relative_path=path.name
                    )
            for library_index, library in enumerate(parsed.libraries):
                if library_index % 64 == 0:
                    await asyncio.sleep(0)
                if not self._is_crypto_library(library):
                    continue
                if emitted >= request.limits.max_evidence_count:
                    warnings.append("binary evidence limit reached")
                    self.partial = True
                    self.warnings = tuple(warnings)
                    return
                emitted += 1
                yield BinaryObservation(
                    kind=EvidenceKind.BINARY_IMPORT,
                    location=EvidenceLocation(relative_path=path.name, symbol=library),
                    payload_digest=digest,
                    attributes={"subject_kind": "library", "subject_value": library},
                    confidence=0.95,
                    format=parsed.format,
                    detector_type="import",
                    binary_digest=digest,
                )
        if parsed is not None:
            for section in parsed.sections:
                await asyncio.sleep(0)
                if time.monotonic() > deadline:
                    warnings.append("binary scan wall-time limit reached")
                    self.partial = True
                    break
                if not self._valid_section(section, size):
                    continue
                # The worker owns its stream: cancellation cannot close a
                # file handle while an executor thread is still reading it.
                entropy = await asyncio.to_thread(self._entropy, path, section, cancelled)
                if entropy < self.entropy_threshold or section.size < 32:
                    continue
                if emitted >= request.limits.max_evidence_count:
                    warnings.append("binary evidence limit reached")
                    self.partial = True
                    break
                emitted += 1
                yield BinaryObservation(
                    kind=EvidenceKind.BINARY_STRING,
                    location=EvidenceLocation(
                        relative_path=path.name,
                        byte_start=section.offset,
                        byte_end=section.offset + section.size,
                        symbol=section.name or None,
                    ),
                    payload_digest=digest,
                    attributes={
                        "subject_kind": "high_entropy_section",
                        "subject_value": section.name or "unnamed",
                        "entropy_bits_per_byte": round(entropy, 4),
                        "section_size_bytes": section.size,
                    },
                    confidence=0.55,
                    format=parsed.format,
                    detector_type="entropy",
                    binary_digest=digest,
                )
        if emitted == 0:
            # Strings fallback: `strings binary | grep -i <token>` parity.
            # Structured parse found nothing (or was skipped) — scan printable
            # strings for crypto tokens so AES/RSA/SHA references in .rodata
            # are not silent. Bounded: file already ≤ max_file_bytes.
            try:
                text = await asyncio.to_thread(self._read_text, path, request.limits.max_file_bytes)
            except OSError:
                text = ""
            if text:
                seen: set[str] = set()
                for token in _CRYPTO_TOKENS:
                    await asyncio.sleep(0)
                    if len(seen) >= 20 or emitted >= request.limits.max_evidence_count:
                        break
                    if token in text and token not in seen:
                        seen.add(token)
                        emitted += 1
                        # Map short binary tokens to stable subject values.
                        subject = token.rstrip("_")
                        yield BinaryObservation(
                            kind=EvidenceKind.BINARY_STRING,
                            location=EvidenceLocation(
                                relative_path=path.name, symbol=f"strings:{subject}"
                            ),
                            payload_digest=digest,
                            attributes={
                                "subject_kind": "algorithm",
                                "subject_value": subject,
                            },
                            confidence=0.65,
                            format=parsed.format if parsed is not None else "elf",
                            detector_type="entropy",
                            binary_digest=digest,
                        )
                if seen:
                    warnings.append(f"strings fallback matched: {','.join(sorted(seen))}")
        self.warnings = tuple(warnings[:100])

    def _resolve(self, request: ScanRequest) -> Path:
        if request.target.kind.value not in self.supported_targets:
            raise ValueError("binary scanner does not support target kind")
        if "\x00" in request.target.locator:
            raise ValueError("target locator contains NUL")
        path = Path(request.target.locator)
        # Resolve only after rejecting symlinks: no scanner path ever follows one.
        if path.is_symlink():
            return path
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(self.allowed_root)
        except ValueError as error:
            raise ValueError("target locator lies outside allowed_root") from error
        if not resolved.is_file():
            raise ValueError("binary target must be an existing regular file")
        return resolved

    @staticmethod
    def _digest(path: Path, max_bytes: int, cancelled: Event) -> str:
        digest = hashlib.sha256()
        consumed = 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                if cancelled.is_set():
                    raise InterruptedError("binary hashing cancelled")
                consumed += len(chunk)
                if consumed > max_bytes:
                    raise ValueError("binary exceeds file limit")
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _entropy(path: Path, section: BinarySection, cancelled: Event) -> float:
        with path.open("rb") as stream:
            return shannon_entropy(
                stream, offset=section.offset, size=section.size, cancelled=cancelled
            )

    @staticmethod
    def _read_text(path: Path, max_bytes: int) -> str:
        with path.open("rb") as stream:
            blob = stream.read(max_bytes + 1)
        if len(blob) > max_bytes:
            raise ValueError("binary exceeds file limit")
        return blob.decode("utf-8", errors="replace").casefold()

    @staticmethod
    def _is_crypto_library(library_name: str) -> bool:
        normalized = library_name.casefold()
        return any(
            token in normalized
            for token in (
                "crypt",
                "bcrypt",
                "ncrypt",
                "ssl",
                "tls",
                "cert",
                "sec",
                "mbed",
                "gnutls",
                "nss",
                "boring",
                "sodium",
            )
        )

    @staticmethod
    def _is_crypto_symbol(symbol: str) -> bool:
        normalized = symbol.casefold().lstrip("_")
        if any(ex in normalized for ex in _EXCLUDED_SUBSTRINGS):
            return False
        return any(token in normalized for token in _CRYPTO_TOKENS)

    @staticmethod
    def _valid_section(section: BinarySection, size: int) -> bool:
        return section.offset >= 0 and section.size >= 0 and section.offset <= size - section.size

    @staticmethod
    def _symbol_observation(
        format_name: str,
        digest: str,
        symbol: str,
        detector_type: str,
        relative_path: str | None = None,
    ) -> BinaryObservation:
        return BinaryObservation(
            kind=EvidenceKind.BINARY_IMPORT
            if detector_type == "import"
            else EvidenceKind.BINARY_SYMBOL,
            location=EvidenceLocation(relative_path=relative_path, symbol=symbol),
            payload_digest=digest,
            attributes={"subject_kind": "algorithm", "subject_value": symbol},
            confidence=0.9,
            format=format_name,  # type: ignore[arg-type]
            detector_type=detector_type,  # type: ignore[arg-type]
            binary_digest=digest,
        )
