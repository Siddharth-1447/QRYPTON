"""Read-only executable scanner with strict file and evidence limits."""

from __future__ import annotations

import hashlib
import time
from collections.abc import AsyncIterator
from pathlib import Path

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import BinaryObservation, ScanRequest
from qrypton.scanners.binary.entropy import shannon_entropy
from qrypton.scanners.binary.formats import BinarySection, parse_binary

_CRYPTO_TOKENS = (
    "aes",
    "argon",
    "blowfish",
    "camellia",
    "chacha",
    "des",
    "dh",
    "dsa",
    "ec_",
    "ed25519",
    "evp_",
    "hkdf",
    "hmac",
    "md5",
    "pbkdf",
    "rc2",
    "rc4",
    "rsa",
    "sha",
    "scrypt",
    "tls",
    "x25519",
    "x509",
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
        path = self._resolve(request)
        warnings: list[str] = []
        self.partial = False
        if path.is_symlink():
            self.warnings = ("skipped symlink target",)
            self.partial = True
            return
        try:
            size = path.stat().st_size
        except OSError:
            self.warnings = ("unreadable binary metadata",)
            self.partial = True
            return
        if size > request.limits.max_file_bytes:
            self.warnings = ("skipped oversized binary",)
            self.partial = True
            return
        deadline = time.monotonic() + request.limits.max_wall_time_seconds
        digest = self._digest(path)
        try:
            parsed = parse_binary(path)
        except (OSError, ValueError) as error:
            self.warnings = (f"binary parsing skipped: {error}",)
            self.partial = True
            return
        emitted = 0
        for kind, values in (("import", parsed.imports), ("export", parsed.exports)):
            for symbol in values:
                if not self._is_crypto_symbol(symbol):
                    continue
                if emitted >= request.limits.max_evidence_count:
                    warnings.append("binary evidence limit reached")
                    self.partial = True
                    self.warnings = tuple(warnings)
                    return
                emitted += 1
                yield self._symbol_observation(parsed.format, digest, symbol, kind)
        for library in parsed.libraries:
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
        with path.open("rb") as stream:
            for section in parsed.sections:
                if time.monotonic() > deadline:
                    warnings.append("binary scan wall-time limit reached")
                    self.partial = True
                    break
                if not self._valid_section(section, size):
                    continue
                entropy = shannon_entropy(stream, offset=section.offset, size=section.size)
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
    def _digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _is_crypto_symbol(symbol: str) -> bool:
        normalized = symbol.casefold().lstrip("_")
        return any(token in normalized for token in _CRYPTO_TOKENS)

    @staticmethod
    def _valid_section(section: BinarySection, size: int) -> bool:
        return section.offset >= 0 and section.size >= 0 and section.offset <= size - section.size

    @staticmethod
    def _symbol_observation(
        format_name: str, digest: str, symbol: str, detector_type: str
    ) -> BinaryObservation:
        return BinaryObservation(
            kind=EvidenceKind.BINARY_IMPORT
            if detector_type == "import"
            else EvidenceKind.BINARY_SYMBOL,
            location=EvidenceLocation(symbol=symbol),
            payload_digest=digest,
            attributes={"subject_kind": "algorithm", "subject_value": symbol},
            confidence=0.9,
            format=format_name,  # type: ignore[arg-type]
            detector_type=detector_type,  # type: ignore[arg-type]
            binary_digest=digest,
        )
