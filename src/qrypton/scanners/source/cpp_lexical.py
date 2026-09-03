"""Bounded C/C++ lexical crypto detection without semantic-parser claims."""

from __future__ import annotations

import re
from collections.abc import Iterator

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import ScanLimits, SourceObservation
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.rules import algorithm_for_name
from qrypton.scanners.source.traversal import SourceFile

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", re.MULTILINE)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_STRING_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
_HEADER_PREFIXES = ("openssl/", "mbedtls/", "wolfssl/", "sodium", "bcrypt", "CommonCrypto")
_API_ALGORITHMS = {
    "EVP_aes": "aes",
    "AES_": "aes",
    "EVP_sha": "sha256",
    "SHA": "sha256",
    "MD5": "md5",
    "RSA_": "rsa",
    "EVP_PKEY_RSA": "rsa",
    "EVP_PKEY_EC": "ec",
    "crypto_box": "x25519",
    "crypto_sign": "ed25519",
    "BCrypt": "aes",
    "CCCrypt": "aes",
    "mbedtls_aes": "aes",
    "mbedtls_sha": "sha256",
    "wolfSSL": "tls",
}


def _stripped_comments(text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return _COMMENT_RE.sub(blank, text)


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    previous = text.rfind("\n", 0, offset)
    return line, offset - (previous + 1)


def _observation(
    source: SourceFile,
    *,
    offset: int,
    rule_id: str,
    subject_kind: str,
    subject: str,
    confidence: float,
    reason: str,
) -> SourceObservation:
    line, column = _line_col(source.text, offset)
    return SourceObservation(
        kind=EvidenceKind.SOURCE_LEXICAL,
        location=EvidenceLocation(
            relative_path=source.relative_path,
            line_start=line,
            line_end=line,
            byte_start=column,
            byte_end=column + len(subject),
        ),
        payload_digest=source.digest,
        excerpt=None,
        attributes={
            "language": source.language,
            "detector_type": "cpp_lexical",
            "rule_id": rule_id,
            "subject_kind": subject_kind,
            "subject_value": subject,
            "confidence_reason": reason,
        },
        confidence=min(confidence, 0.35) if source.encoding_degraded else confidence,
        language="c" if source.language == "c" else "cpp",
        detector_type="cpp_lexical",
        rule_id=rule_id,
        source_file_digest=source.digest,
    )


def _algorithm_for_api(name: str) -> str | None:
    for prefix, algorithm in _API_ALGORITHMS.items():
        if name.startswith(prefix):
            return algorithm
    return None


def analyze_cpp_lexical(
    source: SourceFile, *, policy: SourceScanPolicy, limits: ScanLimits
) -> Iterator[SourceObservation]:
    """Yield header/API corroborated source evidence; macros and types are not resolved."""
    del policy, limits
    text = _stripped_comments(source.text)
    headers = {match.group(1) for match in _INCLUDE_RE.finditer(text)}
    has_crypto_header = any(header.startswith(_HEADER_PREFIXES) for header in headers)
    for match in _CALL_RE.finditer(text):
        api = match.group(1)
        algorithm_name = _algorithm_for_api(api)
        if algorithm_name is None:
            continue
        algorithm = algorithm_for_name(algorithm_name)
        subject = algorithm.canonical_name if algorithm else algorithm_name
        yield _observation(
            source,
            offset=match.start(1),
            rule_id="cpp.api.crypto",
            subject_kind="algorithm",
            subject=subject,
            confidence=0.55 if has_crypto_header else 0.35,
            reason=(
                "recognized C/C++ API with crypto header"
                if has_crypto_header
                else "isolated API token"
            ),
        )
    for match in _STRING_RE.finditer(text):
        candidate = match.group(1)
        if "TLS_" not in candidate and "ECDHE" not in candidate:
            continue
        yield _observation(
            source,
            offset=match.start(1),
            rule_id="cpp.protocol.cipher_suite",
            subject_kind="cipher_suite",
            subject=candidate[:512],
            confidence=0.35,
            reason="standalone cipher-suite string literal",
        )
