"""Token-aware degraded Python source detector for malformed modules."""

from __future__ import annotations

import io
import tokenize
from collections.abc import Iterator

from qrypton.contracts.enums import EvidenceKind
from qrypton.contracts.models import EvidenceLocation
from qrypton.ports.scanners import ScanLimits, SourceObservation
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.rules import (
    CRYPTO_LIBRARY_PREFIXES,
    algorithm_components,
    algorithm_for_name,
)
from qrypton.scanners.source.traversal import SourceFile


def _observation(
    source: SourceFile,
    token: tokenize.TokenInfo,
    *,
    rule_id: str,
    subject_kind: str,
    subject: str,
    confidence: float,
) -> SourceObservation:
    return SourceObservation(
        kind=EvidenceKind.SOURCE_LEXICAL,
        location=EvidenceLocation(
            relative_path=source.relative_path,
            line_start=token.start[0],
            line_end=token.end[0],
            byte_start=token.start[1],
            byte_end=token.end[1],
        ),
        payload_digest=source.digest,
        excerpt=None,
        attributes={
            "language": "python",
            "detector_type": "python_lexical",
            "rule_id": rule_id,
            "subject_kind": subject_kind,
            "subject_value": subject,
            "confidence_reason": "token-aware fallback after AST parse failure",
        },
        confidence=min(confidence, 0.35) if source.encoding_degraded else confidence,
        language="python",
        detector_type="python_lexical",
        rule_id=rule_id,
        source_file_digest=source.digest,
    )


def analyze_python_lexical(
    source: SourceFile, *, policy: SourceScanPolicy, limits: ScanLimits
) -> Iterator[SourceObservation]:
    """Emit only token-level, low-confidence signals; comments are ignored by tokenize."""
    del policy, limits
    tokens = list(tokenize.generate_tokens(io.StringIO(source.text).readline))
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME:
            continue
        lowered = token.string.casefold()
        if lowered in CRYPTO_LIBRARY_PREFIXES:
            yield _observation(
                source,
                token,
                rule_id="python.lexical.library",
                subject_kind="library",
                subject=lowered,
                confidence=0.60,
            )
        rule = algorithm_for_name(lowered)
        next_token = tokens[index + 1] if index + 1 < len(tokens) else None
        if rule and next_token is not None and next_token.string == "(":
            components = algorithm_components(lowered)
            yield _observation(
                source,
                token,
                rule_id=f"python.lexical.algorithm.{lowered}",
                subject_kind="algorithm",
                subject=(
                    lowered if len(components) > 1
                    or (components and components[0].key_size_bits is not None)
                    else rule.canonical_name
                ),
                confidence=0.60,
            )
