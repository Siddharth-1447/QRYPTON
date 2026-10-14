"""Honest classification of inspected bytes vs identifier-only inference.

Canonical home for evidence-quality classification. This module lives in
``qrypton.contracts`` (pure domain logic over :class:`Evidence`) so that
read-only presentation layers — which must not import scanner
implementations — can label findings without duplicating the rule set.
``qrypton.scanners.evidence_quality`` re-exports these helpers for
backwards compatibility.
"""

from __future__ import annotations

from typing import Literal

from qrypton.contracts.enums import EvidenceCollectionMode, EvidenceKind
from qrypton.contracts.models import Evidence

EvidenceQuality = Literal["observed", "inferred"]

_INFERRED_RULES = frozenset({"static.kms-reference", "static.container-reference"})
_INFERRED_SCANNERS = frozenset({"qrypton-kms"})
_OBSERVED_KINDS = frozenset(
    {
        EvidenceKind.SOURCE_AST,
        EvidenceKind.SOURCE_LEXICAL,
        EvidenceKind.BINARY_SYMBOL,
        EvidenceKind.BINARY_STRING,
        EvidenceKind.BINARY_IMPORT,
        EvidenceKind.IMAGE_MANIFEST,
        EvidenceKind.IMAGE_LAYER,
        EvidenceKind.CERTIFICATE,
        EvidenceKind.CONFIGURATION,
    }
)

_KMS_LABEL = (
    "Inferred from identifier — no key material or registry contents were accessed"
)
_CONTAINER_REF_LABEL = (
    "Inferred from public image metadata — registry was not pulled"
)
_OBSERVED_LABEL = "Observed from inspected target bytes"


def classify_evidence(
    evidence: Evidence, *, scanner_name: str | None = None
) -> tuple[EvidenceQuality, str]:
    """Return (quality, human label) for one persisted evidence record."""
    rule = str(evidence.attributes.get("rule_id") or "")
    quality_attr = str(evidence.attributes.get("evidence_quality") or "")
    scanner = (scanner_name or evidence.provenance.scanner_name or "").casefold()
    if (
        evidence.collection_mode is EvidenceCollectionMode.STATIC_IDENTIFIER
        or quality_attr == "inferred"
        or rule in _INFERRED_RULES
        or scanner in _INFERRED_SCANNERS
    ):
        if "container" in rule or "container" in scanner:
            return "inferred", _CONTAINER_REF_LABEL
        return "inferred", _KMS_LABEL
    if (
        scanner == "qrypton-container"
        and evidence.kind is EvidenceKind.PACKAGE_METADATA
        and not evidence.location.relative_path
    ):
        return "inferred", _CONTAINER_REF_LABEL
    if evidence.kind in _OBSERVED_KINDS:
        return "observed", _OBSERVED_LABEL
    if evidence.kind is EvidenceKind.PACKAGE_METADATA:
        return "observed", "Observed from a supplied metadata / manifest document"
    return "observed", _OBSERVED_LABEL


def classify_finding_evidence(
    evidence: tuple[Evidence, ...], *, scanner_name: str | None = None
) -> tuple[EvidenceQuality, str, bool]:
    """Finding-level rollup: inferred if every record is inferred."""
    if not evidence:
        return "inferred", "No inspected bytes were persisted for this finding", False
    labels = [classify_evidence(item, scanner_name=scanner_name) for item in evidence]
    if all(quality == "inferred" for quality, _ in labels):
        return labels[0][0], labels[0][1], False
    observed = next(label for quality, label in labels if quality == "observed")
    return "observed", observed, True
