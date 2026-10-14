"""Backwards-compatible re-export of the canonical evidence-quality classifier.

The canonical implementation lives in :mod:`qrypton.contracts.evidence_quality`
so read-only presentation layers (which must not import scanner
implementations) can label findings without duplicating the rule set.
"""

from __future__ import annotations

from qrypton.contracts.evidence_quality import (
    EvidenceQuality,
    classify_evidence,
    classify_finding_evidence,
)

__all__ = ["EvidenceQuality", "classify_evidence", "classify_finding_evidence"]
