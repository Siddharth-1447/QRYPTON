"""Interfaces that turn raw observations into canonical evidence and findings."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from qrypton.contracts.models import Asset, CryptoFinding, Evidence, Provenance, ScanTarget
from qrypton.contracts.primitives import ScannerVersion
from qrypton.ports.scanners import RawObservation


class EvidenceNormalizer(Protocol):
    name: str
    version: ScannerVersion

    def normalize(
        self, raw: RawObservation, *, target: ScanTarget, provenance: Provenance
    ) -> Evidence:
        """Convert one raw observation to canonical, deduplicable evidence."""


class FindingNormalizer(Protocol):
    name: str
    version: ScannerVersion

    def derive_findings(
        self, evidence: Sequence[Evidence], *, asset: Asset
    ) -> Sequence[CryptoFinding]:
        """Derive findings without mutating or discarding conflicting evidence."""
