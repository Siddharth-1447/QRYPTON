"""Deterministic finding correlation interface."""

from collections.abc import Sequence
from typing import Protocol

from qrypton.contracts.ids import IdDeriver
from qrypton.contracts.models import Asset, CryptoFinding, Evidence, Provenance, ScanTarget
from qrypton.contracts.primitives import ScannerVersion


class CorrelationEngine(Protocol):
    name: str
    version: ScannerVersion

    def correlate(
        self,
        candidates: Sequence[CryptoFinding],
        *,
        evidence: Sequence[Evidence],
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Sequence[CryptoFinding]: ...
