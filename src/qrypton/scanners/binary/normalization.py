"""Canonical normalization for binary scanner observations."""

from __future__ import annotations

from collections.abc import Sequence

from qrypton.contracts.ids import IdDeriver
from qrypton.contracts.models import Asset, CryptoFinding, Evidence, Provenance, ScanTarget
from qrypton.ports.scanners import RawObservation
from qrypton.scanners.source.normalization import SourceNormalizer


class BinaryNormalizer(SourceNormalizer):
    """Binary observations use the same stable Evidence/Finding identity contract."""

    name = "qrypton-binary-normalizer"
    version = "0.3.0"

    def normalize(
        self,
        raw: RawObservation,
        *,
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Evidence:
        return super().normalize(
            raw, asset=asset, target=target, provenance=provenance, id_deriver=id_deriver
        )

    def derive_findings(
        self,
        evidence: Sequence[Evidence],
        *,
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Sequence[CryptoFinding]:
        return super().derive_findings(
            evidence, asset=asset, target=target, provenance=provenance, id_deriver=id_deriver
        )
