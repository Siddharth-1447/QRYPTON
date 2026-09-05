"""Safe deterministic correlation of independently produced finding candidates."""

from __future__ import annotations

from collections.abc import Sequence

from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, CryptoFinding, Evidence, Provenance, ScanTarget


class DeterministicCorrelationEngine:
    name = "qrypton-correlation"
    version = "1.0.0"

    def correlate(
        self,
        candidates: Sequence[CryptoFinding],
        *,
        evidence: Sequence[Evidence],
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Sequence[CryptoFinding]:
        evidence_by_id = {item.id: item for item in evidence}
        groups: dict[bytes, list[CryptoFinding]] = {}
        for candidate in candidates:
            payload = self._subject_payload(candidate, evidence_by_id)
            groups.setdefault(canonical_json_bytes(payload), []).append(candidate)
        correlated: list[CryptoFinding] = []
        for key in sorted(groups):
            group = groups[key]
            evidence_ids = tuple(
                sorted({item for candidate in group for item in candidate.evidence_ids})
            )
            fingerprints = tuple(
                sorted(
                    evidence_by_id[item].deduplication_fingerprint
                    for item in evidence_ids
                    if item in evidence_by_id
                )
            )
            exemplar = sorted(group, key=lambda item: item.id)[0]
            finding_id = id_deriver.derive(
                namespace="finding",
                tenant_id=asset.tenant_id,
                canonical_payload=canonical_json_bytes(
                    {
                        "schema": 1,
                        "asset_id": asset.id,
                        "target_id": target.id,
                        "subject": self._subject_payload(exemplar, {}),
                        "evidence_fingerprints": fingerprints,
                        "correlator": {"name": self.name, "version": self.version},
                    }
                ),
            )
            correlated.append(
                exemplar.model_copy(
                    update={
                        "id": finding_id,
                        "evidence_ids": evidence_ids,
                        "confidence": max(item.confidence for item in group),
                        "provenance": provenance,
                    }
                )
            )
        return tuple(sorted(correlated, key=lambda item: item.id))

    @staticmethod
    def _subject_payload(
        finding: CryptoFinding, evidence_by_id: dict[str, Evidence]
    ) -> dict[str, object]:
        del evidence_by_id
        subject: dict[str, object] = {
            "category": finding.category,
            "algorithm": finding.algorithm.model_dump(mode="json", exclude={"basis_evidence_ids"}),
            "key_material": finding.key_material.model_dump(
                mode="json", exclude={"basis_evidence_ids"}
            ),
            "certificate": finding.certificate.model_dump(
                mode="json", exclude={"basis_evidence_ids"}
            ),
            "protocol": finding.protocol.model_dump(mode="json", exclude={"basis_evidence_ids"}),
            "library": finding.library.model_dump(mode="json", exclude={"basis_evidence_ids"}),
        }
        return subject
