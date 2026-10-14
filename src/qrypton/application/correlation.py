"""Deterministic, context-preserving correlation of finding candidates."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, CryptoFinding, Evidence, Provenance, ScanTarget


class DeterministicCorrelationEngine:
    """Merge only candidates that identify the same cryptographic usage.

    Evidence IDs are deduplicated by normalizers first. This stage can merge
    complementary observations at one usage location without turning a shared
    algorithm or library name into a repository-wide finding.
    """

    name = "qrypton-correlation"
    version = "2.0.0"

    _CONTEXT_ATTRIBUTES = (
        "subject_kind",
        "subject_value",
        "crypto_role",
        "module",
        "service",
        "package_name",
        "package_version",
        "image_layer_digest",
        "format",
    )

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
            self._validate_scope(candidate, asset, target)
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
                        "schema": 2,
                        "subject": self._subject_payload(exemplar, evidence_by_id),
                        "evidence_fingerprints": fingerprints,
                        "correlator": {"name": self.name, "version": self.version},
                    }
                ),
            )
            reasons = exemplar.confidence_reasons
            if len(evidence_ids) > len(exemplar.evidence_ids):
                reasons = tuple(
                    dict.fromkeys(
                        (
                            *reasons,
                            (
                                "Additional equivalent evidence retained "
                                f"({len(evidence_ids)} records); it did not change confidence."
                            ),
                        )
                    )
                )
            correlated.append(
                exemplar.model_copy(
                    update={
                        "id": finding_id,
                        "evidence_ids": evidence_ids,
                        "confidence_reasons": reasons,
                        "correlation_provenance": provenance,
                        "first_observed_at": min(item.first_observed_at for item in group),
                        "last_observed_at": max(item.last_observed_at for item in group),
                    }
                )
            )
        return tuple(sorted(correlated, key=lambda item: item.id))

    @staticmethod
    def _validate_scope(candidate: CryptoFinding, asset: Asset, target: ScanTarget) -> None:
        if (
            candidate.tenant_id != asset.tenant_id
            or candidate.asset_id != asset.id
            or candidate.scan_target_id != target.id
        ):
            raise ValueError("candidate lies outside the correlation asset and target scope")

    @classmethod
    def _subject_payload(
        cls, finding: CryptoFinding, evidence_by_id: dict[str, Evidence]
    ) -> dict[str, Any]:
        """Identity and usage context required before candidates can merge."""
        return {
            "asset_id": finding.asset_id,
            "target_id": finding.scan_target_id,
            "category": finding.category,
            "algorithm_family": finding.algorithm_family.value
            if finding.algorithm_family is not None
            else None,
            "algorithm_variant": finding.algorithm_variant,
            "crypto_role": finding.crypto_role,
            "algorithm_identification_status": finding.algorithm_identification_status.value,
            "algorithm": finding.algorithm.model_dump(mode="json", exclude={"basis_evidence_ids"}),
            "key_material": finding.key_material.model_dump(
                mode="json", exclude={"basis_evidence_ids"}
            ),
            "certificate": finding.certificate.model_dump(
                mode="json", exclude={"basis_evidence_ids"}
            ),
            "protocol": finding.protocol.model_dump(mode="json", exclude={"basis_evidence_ids"}),
            "library": finding.library.model_dump(mode="json", exclude={"basis_evidence_ids"}),
            "usage_context": cls._usage_context(finding, evidence_by_id),
        }

    @classmethod
    def _usage_context(
        cls, finding: CryptoFinding, evidence_by_id: dict[str, Evidence]
    ) -> tuple[dict[str, Any], ...]:
        """Return surface-neutral anchors for each evidence item.

        An unresolved evidence ID is deliberately an anchor of its own. It is
        safer to retain two unlocatable candidate usages than to merge them
        because their library or algorithm labels match.
        """
        contexts: list[dict[str, Any]] = []
        for evidence_id in sorted(finding.evidence_ids):
            item = evidence_by_id.get(evidence_id)
            if item is None:
                contexts.append({"unresolved_evidence_id": evidence_id})
                continue
            attributes = {
                name: item.attributes[name]
                for name in cls._CONTEXT_ATTRIBUTES
                if name in item.attributes
            }
            contexts.append(
                {
                    "location": item.location.model_dump(mode="json", exclude_none=True),
                    "context_attributes": attributes,
                }
            )
        return tuple(sorted(contexts, key=canonical_json_bytes))
