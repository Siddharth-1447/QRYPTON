"""Composition service for the Phase 2 local source scanner."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal

from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, Evidence, Provenance, ScanResult
from qrypton.ports.scanners import ScanRequest
from qrypton.scanners.source.normalization import SourceNormalizer
from qrypton.scanners.source.scanner import LocalSourceScanner


class SourceDiscoveryService:
    def __init__(
        self,
        scanner: LocalSourceScanner,
        normalizer: SourceNormalizer,
        id_deriver: IdDeriver,
    ) -> None:
        self._scanner = scanner
        self._normalizer = normalizer
        self._id_deriver = id_deriver

    async def scan(
        self, *, request: ScanRequest, asset: Asset
    ) -> tuple[tuple[Evidence, ...], ScanResult]:
        started_at = datetime.now(UTC)
        policy_payload = canonical_json_bytes(self._scanner.policy.model_dump(mode="json"))
        config_digest = f"sha256:{hashlib.sha256(policy_payload).hexdigest()}"
        provenance = Provenance(
            scanner_name=self._scanner.name,
            scanner_version=self._scanner.version,
            scanner_config_digest=config_digest,
            observed_at=started_at,
            source_digest=request.target.content_digest.value,
        )
        normalized: list[Evidence] = []
        async for raw in self._scanner.scan(request):
            normalized.append(
                self._normalizer.normalize(
                    raw,
                    asset=asset,
                    target=request.target,
                    provenance=provenance,
                    id_deriver=self._id_deriver,
                )
            )
        evidence_by_id = {item.id: item for item in normalized}
        evidence = tuple(sorted(evidence_by_id.values(), key=lambda item: item.id))
        findings = self._normalizer.derive_findings(
            evidence,
            asset=asset,
            target=request.target,
            provenance=provenance,
            id_deriver=self._id_deriver,
        )
        completed_at = datetime.now(UTC)
        status: Literal["completed", "partial", "failed"] = (
            "partial" if self._scanner.partial else "completed"
        )
        result_payload = {
            "target_id": request.target.id,
            "started_at": started_at,
            "evidence_ids": [item.id for item in evidence],
        }
        result = ScanResult(
            id=self._id_deriver.derive(
                namespace="scan_result",
                tenant_id=asset.tenant_id,
                canonical_payload=canonical_json_bytes(result_payload),
            ),
            tenant_id=asset.tenant_id,
            scan_target_id=request.target.id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            scanner_name=self._scanner.name,
            scanner_version=self._scanner.version,
            evidence_ids=tuple(item.id for item in evidence),
            finding_ids=tuple(item.id for item in findings),
            warnings=self._scanner.warnings,
        )
        return evidence, result
