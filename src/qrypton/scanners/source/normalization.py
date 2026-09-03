"""Deterministic source-observation normalization into Phase 1 contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Literal, TypeVar

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    ObservationState,
    ProtocolLayer,
)
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    Algorithm,
    Asset,
    CertificateMetadata,
    CryptoFinding,
    Evidence,
    KeyMaterialMetadata,
    LibraryMetadata,
    Observation,
    ProtocolMetadata,
    Provenance,
    ScanTarget,
)
from qrypton.ports.scanners import RawObservation
from qrypton.scanners.source.rules import algorithm_for_name

T = TypeVar("T")


def _unknown() -> Observation[T]:
    return Observation[T](state=ObservationState.UNKNOWN)


def _observed(value: T, evidence_id: str) -> Observation[T]:
    return Observation[T](
        state=ObservationState.OBSERVED,
        value=value,
        basis_evidence_ids=(evidence_id,),
    )


class SourceNormalizer:
    name = "qrypton-source-normalizer"
    version = "0.2.0"

    def normalize(
        self,
        raw: RawObservation,
        *,
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Evidence:
        payload = {
            "asset_id": asset.id,
            "target_id": target.id,
            "kind": raw.kind.value,
            "location": raw.location.model_dump(mode="json", exclude_none=True),
            "attributes": dict(raw.attributes),
            "payload_digest": raw.payload_digest,
        }
        canonical = canonical_json_bytes(payload)
        fingerprint = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        evidence_id = id_deriver.derive(
            namespace="evidence", tenant_id=asset.tenant_id, canonical_payload=canonical
        )
        source_digest = getattr(raw, "source_file_digest", raw.payload_digest)
        evidence_provenance = provenance.model_copy(update={"source_digest": source_digest})
        return Evidence(
            id=evidence_id,
            tenant_id=asset.tenant_id,
            asset_id=asset.id,
            scan_target_id=target.id,
            kind=raw.kind,
            location=raw.location,
            raw_content_digest=raw.payload_digest,
            excerpt=raw.excerpt,
            attributes=raw.attributes,
            confidence=raw.confidence,
            deduplication_fingerprint=fingerprint,
            provenance=evidence_provenance,
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
        unique = {item.id: item for item in evidence}
        findings = [
            self._finding(
                item,
                asset=asset,
                target=target,
                provenance=provenance,
                id_deriver=id_deriver,
            )
            for item in unique.values()
        ]
        return tuple(sorted(findings, key=lambda item: item.id))

    def _finding(
        self,
        evidence: Evidence,
        *,
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> CryptoFinding:
        attributes = dict(evidence.attributes)
        subject_kind = str(attributes.get("subject_kind", "unknown"))
        subject_value = str(attributes.get("subject_value", "unknown"))
        algorithm: Observation[Algorithm] = _unknown()
        key_material: Observation[KeyMaterialMetadata] = _unknown()
        certificate: Observation[CertificateMetadata] = _unknown()
        protocol: Observation[ProtocolMetadata] = _unknown()
        library: Observation[LibraryMetadata] = _unknown()
        category: Literal["algorithm_use", "key_material", "certificate", "protocol", "library"]
        category = "algorithm_use"
        if subject_kind in {"algorithm", "mode"}:
            rule = algorithm_for_name(subject_value) if subject_kind == "algorithm" else None
            algorithm_value = Algorithm(
                canonical_name=rule.canonical_name if rule else subject_value.casefold(),
                family=AlgorithmFamily(rule.family) if rule else AlgorithmFamily.UNKNOWN,
                parameters={"mode": subject_value} if subject_kind == "mode" else {},
                key_size_bits=_unknown(),
                security_strength_bits=_unknown(),
                lifecycle_status=(
                    AlgorithmStatus(rule.lifecycle) if rule else AlgorithmStatus.UNKNOWN
                ),
            )
            algorithm = _observed(algorithm_value, evidence.id)
        elif subject_kind in {"protocol", "cipher_suite"}:
            category = "protocol"
            protocol_value = ProtocolMetadata(
                name=(
                    _observed(subject_value, evidence.id)
                    if subject_kind == "protocol"
                    else _unknown()
                ),
                version=_unknown(),
                layer=ProtocolLayer.TRANSPORT,
                cipher_suite=(
                    _observed(subject_value, evidence.id)
                    if subject_kind == "cipher_suite"
                    else _unknown()
                ),
                peer_authentication=_unknown(),
            )
            protocol = _observed(protocol_value, evidence.id)
        elif subject_kind == "library":
            category = "library"
            library_value = LibraryMetadata(
                ecosystem=_observed("source", evidence.id),
                name=_observed(subject_value, evidence.id),
                version=_unknown(),
                package_url=_unknown(),
                known_maintenance_state=_unknown(),
            )
            library = _observed(library_value, evidence.id)
        payload = {
            "asset_id": asset.id,
            "target_id": target.id,
            "category": category,
            "evidence_ids": [evidence.id],
            "subject_kind": subject_kind,
            "subject_value": subject_value,
        }
        finding_id = id_deriver.derive(
            namespace="finding",
            tenant_id=asset.tenant_id,
            canonical_payload=canonical_json_bytes(payload),
        )
        return CryptoFinding(
            id=finding_id,
            tenant_id=asset.tenant_id,
            asset_id=asset.id,
            scan_target_id=target.id,
            category=category,
            algorithm=algorithm,
            key_material=key_material,
            certificate=certificate,
            protocol=protocol,
            library=library,
            evidence_ids=(evidence.id,),
            confidence=evidence.confidence,
            first_observed_at=provenance.observed_at,
            last_observed_at=provenance.observed_at,
            provenance=provenance,
        )
