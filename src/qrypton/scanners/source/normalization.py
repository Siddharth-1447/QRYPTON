"""Deterministic source-observation normalization into Phase 1 contracts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Literal, TypeVar

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmIdentificationStatus,
    AlgorithmStatus,
    EvidenceCollectionMode,
    EvidenceSurface,
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
from qrypton.contracts.primitives import JsonScalar
from qrypton.ports.scanners import RawObservation
from qrypton.scanners.source.rules import MODE_NAMES, algorithm_for_name

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

    @staticmethod
    def _collection_semantics(
        raw: RawObservation, provenance: Provenance
    ) -> tuple[EvidenceSurface, EvidenceCollectionMode, tuple[str, ...]]:
        """Classify the acquisition path without inferring unperformed access."""
        scanner = provenance.scanner_name.casefold()
        rule_id = str(raw.attributes.get("rule_id") or "")
        if scanner == "qrypton-kms" or rule_id == "static.kms-reference":
            return (
                EvidenceSurface.KMS,
                EvidenceCollectionMode.STATIC_IDENTIFIER,
                (
                    "Static KMS identifier or supplied descriptor only; "
                    "no authenticated cloud-provider API call was made.",
                ),
            )
        if scanner == "qrypton-container":
            if rule_id == "static.container-reference":
                return (
                    EvidenceSurface.CONTAINER,
                    EvidenceCollectionMode.STATIC_IDENTIFIER,
                    (
                        "Static container reference only; registry was not pulled "
                        "and no container was started.",
                    ),
                )
            return EvidenceSurface.CONTAINER, EvidenceCollectionMode.STATIC_ARTIFACT, ()
        if scanner == "qrypton-library":
            return EvidenceSurface.LIBRARY, EvidenceCollectionMode.STATIC_ARTIFACT, ()
        if scanner == "qrypton-binary":
            return EvidenceSurface.BINARY, EvidenceCollectionMode.STATIC_ARTIFACT, ()
        if scanner == "qrypton-source":
            return EvidenceSurface.SOURCE, EvidenceCollectionMode.STATIC_ARTIFACT, ()
        return EvidenceSurface.UNKNOWN, EvidenceCollectionMode.UNKNOWN, ()

    @staticmethod
    def _canonical_attributes(raw: RawObservation) -> dict[str, JsonScalar]:
        """Retain bounded scanner semantics needed for correlation and audit."""
        attributes: dict[str, JsonScalar] = dict(raw.attributes)
        for field_name in (
            "language",
            "detector_type",
            "rule_id",
            "source_file_digest",
            "format",
            "binary_digest",
        ):
            value = getattr(raw, field_name, None)
            if value is not None:
                attributes.setdefault(field_name, value.value if hasattr(value, "value") else value)
        return attributes

    def normalize(
        self,
        raw: RawObservation,
        *,
        asset: Asset,
        target: ScanTarget,
        provenance: Provenance,
        id_deriver: IdDeriver,
    ) -> Evidence:
        attributes = self._canonical_attributes(raw)
        surface, collection_mode, limitations = self._collection_semantics(raw, provenance)
        payload = {
            "asset_id": asset.id,
            "target_id": target.id,
            "kind": raw.kind.value,
            "surface": surface.value,
            "collection_mode": collection_mode.value,
            "location": raw.location.model_dump(mode="json", exclude_none=True),
            "attributes": attributes,
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
            attributes=attributes,
            confidence=raw.confidence,
            deduplication_fingerprint=fingerprint,
            provenance=evidence_provenance,
            surface=surface,
            collection_mode=collection_mode,
            limitations=limitations,
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
        algorithm_family: AlgorithmFamily | None = None
        algorithm_variant: str | None = None
        algorithm_identification_status = AlgorithmIdentificationStatus.UNKNOWN
        algorithm_identification_confidence = 0.0
        algorithm_identification_evidence: tuple[str, ...] = ()
        key_material: Observation[KeyMaterialMetadata] = _unknown()
        certificate: Observation[CertificateMetadata] = _unknown()
        protocol: Observation[ProtocolMetadata] = _unknown()
        library: Observation[LibraryMetadata] = _unknown()
        category: Literal["algorithm_use", "key_material", "certificate", "protocol", "library"]
        category = "algorithm_use"
        if subject_kind in {"algorithm", "mode"}:
            # A mode only identifies its cipher when the same observation
            # supplies an explicit binding (or a composite name such as AES-CBC).
            bound_name = attributes.get("algorithm_name")
            rule = algorithm_for_name(
                bound_name
                if subject_kind == "mode" and isinstance(bound_name, str)
                else subject_value
            )
            parameters: dict[str, JsonScalar] = {}
            mode = attributes.get("mode")
            if not isinstance(mode, str):
                tokens = re.split(r"[-_.]", subject_value.casefold())
                mode = next((token for token in reversed(tokens) if token in MODE_NAMES), None)
            if isinstance(mode, str) and mode.casefold() in MODE_NAMES:
                parameters["mode"] = mode.upper()
            raw_size = attributes.get("key_size_bits")
            key_size: Observation[int] = _unknown()
            # bool is an int subclass; invalid/unresolved metadata must not
            # manufacture an observed size or crash the normalization stage.
            if type(raw_size) is int and 1 <= raw_size <= 1_000_000:
                key_size = _observed(raw_size, evidence.id)
            algorithm_variant = subject_value
            if rule is not None:
                algorithm_value = Algorithm(
                    canonical_name=rule.canonical_name,
                    family=AlgorithmFamily(rule.family),
                    parameters=parameters,
                    key_size_bits=key_size,
                    security_strength_bits=_unknown(),
                    lifecycle_status=AlgorithmStatus(rule.lifecycle),
                )
                algorithm = _observed(algorithm_value, evidence.id)
                algorithm_family = algorithm_value.family
                algorithm_variant = algorithm_value.canonical_name
                algorithm_identification_status = AlgorithmIdentificationStatus.IDENTIFIED
                algorithm_identification_confidence = evidence.confidence
                algorithm_identification_evidence = (evidence.id,)
            else:
                if parameters:
                    algorithm = _observed(
                        Algorithm(
                            canonical_name="unknown",
                            family=AlgorithmFamily.UNKNOWN,
                            parameters=parameters,
                            key_size_bits=key_size,
                            security_strength_bits=_unknown(),
                            lifecycle_status=AlgorithmStatus.UNKNOWN,
                        ),
                        evidence.id,
                    )
                # Retain the observed token as a candidate variant without
                # claiming it is a canonical Algorithm or assigning a family.
                algorithm_identification_status = AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED
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
            algorithm_identification_status = AlgorithmIdentificationStatus.PARTIALLY_IDENTIFIED
            lib_name = (
                subject_value.strip()
                if subject_value and subject_value.strip()
                else (
                    evidence.location.symbol.strip()
                    if evidence.location
                    and evidence.location.symbol
                    and evidence.location.symbol.strip()
                    else "unknown_library"
                )
            )
            library_value = LibraryMetadata(
                ecosystem=_observed("source", evidence.id),
                name=_observed(lib_name, evidence.id),
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
        detector = str(attributes.get("detector_type") or attributes.get("language") or "scanner")
        rule_id = str(attributes.get("rule_id") or "unspecified-rule")
        scanner_reason = str(attributes.get("confidence_reason") or "")
        reason = (
            f"Evidence {evidence.id} has confidence {evidence.confidence:g} from "
            f"{detector} ({rule_id})"
        )
        if scanner_reason:
            reason += f": {scanner_reason}"

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
            algorithm_family=algorithm_family,
            algorithm_variant=algorithm_variant,
            crypto_role=(
                str(attributes["crypto_role"])
                if isinstance(attributes.get("crypto_role"), str)
                else None
            ),
            algorithm_identification_status=algorithm_identification_status,
            algorithm_identification_confidence=algorithm_identification_confidence,
            algorithm_identification_evidence=algorithm_identification_evidence,
            confidence_reasons=(reason,),
            identification_confidence=algorithm_identification_confidence,
            usage_confidence=evidence.confidence,
            evidence_ids=(evidence.id,),
            confidence=evidence.confidence,
            first_observed_at=provenance.observed_at,
            last_observed_at=provenance.observed_at,
            provenance=provenance,
        )
