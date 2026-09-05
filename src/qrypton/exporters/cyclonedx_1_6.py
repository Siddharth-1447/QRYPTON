"""Offline deterministic CycloneDX 1.6 CBOM exporter."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from jsonschema import Draft7Validator, FormatChecker  # type: ignore[import-untyped]
from pydantic import Field

from qrypton.contracts.enums import AlgorithmFamily, AssetKind, KeyKind, ObservationState
from qrypton.contracts.errors import CBOMExportError, CBOMValidationError
from qrypton.contracts.models import (
    Algorithm,
    Asset,
    CryptoFinding,
    DomainModel,
    Evidence,
    Recommendation,
    RiskAssessment,
)
from qrypton.contracts.primitives import ScannerVersion, UtcDateTime
from qrypton.recommendations.schemas import PqcRecommendationPlan

JsonObject = dict[str, Any]
_SCHEMA_FILE = Path(__file__).parent / "schemas" / "cyclonedx" / "bom-1.6.schema.json"
_SCHEMA_MANIFEST = _SCHEMA_FILE.with_name("MANIFEST.json")
_ROOT_TYPES: Mapping[AssetKind, str] = {
    AssetKind.APPLICATION: "application",
    AssetKind.LIBRARY: "library",
    AssetKind.CONTAINER_IMAGE: "container",
    AssetKind.BINARY: "file",
}
_PRIMITIVES: Mapping[AlgorithmFamily, str] = {
    AlgorithmFamily.SYMMETRIC_CIPHER: "block-cipher",
    AlgorithmFamily.ASYMMETRIC_ENCRYPTION: "pke",
    AlgorithmFamily.SIGNATURE: "signature",
    AlgorithmFamily.HASH: "hash",
    AlgorithmFamily.MAC: "mac",
    AlgorithmFamily.KDF: "kdf",
    AlgorithmFamily.KEY_AGREEMENT: "key-agree",
    AlgorithmFamily.RNG: "drbg",
    AlgorithmFamily.PROTOCOL: "other",
}


class CbomExportContext(DomainModel):
    serial_number: UUID
    bom_version: Annotated[int, Field(ge=1)] = 1
    generated_at: UtcDateTime
    lifecycle: Literal["discovery", "post-build", "operations"] = "discovery"


class CycloneDx16CbomExporter:
    """Build and validate CycloneDX 1.6 JSON without network access or clock reads."""

    name = "qrypton-cyclonedx-1.6"
    version: ScannerVersion = "0.7.0"

    def __init__(self) -> None:
        try:
            schema = json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))
            manifest = json.loads(_SCHEMA_MANIFEST.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CBOMExportError("bundled CycloneDX 1.6 schema is unavailable") from error
        if hashlib.sha256(_SCHEMA_FILE.read_bytes()).hexdigest() != manifest.get("sha256"):
            raise CBOMExportError("bundled CycloneDX 1.6 schema checksum does not match manifest")
        self._validator = Draft7Validator(schema, format_checker=FormatChecker())

    def export(
        self,
        *,
        asset: Asset,
        findings: Sequence[CryptoFinding],
        assessments: Sequence[RiskAssessment],
        recommendations: Sequence[Recommendation],
        recommendation_plans: Sequence[PqcRecommendationPlan],
        evidence: Sequence[Evidence],
        context: CbomExportContext,
    ) -> bytes:
        root_type = _ROOT_TYPES.get(asset.kind)
        if root_type is None:
            raise CBOMExportError(
                f"asset kind {asset.kind.value} has no safe CycloneDX component mapping"
            )
        evidence_by_id = self._deduplicate_evidence(evidence)
        assessment_by_finding = self._index_unique(assessments, "finding_id")
        recommendation_by_finding = self._group_recommendations(recommendations)
        plan_by_finding = self._index_unique(recommendation_plans, "finding_id")
        root_ref = f"qrypton:asset:{asset.id}"
        components = [self._root_component(asset, root_ref, root_type)]
        dependencies: list[JsonObject] = []
        for finding in sorted(findings, key=lambda item: item.id):
            component = self._finding_component(
                finding,
                assessment_by_finding.get(finding.id),
                recommendation_by_finding.get(finding.id, ()),
                plan_by_finding.get(finding.id),
                evidence_by_id,
            )
            components.append(component)
            dependencies.append({"ref": root_ref, "dependsOn": [component["bom-ref"]]})
        document: JsonObject = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{context.serial_number}",
            "version": context.bom_version,
            "metadata": {
                "timestamp": context.generated_at.isoformat().replace("+00:00", "Z"),
                "lifecycles": [{"phase": context.lifecycle}],
                "component": components[0],
                "tools": {
                    "components": [
                        {"type": "application", "name": "qrypton", "version": self.version}
                    ]
                },
            },
            "components": components[1:],
            "dependencies": sorted(dependencies, key=lambda item: str(item["ref"])),
        }
        payload = self._serialize(document)
        self.validate(payload)
        return payload

    def validate(self, document: bytes) -> None:
        try:
            decoded = json.loads(document)
        except json.JSONDecodeError as error:
            raise CBOMValidationError("document is not valid JSON") from error
        errors = sorted(
            self._validator.iter_errors(decoded), key=lambda item: list(item.absolute_path)
        )
        if errors:
            validation_error = errors[0]
            path = "/".join(str(item) for item in validation_error.absolute_path) or "$"
            raise CBOMValidationError(
                f"CycloneDX 1.6 validation failed at {path}: {validation_error.message}"
            )

    def _root_component(self, asset: Asset, bom_ref: str, component_type: str) -> JsonObject:
        properties = [
            self._property("org.qrypton.asset.id", asset.id),
            self._property("org.qrypton.asset.kind", asset.kind.value),
            self._property("org.qrypton.provenance", self._provenance(asset.provenance)),
        ]
        if asset.external_reference:
            properties.append(
                self._property("org.qrypton.asset.external-reference", asset.external_reference)
            )
        return {
            "type": component_type,
            "bom-ref": bom_ref,
            "name": asset.name,
            "properties": self._properties(properties),
        }

    def _finding_component(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment | None,
        recommendations: Sequence[Recommendation],
        plan: PqcRecommendationPlan | None,
        evidence: Mapping[str, Evidence],
    ) -> JsonObject:
        bom_ref = f"qrypton:crypto:{finding.id}"
        component: JsonObject = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": f"qrypton-finding-{finding.id}",
        }
        properties = [
            self._property("org.qrypton.finding.id", finding.id),
            self._property("org.qrypton.finding.category", finding.category),
            self._property("org.qrypton.finding.confidence", finding.confidence),
            self._property("org.qrypton.provenance", self._provenance(finding.provenance)),
        ]
        if (
            finding.algorithm.state is ObservationState.OBSERVED
            and finding.algorithm.value is not None
        ):
            algorithm = finding.algorithm.value
            component["name"] = algorithm.canonical_name
            component["cryptoProperties"] = self._algorithm_properties(algorithm)
            properties.append(
                self._property("org.qrypton.algorithm.family", algorithm.family.value)
            )
            if algorithm.registry_reference is not None:
                component["externalReferences"] = [
                    {"type": "other", "url": str(algorithm.registry_reference)}
                ]
        elif (
            finding.protocol.state is ObservationState.OBSERVED
            and finding.protocol.value is not None
        ):
            protocol = finding.protocol.value
            component["name"] = protocol.name.value or component["name"]
            component["cryptoProperties"] = self._protocol_properties(
                protocol.name.value, protocol.version.value, protocol.cipher_suite.value
            )
        elif (
            finding.certificate.state is ObservationState.OBSERVED
            and finding.certificate.value is not None
        ):
            component["cryptoProperties"] = self._certificate_properties(finding.certificate.value)
        elif (
            finding.key_material.state is ObservationState.OBSERVED
            and finding.key_material.value is not None
        ):
            material = finding.key_material.value
            material_type = {
                KeyKind.PUBLIC: "public-key",
                KeyKind.PRIVATE: "private-key",
                KeyKind.SYMMETRIC: "secret-key",
                KeyKind.SECRET: "secret-key",
            }.get(material.kind)
            if material_type is not None:
                related: JsonObject = {"type": material_type}
                if (
                    material.size_bits.state is ObservationState.OBSERVED
                    and material.size_bits.value is not None
                ):
                    related["size"] = material.size_bits.value
                component["cryptoProperties"] = {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": related,
                }
        else:
            properties.append(self._property("org.qrypton.observation-state", "unclassified"))
        if assessment is not None:
            properties.append(
                self._property("org.qrypton.risk.assessment", assessment.model_dump(mode="json"))
            )
        for recommendation in sorted(recommendations, key=lambda item: item.id):
            properties.append(
                self._property("org.qrypton.recommendation", recommendation.model_dump(mode="json"))
            )
        if plan is not None:
            properties.extend(
                (
                    self._property("org.qrypton.crypto.role", plan.role.value),
                    self._property("org.qrypton.pqc.confidence", plan.rationale.confidence),
                    self._property("org.qrypton.pqc.plan", plan.model_dump(mode="json")),
                )
            )
        for evidence_id in sorted(set(finding.evidence_ids)):
            item = evidence.get(evidence_id)
            if item is not None:
                properties.append(self._property("org.qrypton.evidence", self._evidence(item)))
        component["properties"] = self._properties(properties)
        return component

    @staticmethod
    def _algorithm_properties(algorithm: Algorithm) -> JsonObject:
        properties: JsonObject = {
            "assetType": "algorithm",
            "algorithmProperties": {},
        }
        details: JsonObject = properties["algorithmProperties"]
        primitive = _PRIMITIVES.get(algorithm.family)
        if primitive is not None:
            details["primitive"] = primitive
        if (
            algorithm.key_size_bits.state is ObservationState.OBSERVED
            and algorithm.key_size_bits.value is not None
        ):
            details["parameterSetIdentifier"] = str(algorithm.key_size_bits.value)
        if (
            algorithm.security_strength_bits.state is ObservationState.OBSERVED
            and algorithm.security_strength_bits.value is not None
        ):
            details["classicalSecurityLevel"] = algorithm.security_strength_bits.value
        mode = algorithm.parameters.get("mode")
        if isinstance(mode, str) and mode in {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}:
            details["mode"] = mode
        return properties

    @staticmethod
    def _protocol_properties(
        name: str | None, version: str | None, suite: str | None
    ) -> JsonObject:
        kind = name.casefold() if name is not None else "unknown"
        protocol_type = kind if kind in {"tls", "ssh", "ipsec", "ike", "sstp", "wpa"} else "other"
        details: JsonObject = {"type": protocol_type}
        if version is not None:
            details["version"] = version
        if suite is not None:
            details["cipherSuites"] = [{"name": suite}]
        return {"assetType": "protocol", "protocolProperties": details}

    @staticmethod
    def _certificate_properties(certificate: Any) -> JsonObject:
        details: JsonObject = {}
        fields = (
            ("subjectName", certificate.subject_dn),
            ("issuerName", certificate.issuer_dn),
            ("notValidBefore", certificate.not_before),
            ("notValidAfter", certificate.not_after),
        )
        for key, observation in fields:
            if observation.state is ObservationState.OBSERVED and observation.value is not None:
                value = (
                    observation.value.isoformat().replace("+00:00", "Z")
                    if hasattr(observation.value, "isoformat")
                    else observation.value
                )
                details[key] = value
        return {"assetType": "certificate", "certificateProperties": details}

    @staticmethod
    def _property(name: str, value: Any) -> JsonObject:
        return {
            "name": name,
            "value": value
            if isinstance(value, str)
            else json.dumps(
                value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
            ),
        }

    @staticmethod
    def _properties(properties: Sequence[JsonObject]) -> list[JsonObject]:
        return sorted(properties, key=lambda item: (str(item["name"]), str(item["value"])))

    @staticmethod
    def _provenance(provenance: Any) -> JsonObject:
        return cast(JsonObject, provenance.model_dump(mode="json", exclude={"parent_evidence_ids"}))

    def _deduplicate_evidence(self, evidence: Sequence[Evidence]) -> Mapping[str, Evidence]:
        indexed: dict[str, Evidence] = {}
        for item in evidence:
            previous = indexed.get(item.id)
            if previous is not None and self._serialize(
                previous.model_dump(mode="json")
            ) != self._serialize(item.model_dump(mode="json")):
                raise CBOMExportError(f"evidence ID {item.id} has conflicting content")
            indexed[item.id] = item
        return indexed

    @staticmethod
    def _index_unique(items: Sequence[Any], field: str) -> Mapping[str, Any]:
        result: dict[str, Any] = {}
        for item in items:
            key = str(getattr(item, field))
            if key in result:
                raise CBOMExportError(f"duplicate {field}: {key}")
            result[key] = item
        return result

    @staticmethod
    def _group_recommendations(
        items: Sequence[Recommendation],
    ) -> Mapping[str, tuple[Recommendation, ...]]:
        grouped: dict[str, list[Recommendation]] = {}
        for item in items:
            grouped.setdefault(item.finding_id, []).append(item)
        return {key: tuple(value) for key, value in grouped.items()}

    @staticmethod
    def _evidence(evidence: Evidence) -> JsonObject:
        return {
            "id": evidence.id,
            "kind": evidence.kind.value,
            "raw_content_digest": evidence.raw_content_digest,
            "location": evidence.location.model_dump(mode="json", exclude_none=True),
            "confidence": evidence.confidence,
            "provenance": evidence.provenance.model_dump(mode="json"),
        }

    @staticmethod
    def _serialize(document: Any) -> bytes:
        return json.dumps(
            document, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
