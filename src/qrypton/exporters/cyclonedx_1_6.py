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
from qrypton.contracts.identity import finding_identity_label
from qrypton.contracts.models import (
    Algorithm,
    Asset,
    BusinessContext,
    CryptoFinding,
    DomainModel,
    Evidence,
    PersistedMoscaEvaluation,
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
    AssetKind.SERVICE: "application",
    AssetKind.HOST: "application",
    AssetKind.REPOSITORY: "application",
    AssetKind.LIBRARY: "library",
    AssetKind.CONTAINER_IMAGE: "container",
    AssetKind.BINARY: "file",
    AssetKind.OTHER: "application",
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
        business_context: BusinessContext | None = None,
        finding_business_contexts: Mapping[str, BusinessContext] | None = None,
        mosca_evaluations: Sequence[PersistedMoscaEvaluation] = (),
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
        mosca_by_finding = self._index_unique(mosca_evaluations, "finding_id")
        root_ref = f"qrypton:asset:{asset.id}"
        components = [self._root_component(asset, root_ref, root_type, business_context)]
        dependencies: list[JsonObject] = []
        for finding in sorted(findings, key=lambda item: item.id):
            component = self._finding_component(
                finding,
                assessment_by_finding.get(finding.id),
                recommendation_by_finding.get(finding.id, ()),
                plan_by_finding.get(finding.id),
                evidence_by_id,
                asset.id,
                mosca_by_finding.get(finding.id),
                (finding_business_contexts or {}).get(finding.id),
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

    def _root_component(
        self,
        asset: Asset,
        bom_ref: str,
        component_type: str,
        business_context: BusinessContext | None = None,
    ) -> JsonObject:
        properties = [
            self._property("org.qrypton.asset.id", asset.id),
            self._property("org.qrypton.asset.kind", asset.kind.value),
            self._property("org.qrypton.provenance", self._provenance(asset.provenance)),
        ]
        if asset.external_reference:
            properties.append(
                self._property("org.qrypton.asset.external-reference", asset.external_reference)
            )
        for tag in asset.tags:
            properties.append(self._property("org.qrypton.asset.tag", tag))
        if business_context is not None:
            properties.extend(self._business_properties(business_context))
        return {
            "type": component_type,
            "bom-ref": bom_ref,
            "name": asset.name,
            "properties": self._properties(properties),
        }

    @staticmethod
    def _business_properties(business_context: BusinessContext) -> list[JsonObject]:
        """Target-independent business context retained on the CBOM root asset."""
        properties: list[JsonObject] = []
        observed = (
            ("org.qrypton.business.criticality", business_context.criticality),
            ("org.qrypton.business.data-classification", business_context.data_classification),
            ("org.qrypton.business.internet-exposed", business_context.internet_exposed),
            ("org.qrypton.business.owner", business_context.owner_reference),
        )
        for name, observation in observed:
            if observation.state is ObservationState.OBSERVED and observation.value is not None:
                value = observation.value
                properties.append(CycloneDx16CbomExporter._property(name, value))
        if business_context.regulatory_scopes:
            properties.append(
                CycloneDx16CbomExporter._property(
                    "org.qrypton.business.regulatory-scopes",
                    sorted(set(business_context.regulatory_scopes)),
                )
            )
        return properties

    @staticmethod
    def _mosca_property(evaluation: PersistedMoscaEvaluation) -> JsonObject:
        """Persist the complete independent Mosca result without merging severity."""
        return CycloneDx16CbomExporter._property(
            "org.qrypton.mosca", evaluation.model_dump(mode="json")
        )

    def _finding_component(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment | None,
        recommendations: Sequence[Recommendation],
        plan: PqcRecommendationPlan | None,
        evidence: Mapping[str, Evidence],
        asset_id: str,
        mosca: PersistedMoscaEvaluation | None = None,
        business_context: BusinessContext | None = None,
    ) -> JsonObject:
        bom_ref = f"qrypton:crypto:{finding.id}"
        component: JsonObject = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": f"qrypton-finding-{finding.id}",
        }
        canonical = finding.model_dump(mode="json")
        # Scanner parameters are free-form and can carry provider secrets.
        # Retain only a recognized, non-secret cipher mode.
        algorithm_observation = canonical.get("algorithm", {})
        safe_parameters: dict[str, str] = {}
        if isinstance(algorithm_observation, dict) and isinstance(
            algorithm_observation.get("value"), dict
        ):
            raw_parameters = algorithm_observation["value"].get("parameters", {})
            mode = raw_parameters.get("mode") if isinstance(raw_parameters, dict) else None
            if isinstance(mode, str) and mode.casefold() in {
                "cbc",
                "ecb",
                "ccm",
                "gcm",
                "cfb",
                "ofb",
                "ctr",
            }:
                safe_parameters["mode"] = mode
            algorithm_observation["value"]["parameters"] = safe_parameters
        properties = [
            self._property("org.qrypton.asset.id", asset_id),
            self._property("org.qrypton.finding.id", finding.id),
            self._property("org.qrypton.finding.category", finding.category),
            # Retain the entire canonical contract so unsupported CycloneDX facets
            # and observation states survive round trips without inference.
            self._property("org.qrypton.finding.canonical", canonical),
            self._property("org.qrypton.finding.confidence", finding.confidence),
            self._property("org.qrypton.provenance", self._provenance(finding.provenance)),
            self._property(
                "org.qrypton.identity.status", finding.algorithm_identification_status.value
            ),
            self._property("org.qrypton.identity.label", finding_identity_label(finding)),
            self._property(
                "org.qrypton.identity.confidence", finding.algorithm_identification_confidence
            ),
            self._property(
                "org.qrypton.identity.evidence", sorted(finding.algorithm_identification_evidence)
            ),
            self._property("org.qrypton.finding.confidence.reasons", finding.confidence_reasons),
            self._property("org.qrypton.finding.usage-confidence", finding.usage_confidence),
        ]
        if finding.correlation_provenance is not None:
            properties.append(
                self._property(
                    "org.qrypton.correlation.provenance",
                    self._provenance(finding.correlation_provenance),
                )
            )
        if finding.algorithm_variant:
            properties.append(
                self._property("org.qrypton.algorithm.variant", finding.algorithm_variant)
            )
        if finding.crypto_role:
            properties.append(self._property("org.qrypton.crypto.role", finding.crypto_role))
        if finding.library.state is ObservationState.OBSERVED and finding.library.value is not None:
            metadata = finding.library.value
            if finding.algorithm.state is not ObservationState.OBSERVED:
                component["type"] = "library"
            if metadata.name.state is ObservationState.OBSERVED and metadata.name.value:
                properties.append(self._property("org.qrypton.library.name", metadata.name.value))
            if metadata.ecosystem.state is ObservationState.OBSERVED and metadata.ecosystem.value:
                properties.append(
                    self._property("org.qrypton.library.ecosystem", metadata.ecosystem.value)
                )
        if business_context is not None:
            properties.extend(self._business_properties(business_context))
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
            if safe_parameters:
                properties.append(
                    self._property("org.qrypton.algorithm.parameters", safe_parameters)
                )
            properties.append(
                self._property("org.qrypton.algorithm.lifecycle", algorithm.lifecycle_status.value)
            )
            if algorithm.registry_reference is not None:
                component["externalReferences"] = [
                    {"type": "other", "url": str(algorithm.registry_reference)}
                ]
        elif (
            finding.library.state is ObservationState.OBSERVED
            and finding.library.value is not None
            and finding.library.value.name.state is ObservationState.OBSERVED
            and finding.library.value.name.value
        ):
            component["name"] = finding.library.value.name.value
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
            if assessment.assessment_confidence is not None:
                properties.append(
                    self._property(
                        "org.qrypton.risk.assessment-confidence",
                        assessment.assessment_confidence,
                    )
                )
            if assessment.context_completeness is not None:
                properties.append(
                    self._property(
                        "org.qrypton.risk.context-completeness",
                        assessment.context_completeness,
                    )
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
        if mosca is not None:
            properties.append(self._mosca_property(mosca))
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
        if isinstance(mode, str) and mode.casefold() in {
            "cbc",
            "ecb",
            "ccm",
            "gcm",
            "cfb",
            "ofb",
            "ctr",
        }:
            details["mode"] = mode.casefold()
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
        # Preserve provenance, location and digests. Captured excerpts and
        # free-form scanner attributes may contain credentials or key material.
        return evidence.model_dump(mode="json", exclude={"excerpt", "attributes"})

    @staticmethod
    def _serialize(document: Any) -> bytes:
        return json.dumps(
            document, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")


def sanitize_persisted_cbom(payload: bytes) -> bytes:
    """Redact unsafe legacy free-form fields without changing stored scan bytes.

    Current exporter already omits these fields. Older persisted documents are
    projected at download time; assessments and observation states are untouched.
    """
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("CBOM root must be an object")
    changed = False
    components = document.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CBOM components must be a list")
    for component in components:
        if not isinstance(component, dict):
            continue
        properties = component.get("properties", [])
        if not isinstance(properties, list):
            continue
        safe_properties = []
        for prop in properties:
            if not isinstance(prop, dict):
                continue
            name = prop.get("name")
            if name == "org.qrypton.evidence":
                try:
                    evidence = json.loads(prop["value"])
                except (KeyError, TypeError, ValueError):
                    changed = True
                    continue
                if not isinstance(evidence, dict):
                    changed = True
                    continue
                if "excerpt" in evidence or "attributes" in evidence:
                    evidence.pop("excerpt", None)
                    evidence.pop("attributes", None)
                    prop["value"] = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
                    changed = True
            elif name == "org.qrypton.algorithm.parameters":
                try:
                    parameters = json.loads(prop["value"])
                except (KeyError, TypeError, ValueError):
                    parameters = {}
                mode = parameters.get("mode") if isinstance(parameters, dict) else None
                if not isinstance(mode, str) or mode.casefold() not in {
                    "cbc",
                    "ecb",
                    "ccm",
                    "gcm",
                    "cfb",
                    "ofb",
                    "ctr",
                }:
                    changed = True
                    continue
                safe = {"mode": mode}
                if parameters != safe:
                    prop["value"] = json.dumps(safe, sort_keys=True, separators=(",", ":"))
                    changed = True
            elif name == "org.qrypton.finding.canonical":
                try:
                    canonical = json.loads(prop["value"])
                except (KeyError, TypeError, ValueError):
                    changed = True
                    continue
                if not isinstance(canonical, dict):
                    changed = True
                    continue
                algorithm = canonical.get("algorithm", {})
                value = algorithm.get("value") if isinstance(algorithm, dict) else None
                if isinstance(value, dict):
                    parameters = value.get("parameters", {})
                    mode = parameters.get("mode") if isinstance(parameters, dict) else None
                    safe = (
                        {"mode": mode}
                        if isinstance(mode, str)
                        and mode.casefold() in {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
                        else {}
                    )
                    if parameters != safe:
                        value["parameters"] = safe
                        prop["value"] = json.dumps(
                            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                        )
                        changed = True
            safe_properties.append(prop)
        component["properties"] = safe_properties
    return CycloneDx16CbomExporter._serialize(document) if changed else payload
