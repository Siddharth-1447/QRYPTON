"""Role-first, deterministic PQC recommendation engine."""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import HttpUrl, TypeAdapter

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    ObservationState,
    RecommendationKind,
    RiskLevel,
)
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    Algorithm,
    CryptoFinding,
    Observation,
    Provenance,
    Recommendation,
    RiskAssessment,
)
from qrypton.contracts.primitives import ScannerVersion
from qrypton.policies.pqc import PqcRecommendationPolicy
from qrypton.recommendations.schemas import (
    CompatibilityFactors,
    CryptoRole,
    HybridMode,
    PqcRecommendationPlan,
    RecommendationBasis,
    RecommendationRationale,
    RoleClassification,
    SignatureSelection,
)

_url = TypeAdapter(HttpUrl)
_FIPS_203 = _url.validate_python("https://csrc.nist.gov/pubs/fips/203/final")
_FIPS_204 = _url.validate_python("https://csrc.nist.gov/pubs/fips/204/final")
_FIPS_205 = _url.validate_python("https://csrc.nist.gov/pubs/fips/205/final")
_FIPS_180 = _url.validate_python("https://csrc.nist.gov/pubs/fips/180-4/upd1/final")
_FIPS_197 = _url.validate_python("https://csrc.nist.gov/pubs/fips/197/final")
_FIPS_198 = _url.validate_python("https://csrc.nist.gov/pubs/fips/198-1/final")
_FIPS_202 = _url.validate_python("https://csrc.nist.gov/pubs/fips/202/final")
_SP_800_38D = _url.validate_python("https://csrc.nist.gov/pubs/sp/800/38/d/final")
_ASYMMETRIC_NAMES = frozenset({"rsa", "ec", "ecdsa", "ed25519", "x25519", "x448"})


def _unknown_int() -> Observation[int]:
    return Observation[int](state=ObservationState.UNKNOWN)


def _unknown_algorithm() -> Observation[Algorithm]:
    return Observation[Algorithm](state=ObservationState.UNKNOWN)


def _algorithm(name: str, family: AlgorithmFamily) -> Algorithm:
    return Algorithm(
        canonical_name=name,
        family=family,
        lifecycle_status=AlgorithmStatus.APPROVED,
        key_size_bits=_unknown_int(),
        security_strength_bits=_unknown_int(),
    )


class CryptoRoleClassifier:
    """Classify only when the normalized finding supports a non-ambiguous role."""

    def classify(
        self, finding: CryptoFinding, *, policy: PqcRecommendationPolicy
    ) -> RoleClassification:
        override = policy.role_overrides.get(finding.id)
        if override is not None:
            return RoleClassification(
                role=override,
                rule_id="policy.role_override",
                basis_evidence_ids=finding.evidence_ids,
                confidence=0.85,
            )
        if finding.category == "certificate":
            return RoleClassification(
                role=CryptoRole.CERTIFICATE_PKI_ARTIFACT,
                rule_id="finding.category.certificate",
                basis_evidence_ids=finding.evidence_ids,
                confidence=finding.confidence,
            )
        if finding.category == "protocol":
            return RoleClassification(
                role=CryptoRole.PROTOCOL_CONFIGURATION,
                rule_id="finding.category.protocol",
                basis_evidence_ids=finding.evidence_ids,
                confidence=finding.confidence,
            )
        if finding.category == "library":
            return RoleClassification(
                role=CryptoRole.UNKNOWN,
                rule_id="finding.category.library_only",
                basis_evidence_ids=finding.evidence_ids,
                confidence=finding.confidence,
            )
        if (
            finding.algorithm.state is not ObservationState.OBSERVED
            or finding.algorithm.value is None
            or finding.algorithm.value.canonical_name == "unknown"
            or finding.algorithm.value.family is AlgorithmFamily.UNKNOWN
        ):
            return RoleClassification(
                role=CryptoRole.UNKNOWN,
                rule_id="algorithm.unobserved",
                basis_evidence_ids=finding.evidence_ids,
                confidence=0.20,
            )
        algorithm = finding.algorithm.value
        name = algorithm.canonical_name.casefold().replace("_", "-").replace(" ", "-")
        explicit_role = (finding.crypto_role or "").casefold().replace("-", "_")
        explicit_roles = {
            "kem": CryptoRole.KEM,
            "key_establishment": CryptoRole.KEY_ESTABLISHMENT,
            "key_agreement": CryptoRole.KEY_ESTABLISHMENT,
            "signature": CryptoRole.SIGNATURE,
            "signing": CryptoRole.SIGNATURE,
            "encryption": CryptoRole.SYMMETRIC_ENCRYPTION,
            "symmetric_encryption": CryptoRole.SYMMETRIC_ENCRYPTION,
        }
        if explicit_role in explicit_roles:
            role = explicit_roles[explicit_role]
        elif name in {"rsa-kem", "dh", "ecdh", "x25519", "x448"}:
            role = CryptoRole.KEM if name == "rsa-kem" else CryptoRole.KEY_ESTABLISHMENT
        elif name in {"rsa-pss", "ecdsa", "ed25519", "dsa"}:
            role = CryptoRole.SIGNATURE
        elif name in {"ml-kem", "ml-kem-512", "ml-kem-768", "ml-kem-1024"}:
            role = CryptoRole.KEM
        elif name in {"ml-dsa", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa"}:
            role = CryptoRole.SIGNATURE
        elif name in _ASYMMETRIC_NAMES or algorithm.family is AlgorithmFamily.ASYMMETRIC_ENCRYPTION:
            role = CryptoRole.AMBIGUOUS
        else:
            role = {
                AlgorithmFamily.KEY_AGREEMENT: CryptoRole.KEY_ESTABLISHMENT,
                AlgorithmFamily.SIGNATURE: CryptoRole.SIGNATURE,
                AlgorithmFamily.HASH: CryptoRole.HASH,
                AlgorithmFamily.SYMMETRIC_CIPHER: CryptoRole.SYMMETRIC_ENCRYPTION,
                AlgorithmFamily.MAC: CryptoRole.MAC,
                AlgorithmFamily.KDF: CryptoRole.KDF,
                AlgorithmFamily.RNG: CryptoRole.RNG,
                AlgorithmFamily.PROTOCOL: CryptoRole.PROTOCOL_CONFIGURATION,
            }.get(algorithm.family, CryptoRole.UNKNOWN)
        return RoleClassification(
            role=role,
            rule_id=f"algorithm.{algorithm.family.value}",
            basis_evidence_ids=finding.algorithm.basis_evidence_ids,
            confidence=min(
                finding.confidence,
                finding.algorithm_identification_confidence or finding.confidence,
            )
            if role is not CryptoRole.AMBIGUOUS
            else min(finding.confidence, 0.5),
        )


class PqcRecommendationEngine:
    """Pure recommendation-port adapter with injected identity and provenance dependencies."""

    name = "qrypton-pqc-recommendation"
    version: ScannerVersion = "0.6.0"

    def __init__(self, *, id_deriver: IdDeriver, provenance: Provenance) -> None:
        self._id_deriver = id_deriver
        self._provenance = provenance
        self._classifier = CryptoRoleClassifier()

    def recommend(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment,
        policy: PqcRecommendationPolicy,
    ) -> Sequence[Recommendation]:
        """Satisfy the stable RecommendationEngine port with canonical records only."""
        return self.plan(finding, assessment, policy).recommendations

    def plan(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment,
        policy: PqcRecommendationPolicy,
        *,
        compatibility: CompatibilityFactors | None = None,
    ) -> PqcRecommendationPlanWithRecords:
        compatibility = compatibility or policy.default_compatibility
        classification = self._classifier.classify(finding, policy=policy)
        source = self._source_name(finding)
        targets, references, basis, hybrid = self._targets(classification.role, policy)
        source_name = (source or "").casefold().replace("_", "-")
        already_pqc = source_name.startswith(("ml-kem", "ml-dsa", "slh-dsa"))
        if already_pqc:
            references = (
                (_FIPS_203,)
                if source_name.startswith("ml-kem")
                else (_FIPS_204,)
                if source_name.startswith("ml-dsa")
                else (_FIPS_205,)
            )
            targets, basis, hybrid = (), RecommendationBasis.STANDARDS_BACKED, HybridMode.DISABLED
        blockers = self._blockers(classification.role, compatibility, policy)
        rationale = RecommendationRationale(
            rule_id=classification.rule_id,
            role=classification.role,
            basis=basis,
            source_algorithm=source,
            facts={
                "finding_category": finding.category,
                "assessment_level": assessment.level.value,
                "algorithm_lifecycle": (
                    finding.algorithm.value.lifecycle_status.value
                    if finding.algorithm.value is not None
                    else "unknown"
                ),
                "algorithm_family": (
                    finding.algorithm.value.family.value
                    if finding.algorithm.value is not None
                    else "unknown"
                ),
                "evidence_ids": ",".join(classification.basis_evidence_ids),
                "classical_status": self._classical_status(source_name, finding),
                "quantum_migration": "already_pqc" if already_pqc else "role_dependent",
                "peer_support": compatibility.peer_support,
                "protocol_support": compatibility.protocol_support,
                "hsm_kms_support": compatibility.hsm_kms_support,
                "performance_impact": compatibility.performance_impact,
                "latency_impact": compatibility.latency_impact,
                "migration_complexity": compatibility.migration_complexity,
            },
            policy_decisions={
                "hybrid_kem_mode": policy.hybrid_kem_mode.value,
                "signature_selection": policy.signature_selection.value,
            },
            blocking_conditions=blockers,
            confidence=self._confidence(classification.confidence, compatibility, blockers),
        )
        recommendations = self._recommendations(
            finding,
            assessment,
            policy,
            classification.role,
            targets,
            references,
            basis,
            rationale,
            already_pqc=already_pqc,
        )
        plan = PqcRecommendationPlan(
            finding_id=finding.id,
            role=classification.role,
            target_algorithms=targets,
            hybrid_mode=hybrid,
            standard_references=references,
            basis=basis,
            compatibility=compatibility,
            rationale=rationale,
            canonical_recommendation_ids=tuple(item.id for item in recommendations),
        )
        return PqcRecommendationPlanWithRecords(plan=plan, recommendations=recommendations)

    @staticmethod
    def _source_name(finding: CryptoFinding) -> str | None:
        return (
            finding.algorithm.value.canonical_name
            if finding.algorithm.state is ObservationState.OBSERVED
            and finding.algorithm.value is not None
            else None
        )

    @staticmethod
    def _targets(
        role: CryptoRole, policy: PqcRecommendationPolicy
    ) -> tuple[tuple[Algorithm, ...], tuple[HttpUrl, ...], RecommendationBasis, HybridMode]:
        if (
            role in {CryptoRole.KEM, CryptoRole.KEY_ESTABLISHMENT}
            and "FIPS-203" in policy.supported_fips
        ):
            return (
                (_algorithm("ml-kem", AlgorithmFamily.KEY_AGREEMENT),),
                (_FIPS_203,),
                RecommendationBasis.STANDARDS_BACKED,
                policy.hybrid_kem_mode,
            )
        if role is CryptoRole.SIGNATURE:
            if (
                policy.signature_selection is SignatureSelection.SLH_DSA
                and "FIPS-205" in policy.supported_fips
            ):
                return (
                    (_algorithm("slh-dsa", AlgorithmFamily.SIGNATURE),),
                    (_FIPS_205,),
                    RecommendationBasis.STANDARDS_BACKED,
                    HybridMode.DISABLED,
                )
            if "FIPS-204" in policy.supported_fips:
                targets: tuple[Algorithm, ...] = (_algorithm("ml-dsa", AlgorithmFamily.SIGNATURE),)
                references: tuple[HttpUrl, ...] = (_FIPS_204,)
                if (
                    policy.signature_selection is SignatureSelection.POLICY_RANKED
                    and policy.allow_slh_dsa_alternative
                    and "FIPS-205" in policy.supported_fips
                ):
                    targets += (_algorithm("slh-dsa", AlgorithmFamily.SIGNATURE),)
                    references += (_FIPS_205,)
                return (
                    targets,
                    references,
                    RecommendationBasis.STANDARDS_BACKED,
                    HybridMode.DISABLED,
                )
        references_by_role = {
            CryptoRole.HASH: (_FIPS_180, _FIPS_202),
            CryptoRole.SYMMETRIC_ENCRYPTION: (_FIPS_197, _SP_800_38D),
            CryptoRole.MAC: (_FIPS_198,),
            CryptoRole.PROTOCOL_CONFIGURATION: (_FIPS_203, _FIPS_204),
            CryptoRole.CERTIFICATE_PKI_ARTIFACT: (_FIPS_204, _FIPS_205),
        }
        if role in references_by_role:
            return (
                (),
                references_by_role[role],
                RecommendationBasis.STANDARDS_BACKED,
                HybridMode.DISABLED,
            )
        return (), (), RecommendationBasis.HEURISTIC, HybridMode.DISABLED

    @staticmethod
    def _blockers(
        role: CryptoRole, factors: CompatibilityFactors, policy: PqcRecommendationPolicy
    ) -> tuple[str, ...]:
        blockers = list(factors.operational_constraints)
        if factors.peer_support == "unsupported":
            blockers.append("peer support is currently unsupported")
        if factors.protocol_support == "unsupported":
            blockers.append("protocol support is currently unsupported")
        if factors.hsm_kms_support == "unsupported":
            blockers.append("HSM/KMS support is currently unsupported")
        if policy.required_peer_support and factors.peer_support != "confirmed":
            blockers.append("peer support must be confirmed before production cutover")
        if policy.require_hsm_kms_support and factors.hsm_kms_support != "confirmed":
            blockers.append("HSM/KMS support must be confirmed before production cutover")
        if (
            role is CryptoRole.CERTIFICATE_PKI_ARTIFACT
            and factors.certificate_ecosystem_support != "confirmed"
        ):
            blockers.append("certificate ecosystem compatibility must be validated")
        return tuple(sorted(set(blockers)))

    @staticmethod
    def _confidence(base: float, factors: CompatibilityFactors, blockers: tuple[str, ...]) -> float:
        unknowns = sum(
            value == "unknown"
            for value in (factors.peer_support, factors.protocol_support, factors.hsm_kms_support)
        )
        penalty = 0.1 * unknowns + (0.2 if blockers else 0.0)
        return max(0.0, round(base - penalty, 4))

    def _recommendations(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment,
        policy: PqcRecommendationPolicy,
        role: CryptoRole,
        targets: tuple[Algorithm, ...],
        references: tuple[HttpUrl, ...],
        basis: RecommendationBasis,
        rationale: RecommendationRationale,
        *,
        already_pqc: bool = False,
    ) -> tuple[Recommendation, ...]:
        if role is CryptoRole.UNKNOWN or (
            finding.algorithm.state is ObservationState.OBSERVED
            and finding.algorithm.value is not None
            and (
                finding.algorithm.value.canonical_name == "unknown"
                or finding.algorithm.value.family is AlgorithmFamily.UNKNOWN
            )
        ):
            manual_review = self._record(
                finding,
                assessment,
                policy,
                1,
                RecommendationKind.VALIDATION,
                None,
                references,
                rationale,
                (
                    "Library presence alone does not prove cryptographic use; "
                    "inspect reachable call sites, configuration, and runtime role."
                    if finding.category == "library"
                    else "Manual review required: algorithm or cryptographic role "
                    "could not be identified; do not select a replacement "
                    "until context is established."
                ),
                custom_title=(
                    "Insufficient Context: Library Only"
                    if finding.category == "library"
                    else "Manual Review Required: Unidentified Algorithm"
                ),
            )
            return (manual_review,)

        priority = {
            RiskLevel.CRITICAL: 100,
            RiskLevel.HIGH: 85,
            RiskLevel.MEDIUM: 65,
            RiskLevel.LOW: 40,
            RiskLevel.INFORMATIONAL: 20,
            RiskLevel.UNKNOWN: 20,
        }[assessment.level]
        if targets:
            primary = self._record(
                finding,
                assessment,
                policy,
                priority,
                RecommendationKind.MIGRATION,
                targets[0],
                references,
                rationale,
                f"Adopt {targets[0].canonical_name} for {role.value}. "
                "This addresses quantum-era migration; it does not by itself "
                "establish an immediate classical break. Validate peer, protocol, "
                "and deployment support before rollout.",
            )
        elif already_pqc:
            primary = self._record(
                finding,
                assessment,
                policy,
                priority,
                RecommendationKind.VALIDATION,
                None,
                (),
                rationale,
                "PQC algorithm is already present. Verify the exact standardized "
                "parameter set, implementation validation, protocol interoperability, "
                "and operational support; no primitive replacement is indicated "
                "by this finding.",
                custom_title="Validate Existing PQC Deployment",
            )
        else:
            primary = self._record(
                finding,
                assessment,
                policy,
                priority,
                RecommendationKind.VALIDATION,
                None,
                references,
                rationale,
                self._heuristic_action(role, finding),
            )
        if role in {
            CryptoRole.UNKNOWN,
            CryptoRole.AMBIGUOUS,
            CryptoRole.PROTOCOL_CONFIGURATION,
            CryptoRole.CERTIFICATE_PKI_ARTIFACT,
        }:
            return (primary,)
        agility = self._record(
            finding,
            assessment,
            policy,
            max(1, priority - 5),
            RecommendationKind.REMEDIATION,
            None,
            (),
            rationale,
            (
                "Introduce a crypto-agility abstraction with policy-driven algorithm selection, "
                "capability checks, staged rollout, and rollback."
            ),
        )
        return (primary, agility)

    @staticmethod
    def _heuristic_action(role: CryptoRole, finding: CryptoFinding) -> str:
        source = (
            (finding.algorithm.value.canonical_name if finding.algorithm.value else "")
            .casefold()
            .replace("_", "-")
        )
        lifecycle = (
            finding.algorithm.value.lifecycle_status
            if finding.algorithm.value
            else AlgorithmStatus.UNKNOWN
        )
        immediately_weak = source in {
            "md5",
            "sha-1",
            "sha1",
            "des",
            "3des",
            "triple-des",
            "des-ede3",
        }
        if role is CryptoRole.SYMMETRIC_ENCRYPTION:
            if source in {"aes-128", "aes128"}:
                return (
                    "AES-128 is not treated as immediately classically broken by this finding. "
                    "For long-lived confidentiality, assess the quantum security margin and plan "
                    "AES-256 where policy and protocol compatibility require it; use an approved "
                    "authenticated mode and measure deployment impact before rollout."
                )
            if not immediately_weak and lifecycle not in {
                AlgorithmStatus.DEPRECATED,
                AlgorithmStatus.DISALLOWED,
                AlgorithmStatus.LEGACY,
            }:
                return (
                    "No primitive replacement is supported by the observed evidence. "
                    "Validate key size, mode, nonce handling, and policy; assess quantum "
                    "margin for long-lived confidentiality and record measured "
                    "performance and latency before any change."
                )
            return (
                "Replace the classically weak or deprecated symmetric construction "
                "with an approved AEAD suite; "
                "do not replace it with ML-KEM or ML-DSA."
            )
        if role is CryptoRole.HASH:
            if not immediately_weak and lifecycle not in {
                AlgorithmStatus.DEPRECATED,
                AlgorithmStatus.DISALLOWED,
                AlgorithmStatus.LEGACY,
            }:
                return (
                    "No hash replacement is supported by this evidence. Confirm the "
                    "hash purpose and required collision/preimage strength; quantum "
                    "impact depends on that purpose, and compatibility/performance "
                    "must be measured before changing it."
                )
            return (
                "Retire the classically weak or deprecated hash and select an approved "
                "SHA-2 or SHA-3 profile for its actual purpose; "
                "do not replace them with ML-KEM or ML-DSA."
            )
        if role is CryptoRole.MAC:
            return (
                "Validate the MAC construction, key size, and protocol use; "
                "select an approved MAC profile based on the actual role. "
                "PQC signatures or KEMs are not MAC replacements."
            )
        if role is CryptoRole.KDF:
            return (
                "Validate the KDF, salt/context binding, and key lifecycle; "
                "migrate only if its classical status or policy requires it. "
                "PQC signatures or KEMs are not KDF replacements."
            )
        if role is CryptoRole.RNG:
            return (
                "Validate entropy source, DRBG construction, and platform support; "
                "choose a compliant generator based on implementation evidence. "
                "PQC signatures or KEMs are not RNG replacements."
            )
        if role is CryptoRole.PROTOCOL_CONFIGURATION:
            return (
                "Review the negotiated protocol version, cipher suite, peer capabilities, "
                "and configuration. Select a hybrid transition only when the protocol "
                "and both peers support it."
            )
        if role is CryptoRole.CERTIFICATE_PKI_ARTIFACT:
            return (
                "Identify whether the artifact uses a legacy public key or certificate "
                "signature, then validate trust-chain, issuance, client, and HSM support "
                "before planning ML-DSA or SLH-DSA adoption."
            )
        if role is CryptoRole.AMBIGUOUS:
            return (
                "Insufficient context to determine the RSA/ECC operation. Confirm whether it is "
                "key establishment, signing, encryption, or another use; do not select a primitive "
                "replacement until that role and protocol context are evidenced."
            )
        return (
            "Validate the cryptographic role and deployment constraints before selecting "
            "a migration target."
        )

    @staticmethod
    def _classical_status(source: str, finding: CryptoFinding) -> str:
        immediately_weak = {"md5", "sha-1", "sha1", "des", "3des", "triple-des", "des-ede3"}
        if source in immediately_weak or (
            finding.algorithm.value
            and finding.algorithm.value.lifecycle_status
            in {AlgorithmStatus.DEPRECATED, AlgorithmStatus.DISALLOWED}
        ):
            return "classically_weak_or_disallowed"
        if source in {"rsa", "rsa-pss", "dh", "ecdh", "ecdsa", "ed25519", "x25519", "x448"}:
            return "no_classical_break_inferred_from_quantum_exposure_alone"
        return "not_determined_from_available_evidence"

    def _record(
        self,
        finding: CryptoFinding,
        assessment: RiskAssessment,
        policy: PqcRecommendationPolicy,
        priority: int,
        kind: RecommendationKind,
        target: Algorithm | None,
        references: tuple[HttpUrl, ...],
        rationale: RecommendationRationale,
        action: str,
        custom_title: str | None = None,
    ) -> Recommendation:
        payload = {
            "finding_id": finding.id,
            "assessment_id": assessment.id,
            "policy": policy,
            "kind": kind,
            "target": target,
            "rationale": rationale,
            "engine_version": self.version,
            "custom_title": custom_title,
        }
        identifier = self._id_deriver.derive(
            namespace="recommendation",
            tenant_id=finding.tenant_id,
            canonical_payload=canonical_json_bytes(payload),
        )
        name = target.canonical_name if target is not None else rationale.role.value
        title = (
            custom_title
            if custom_title is not None
            else f"{kind.value.replace('_', ' ').title()}: {name}"
        )
        evidence_value = rationale.facts.get("evidence_ids", "")
        evidence_ids = (
            ", ".join(evidence_value.split(",")) if isinstance(evidence_value, str) else ""
        )
        assumptions = (
            "; ".join(rationale.blocking_conditions)
            or "no blocking condition was supplied; compatibility is described "
            "by the recorded factors"
        )
        compatibility = (
            "Compatibility factors (no measurements inferred): "
            f"peer={rationale.facts.get('peer_support', 'unknown')}, "
            f"protocol={rationale.facts.get('protocol_support', 'unknown')}, "
            f"HSM/KMS={rationale.facts.get('hsm_kms_support', 'unknown')}, "
            f"performance={rationale.facts.get('performance_impact', 'unknown')}, "
            f"latency={rationale.facts.get('latency_impact', 'unknown')}, "
            f"migration_complexity={rationale.facts.get('migration_complexity', 'unknown')}."
        )
        hybrid = rationale.policy_decisions.get("hybrid_kem_mode", "disabled")
        hybrid_note = (
            f" Hybrid KEM transition mode is {hybrid}; where protocol constraints "
            "require transition protection, retain classical and PQC key establishment "
            "together only in a mutually supported standardized protocol construction."
            if rationale.role in {CryptoRole.KEM, CryptoRole.KEY_ESTABLISHMENT}
            else ""
        )
        evidenced_action = (
            f"{action}{hybrid_note} Classical status: "
            f"{rationale.facts.get('classical_status', 'not determined')}. "
            f"Assumptions: {assumptions}. {compatibility} "
            f"Evidence: {evidence_ids or 'finding evidence only'}. "
            f"Recommendation confidence: {rationale.confidence:.2f} ({rationale.rule_id})."
        )
        return Recommendation(
            id=identifier,
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            risk_assessment_id=assessment.id,
            kind=kind,
            priority=priority,
            title=title,
            action=evidenced_action,
            nist_references=references,
            policy_profile_id=policy.profile_id,
            policy_profile_version=policy.profile_version,
            replacement_algorithm=Observation(
                state=ObservationState.OBSERVED,
                value=target,
                basis_evidence_ids=finding.evidence_ids,
            )
            if target is not None
            else _unknown_algorithm(),
            created_at=self._provenance.observed_at,
            provenance=self._provenance,
        )


class PqcRecommendationPlanWithRecords:
    """Plan plus canonical records; intentionally not a persisted domain model."""

    def __init__(
        self, *, plan: PqcRecommendationPlan, recommendations: tuple[Recommendation, ...]
    ) -> None:
        self.plan = plan
        self.recommendations = recommendations
