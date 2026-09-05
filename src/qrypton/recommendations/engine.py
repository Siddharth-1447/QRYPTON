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
        if (
            finding.algorithm.state is not ObservationState.OBSERVED
            or finding.algorithm.value is None
        ):
            return RoleClassification(
                role=CryptoRole.UNKNOWN,
                rule_id="algorithm.unobserved",
                basis_evidence_ids=finding.evidence_ids,
                confidence=0.25,
            )
        algorithm = finding.algorithm.value
        name = algorithm.canonical_name.casefold().replace("_", "-")
        if name in {"rsa-kem", "dh", "ecdh", "x25519", "x448"}:
            role = CryptoRole.KEM if name == "rsa-kem" else CryptoRole.KEY_ESTABLISHMENT
        elif name in {"rsa-pss", "ecdsa", "ed25519", "dsa"}:
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
            confidence=finding.confidence
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
        blockers = self._blockers(classification.role, compatibility, policy)
        rationale = RecommendationRationale(
            rule_id=classification.rule_id,
            role=classification.role,
            basis=basis,
            source_algorithm=source,
            facts={
                "finding_category": finding.category,
                "assessment_level": assessment.level.value,
            },
            policy_decisions={
                "hybrid_kem_mode": policy.hybrid_kem_mode.value,
                "signature_selection": policy.signature_selection.value,
            },
            blocking_conditions=blockers,
            confidence=self._confidence(classification.confidence, compatibility, blockers),
        )
        recommendations = self._recommendations(
            finding, assessment, policy, classification.role, targets, references, basis, rationale
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
    ) -> tuple[Recommendation, ...]:
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
                f"Adopt {targets[0].canonical_name} for {role.value}.",
            )
        else:
            primary = self._record(
                finding,
                assessment,
                policy,
                priority,
                RecommendationKind.VALIDATION,
                None,
                (),
                rationale,
                self._heuristic_action(role),
            )
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
    def _heuristic_action(role: CryptoRole) -> str:
        if role is CryptoRole.SYMMETRIC_ENCRYPTION:
            return (
                "Migrate deprecated symmetric encryption to an approved AEAD suite; "
                "do not replace it with ML-KEM or ML-DSA."
            )
        if role is CryptoRole.HASH:
            return (
                "Migrate deprecated hashes to an approved SHA-2 or SHA-3 profile; "
                "do not replace them with ML-KEM or ML-DSA."
            )
        return (
            "Validate the cryptographic role and deployment constraints before selecting "
            "a migration target."
        )

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
    ) -> Recommendation:
        payload = {
            "finding_id": finding.id,
            "assessment_id": assessment.id,
            "policy": policy,
            "kind": kind,
            "target": target,
            "rationale": rationale,
            "engine_version": self.version,
        }
        identifier = self._id_deriver.derive(
            namespace="recommendation",
            tenant_id=finding.tenant_id,
            canonical_payload=canonical_json_bytes(payload),
        )
        name = target.canonical_name if target is not None else rationale.role.value
        return Recommendation(
            id=identifier,
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            risk_assessment_id=assessment.id,
            kind=kind,
            priority=priority,
            title=f"{kind.value.replace('_', ' ').title()}: {name}",
            action=action,
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
