"""NIST PQC and symmetric/hash migration mappings."""

from __future__ import annotations

from typing import Literal, TypeVar

from pydantic import HttpUrl, TypeAdapter

from qrypton.contracts.enums import (
    AlgorithmFamily,
    AlgorithmStatus,
    ObservationState,
    RecommendationKind,
)
from qrypton.contracts.ids import IdDeriver, canonical_json_bytes
from qrypton.contracts.models import (
    Algorithm,
    CryptoFinding,
    DomainModel,
    Observation,
    Provenance,
    Recommendation,
)
from qrypton.policies.pqc import PqcRecommendationPolicy
from qrypton.risk.mosca import MoscaEvaluation

_url_adapter = TypeAdapter(HttpUrl)
_FIPS_203 = _url_adapter.validate_python("https://csrc.nist.gov/pubs/fips/203/final")
_FIPS_204 = _url_adapter.validate_python("https://csrc.nist.gov/pubs/fips/204/final")
_FIPS_205 = _url_adapter.validate_python("https://csrc.nist.gov/pubs/fips/205/final")
T = TypeVar("T")


class PqcMapping(DomainModel):
    """Replacement and urgency metadata for a recognized legacy primitive."""

    legacy_algorithm: str
    replacement_algorithm: Algorithm
    transition_kind: Literal["kem", "signature", "symmetric_hash"]
    standard_references: tuple[HttpUrl, ...]
    urgency: Literal["critical", "high", "medium", "low"]


def _unknown() -> Observation[T]:
    return Observation[T](state=ObservationState.UNKNOWN)


def _algorithm(name: str, family: AlgorithmFamily, status: AlgorithmStatus) -> Algorithm:
    return Algorithm(
        canonical_name=name,
        family=family,
        lifecycle_status=status,
        key_size_bits=_unknown(),
        security_strength_bits=_unknown(),
    )


class PqcMapper:
    """Maps observed legacy algorithms to standards without claiming automatic equivalence."""

    def map_finding(
        self, finding: CryptoFinding, *, mosca: MoscaEvaluation | None = None
    ) -> PqcMapping | None:
        if (
            finding.algorithm.state is not ObservationState.OBSERVED
            or finding.algorithm.value is None
        ):
            return None
        legacy = finding.algorithm.value.canonical_name.casefold().replace("_", "-")
        urgency = mosca.urgency if mosca else "medium"
        if legacy in {"rsa-kem", "dh", "ecdh"}:
            return PqcMapping(
                legacy_algorithm=legacy,
                replacement_algorithm=_algorithm(
                    "ml-kem", AlgorithmFamily.KEY_AGREEMENT, AlgorithmStatus.APPROVED
                ),
                transition_kind="kem",
                standard_references=(_FIPS_203,),
                urgency=urgency,
            )
        if legacy in {"rsa-pss", "ecdsa", "ed25519"}:
            return PqcMapping(
                legacy_algorithm=legacy,
                replacement_algorithm=_algorithm(
                    "ml-dsa", AlgorithmFamily.SIGNATURE, AlgorithmStatus.APPROVED
                ),
                transition_kind="signature",
                standard_references=(_FIPS_204, _FIPS_205),
                urgency=urgency,
            )
        if legacy in {"3des", "triple-des", "des-ede3", "sha-1", "sha1"}:
            replacement = (
                _algorithm("aes-256", AlgorithmFamily.SYMMETRIC_CIPHER, AlgorithmStatus.APPROVED)
                if legacy in {"3des", "triple-des", "des-ede3"}
                else _algorithm("sha3-256", AlgorithmFamily.HASH, AlgorithmStatus.APPROVED)
            )
            return PqcMapping(
                legacy_algorithm=legacy,
                replacement_algorithm=replacement,
                transition_kind="symmetric_hash",
                standard_references=(),
                urgency=urgency,
            )
        return None

    def recommendation_for(
        self,
        finding: CryptoFinding,
        *,
        policy: PqcRecommendationPolicy,
        provenance: Provenance,
        id_deriver: IdDeriver,
        mosca: MoscaEvaluation | None = None,
    ) -> Recommendation | None:
        mapping = self.map_finding(finding, mosca=mosca)
        if mapping is None:
            return None
        priority = {"critical": 100, "high": 90, "medium": 70, "low": 40}[mapping.urgency]
        payload = {
            "finding_id": finding.id,
            "replacement": mapping.replacement_algorithm,
            "policy": policy,
        }
        recommendation_id = id_deriver.derive(
            namespace="recommendation",
            tenant_id=finding.tenant_id,
            canonical_payload=canonical_json_bytes(payload),
        )
        standards = ", ".join(map(str, mapping.standard_references))
        standards = standards or "current NIST symmetric/hash guidance"
        return Recommendation(
            id=recommendation_id,
            tenant_id=finding.tenant_id,
            finding_id=finding.id,
            priority=priority,
            kind=RecommendationKind.MIGRATION,
            title=(
                f"Migrate {mapping.legacy_algorithm} to "
                f"{mapping.replacement_algorithm.canonical_name}"
            ),
            action=(
                f"Plan, test, and deploy a transition from {mapping.legacy_algorithm} to "
                f"{mapping.replacement_algorithm.canonical_name}. Standard references: {standards}."
            ),
            nist_references=tuple(mapping.standard_references),
            policy_profile_id=policy.profile_id,
            policy_profile_version=policy.profile_version,
            replacement_algorithm=Observation(
                state=ObservationState.OBSERVED,
                value=mapping.replacement_algorithm,
                basis_evidence_ids=finding.evidence_ids,
            ),
            created_at=provenance.observed_at,
            provenance=provenance,
        )
