"""Project canonical evidence and business observations without inventing missing facts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from qrypton.contracts.crypto_taxonomy import classify_finding, is_post_quantum_finding
from qrypton.contracts.enums import ObservationState, RiskLevel
from qrypton.contracts.models import (
    BusinessContext,
    CryptoFinding,
    Evidence,
    Observation,
    PersistedMoscaEvaluation,
)
from qrypton.ui.contracts import InventoryEvidenceRow, InventoryObservation

if TYPE_CHECKING:
    from qrypton.ports.storage import PersistedRun


def display_observation(observation: Observation[Any]) -> InventoryObservation:
    value = observation.value
    if value is not None and hasattr(value, "value"):
        value = value.value
    return InventoryObservation(
        state=observation.state, value=value, rationale=observation.rationale,
        evidence_ids=observation.basis_evidence_ids,
    )


def detail_context(context: BusinessContext | None) -> dict[str, InventoryObservation]:
    """Expose persisted business inputs; never estimate missing scoring inputs."""
    if context is None:
        return {}
    result = {
        "exposure": display_observation(context.internet_exposed),
        "data_sensitivity": display_observation(context.data_classification),
        "business_criticality": display_observation(context.criticality),
    }
    complexity = context.migration_complexity
    result["migration_complexity"] = InventoryObservation(
        state=ObservationState.OBSERVED if complexity is not None else ObservationState.UNKNOWN,
        value=complexity,
        evidence_ids=(context.id,) if complexity is not None else (),
    )
    return result


def inventory_context(
    finding: CryptoFinding, run: PersistedRun, evidence_by_id: Mapping[str, Evidence],
    mosca: PersistedMoscaEvaluation | None,
) -> dict[str, Any]:
    context = run.finding_business_contexts.get(finding.id, run.business_context)
    observations: dict[str, InventoryObservation] = {}
    linked = [evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id]
    observations["algorithm"] = InventoryObservation(
        state=finding.algorithm.state,
        value=finding.algorithm.value.canonical_name if finding.algorithm.value else None,
        evidence_ids=finding.algorithm.basis_evidence_ids,
        rationale=finding.algorithm.rationale,
    )
    algorithm = finding.algorithm.value
    key_size = algorithm.key_size_bits if algorithm else None
    if (key_size is None or key_size.value is None) and finding.key_material.value:
        key_size = finding.key_material.value.size_bits
    observations["key_size"] = (
        display_observation(key_size) if key_size is not None else InventoryObservation()
    )
    observations["function"] = InventoryObservation(
        state=ObservationState.OBSERVED if finding.crypto_role else ObservationState.NOT_OBSERVED,
        value=finding.crypto_role, evidence_ids=finding.evidence_ids if finding.crypto_role else (),
    )
    mode = algorithm.parameters.get("mode") if algorithm else None
    mode_ids = finding.algorithm.basis_evidence_ids if mode is not None else ()
    if mode is None:
        modes = [(e.attributes.get("mode"), e.id) for e in linked
                 if isinstance(e.attributes.get("mode"), str)]
        if modes:
            mode = ", ".join(sorted({str(m[0]) for m in modes}))
            mode_ids = tuple(m[1] for m in modes)
    observations["mode"] = InventoryObservation(
        state=ObservationState.OBSERVED if mode is not None else ObservationState.NOT_OBSERVED,
        value=str(mode) if mode is not None else None, evidence_ids=mode_ids,
    )
    observations["library"] = (
        display_observation(finding.library.value.name) if finding.library.value else
        InventoryObservation(
            state=finding.library.state, rationale=finding.library.rationale,
            evidence_ids=finding.library.basis_evidence_ids,
        )
    )
    observations["exposure"] = (
        display_observation(context.internet_exposed) if context else InventoryObservation()
    )
    observations["criticality"] = (
        display_observation(context.criticality) if context else InventoryObservation()
    )
    observations["data_sensitivity"] = (
        display_observation(context.data_classification) if context else InventoryObservation()
    )
    lifetime = finding.mosca_x_data_lifetime_years
    lifetime_ids = finding.evidence_ids if lifetime is not None else ()
    if lifetime is None and context is not None:
        lifetime = context.mosca_x_data_lifetime_years
        lifetime_ids = (context.id,) if lifetime is not None else ()
    observations["data_lifetime"] = InventoryObservation(
        state=ObservationState.OBSERVED if lifetime is not None else ObservationState.UNKNOWN,
        value=lifetime, evidence_ids=lifetime_ids,
    )
    # The evidence index is already shared across the run. Rebuilding its full
    # key set for every finding made large inventory projections quadratic.
    context_id = context.id if context is not None else None
    for key, observation in observations.items():
        if observation.state == ObservationState.CONFIRMED_ABSENT and (
            not observation.evidence_ids or not all(
                evidence_id in evidence_by_id or evidence_id == context_id
                for evidence_id in observation.evidence_ids
            )
        ):
            observations[key] = InventoryObservation(
                rationale="The referenced absence evidence was not found in this scan."
            )
    evidence_rows = []
    for evidence in linked:
        location = evidence.location
        parts = [part for part in (location.relative_path, location.symbol) if part]
        if location.line_start is not None:
            parts.append(f"line {location.line_start}")
        if location.byte_start is not None:
            parts.append(f"byte {location.byte_start}")
        if location.image_layer_digest:
            parts.append(f"layer {location.image_layer_digest}")
        evidence_rows.append(InventoryEvidenceRow(
            id=evidence.id, kind=evidence.kind.value, surface=evidence.surface.value,
            location=" · ".join(parts) or None, confidence=evidence.confidence,
            excerpt=evidence.excerpt,
        ))
    dimensions = classify_finding(finding)
    quantum = (
        "resistant" if is_post_quantum_finding(finding)
        else "vulnerable" if dimensions.quantum_risk == RiskLevel.HIGH
        else "quantum_relevant" if dimensions.quantum_risk == RiskLevel.MEDIUM else "unknown"
    )
    artifact_type = next((tag.removeprefix("target:") for tag in run.asset.tags
                          if tag.startswith("target:")), None) if run.asset else None
    missing_context = context is None or any(
        observations[key].state != ObservationState.OBSERVED or observations[key].value is None
        for key in ("criticality", "exposure", "data_lifetime")
    ) or observations["criticality"].value == "unclassified"
    return {
        "asset_id": finding.asset_id,
        "application": run.asset.name if run.asset and run.asset.id == finding.asset_id else None,
        "artifact_type": artifact_type,
        "environment": context.environment if context else None,
        "observations": observations, "evidence_rows": tuple(evidence_rows),
        "source_surfaces": tuple(sorted({e.surface.value for e in linked})),
        "quantum_status": quantum, "quantum_rationale": dimensions.rationale[-1],
        "timeline_overflow": (
            mosca.time_margin_years < 0 if mosca and mosca.mosca_applicable == "yes"
            and mosca.time_margin_years is not None else None
        ),
        "mosca_urgency": mosca.urgency if mosca else "unknown",
        "missing_business_context": missing_context,
        "assigned_owner": context.owner_reference.value if context else None,
    }
