"""Finding detail view: canonical finding, persisted risk, recommendations, provenance."""

from __future__ import annotations

import streamlit as st

from qrypton.contracts.enums import ObservationState
from qrypton.ui.contracts import DashboardRunView
from qrypton.ui.provider import DashboardDataProvider


def render_finding_detail_view(
    view: DashboardRunView, provider: DashboardDataProvider, tenant_id: str, run_id: str
) -> None:
    """Render deep canonical details for a selected finding."""
    st.subheader("Finding inspection")
    st.caption(
        "Canonical finding, persisted risk assessment, recommendations, and safe provenance."
    )
    findings = view.inventory
    if not findings:
        st.info("No findings in this run.")
        return
    finding_ids = [item.finding_id for item in findings]
    current_selected = st.session_state.get("selected_finding_id", finding_ids[0])
    if current_selected not in finding_ids:
        current_selected = finding_ids[0]

    def _fmt(fid: str) -> str:
        label = next(
            (item.algorithm_name or item.category for item in findings if item.finding_id == fid),
            "",
        )
        return f"{fid} ({label})"

    selected_id = st.selectbox(
        "Select finding ID",
        finding_ids,
        index=finding_ids.index(current_selected),
        format_func=_fmt,
    )
    st.session_state["selected_finding_id"] = selected_id
    detail = provider.get_finding_detail(tenant_id=tenant_id, run_id=run_id, finding_id=selected_id)
    if detail is None:
        st.error("Finding detail is not available for the selected identifiers.")
        return
    finding = detail.finding
    st.markdown("### Canonical finding")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"**Finding ID:** `{finding.id}`")
        st.markdown(f"**Category:** `{finding.category}`")
    with col2:
        st.markdown(f"**Asset ID:** `{finding.asset_id}`")
        st.markdown(f"**Scan target ID:** `{finding.scan_target_id}`")
    with col3:
        st.markdown(f"**Confidence:** `{finding.confidence}`")
        st.markdown(f"**First observed:** `{finding.first_observed_at.isoformat()}`")
    if finding.algorithm.state == ObservationState.OBSERVED and finding.algorithm.value:
        algorithm = finding.algorithm.value
        a_col1, a_col2, a_col3, a_col4 = st.columns(4)
        with a_col1:
            st.metric("Canonical name", algorithm.canonical_name)
        with a_col2:
            st.metric("Family", algorithm.family.value)
        with a_col3:
            bits = algorithm.key_size_bits
            key_sz = bits.value if bits.state == ObservationState.OBSERVED else None
            st.metric("Key size bits", key_sz if key_sz is not None else "—")
        with a_col4:
            st.metric("Lifecycle", algorithm.lifecycle_status.value)

    st.markdown("### Persisted risk assessment")
    if detail.assessment:
        assessment = detail.assessment
        r_col1, r_col2, r_col3 = st.columns(3)
        with r_col1:
            st.metric("Risk level", assessment.level.value)
        with r_col2:
            score_val = (
                assessment.score.value
                if assessment.score.state == ObservationState.OBSERVED
                else None
            )
            st.metric("Risk score", score_val if score_val is not None else "—")
        with r_col3:
            st.metric("Engine", f"{assessment.engine_name} {assessment.engine_version}")
    else:
        st.info("No risk assessment recorded for this finding.")

    st.markdown("### Recommendations")
    if detail.recommendations:
        for index, rec in enumerate(detail.recommendations, 1):
            with st.expander(f"{index}. {rec.title} (priority {rec.priority})", expanded=True):
                st.markdown(f"**Action:** {rec.action}")
                st.markdown(f"**Kind:** `{rec.kind.value}`")
                if (
                    rec.replacement_algorithm.state == ObservationState.OBSERVED
                    and rec.replacement_algorithm.value
                ):
                    name = rec.replacement_algorithm.value.canonical_name
                    st.markdown(f"**Replacement algorithm:** `{name}`")
                for ref in rec.nist_references:
                    st.markdown(f"- {ref}")
    plan_row = next((row for row in view.roadmap if row.finding_id == selected_id), None)
    if plan_row is not None:
        st.markdown(f"**Crypto role:** `{plan_row.role or 'n/a'}`")
        st.markdown(f"**Hybrid mode:** `{plan_row.hybrid_mode or 'n/a'}`")
        targets = ", ".join(plan_row.target_algorithms) or "—"
        st.markdown(f"**Target algorithms:** {targets}")
        for blocker in plan_row.blocking_conditions:
            st.warning(blocker)

    st.markdown("### Safe evidence provenance")
    if detail.evidence_provenance:
        st.dataframe(
            [
                {
                    "Evidence ID": evidence.id,
                    "Kind": evidence.kind.value,
                    "Confidence": evidence.confidence,
                    "Scanner": evidence.provenance.scanner_name,
                    "Scanner version": evidence.provenance.scanner_version,
                    "Observed at": evidence.provenance.observed_at.isoformat(),
                }
                for evidence in detail.evidence_provenance
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.write("No evidence records linked to this finding.")
    if detail.failures:
        st.markdown("### Execution failures")
        for failure in detail.failures:
            scanner = failure.scanner_name or "n/a"
            st.error(f"stage=`{failure.stage}` code=`{failure.error_code}` scanner=`{scanner}`")
