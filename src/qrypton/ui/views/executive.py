"""Executive posture view: measured metrics and policy gate status."""

from __future__ import annotations

import streamlit as st

from qrypton.ui.contracts import DashboardRunView


def render_executive_view(view: DashboardRunView) -> None:
    """Render high-level measured posture metrics from persisted run data."""
    st.subheader("Executive Cryptographic Posture")
    st.caption("Measured posture based strictly on persisted run evidence and risk evaluations.")
    posture = view.posture
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Cryptographic Findings", posture.total_findings)
    with col2:
        high_crit = posture.critical_findings_count + posture.high_findings_count
        st.metric(
            "High & Critical Findings",
            high_crit,
            help=(
                f"Critical: {posture.critical_findings_count}, High: {posture.high_findings_count}"
            ),
        )
    with col3:
        st.metric("Distinct Asset IDs", posture.unique_asset_ids)
    with col4:
        st.metric("Run Status", posture.run_status.value.upper())

    st.divider()
    row2_col1, row2_col2 = st.columns(2)
    with row2_col1:
        st.markdown("#### Findings by persisted risk level")
        breakdown_cols = st.columns(6)
        with breakdown_cols[0]:
            st.metric("Critical", posture.critical_findings_count)
        with breakdown_cols[1]:
            st.metric("High", posture.high_findings_count)
        with breakdown_cols[2]:
            st.metric("Medium", posture.medium_findings_count)
        with breakdown_cols[3]:
            st.metric("Low", posture.low_findings_count)
        with breakdown_cols[4]:
            st.metric("Info", posture.informational_findings_count)
        with breakdown_cols[5]:
            st.metric("Unassessed", posture.unassessed_findings_count)
    with row2_col2:
        st.markdown("#### Policy gate and execution health")
        if posture.policy_passed:
            st.success("Policy gate: passed")
        else:
            st.error("Policy gate: failed")
            for violation in posture.policy_violations:
                st.markdown(f"- `{violation}`")
        st.metric("Failed scanners", posture.scanner_failed_count)
        st.metric("Partial scanners", posture.scanner_partial_count)
