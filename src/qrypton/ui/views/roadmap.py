"""PQC migration roadmap: stored priority, targets, hybrid mode, blockers."""

from __future__ import annotations

import streamlit as st

from qrypton.ui.contracts import DashboardRunView


def render_roadmap_view(view: DashboardRunView) -> None:
    """Render the PQC migration roadmap in persisted priority order."""
    st.subheader("PQC migration roadmap")
    st.caption("Items keep the stored recommendation priority. The UI does not re-rank them.")
    roadmap = view.roadmap
    if not roadmap:
        st.info("No PQC migration recommendations recorded for this run.")
        return
    table_data = [
        {
            "Priority": row.priority,
            "Finding ID": row.finding_id,
            "Action": row.action,
            "Role": row.role or "—",
            "Target algorithms": ", ".join(row.target_algorithms) if row.target_algorithms else "—",
            "Hybrid mode": row.hybrid_mode or "—",
            "Blockers": ", ".join(row.blocking_conditions) if row.blocking_conditions else "—",
            "Standards": ", ".join(str(item) for item in row.standards_references) or "—",
        }
        for row in roadmap
    ]
    st.dataframe(table_data, use_container_width=True, hide_index=True)
    for row in roadmap:
        with st.expander(f"Priority {row.priority}: {row.finding_id}", expanded=False):
            st.markdown(f"**Action:** {row.action}")
            st.markdown(f"**Role:** `{row.role or 'n/a'}`")
            targets = ", ".join(row.target_algorithms) if row.target_algorithms else "n/a"
            st.markdown(f"**Target algorithms:** `{targets}`")
            st.markdown(f"**Hybrid mode:** `{row.hybrid_mode or 'n/a'}`")
            for blocker in row.blocking_conditions:
                st.warning(blocker)
            for reference in row.standards_references:
                st.markdown(f"- {reference}")
