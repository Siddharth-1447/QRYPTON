"""Crypto inventory view: sortable, filterable table of canonical findings."""

from __future__ import annotations

import streamlit as st

from qrypton.contracts.enums import AlgorithmFamily, RiskLevel
from qrypton.ui.contracts import DashboardFilters, DashboardRunView
from qrypton.ui.filtering import SortBy, filter_and_sort_inventory


def render_inventory_view(view: DashboardRunView) -> None:
    """Render the sortable and filterable crypto inventory table."""
    st.subheader("Cryptographic Asset Inventory")
    st.caption("Normalized inventory of discovered cryptographic findings from the selected run.")
    rows = view.inventory
    if not rows:
        st.info("No cryptographic findings recorded in this run.")
        return

    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        search = st.text_input("Search (ID or algorithm)", value="")
    with f_col2:
        categories = ["All", *sorted({row.category for row in rows})]
        cat_filter = st.selectbox("Category", categories, index=0)
    with f_col3:
        risk_options = ["All", *[level.value for level in RiskLevel]]
        risk_filter = st.selectbox("Risk level", risk_options, index=0)
    with f_col4:
        family_options = ["All", *[family.value for family in AlgorithmFamily]]
        family_filter = st.selectbox("Algorithm family", family_options, index=0)

    sort_labels: dict[str, SortBy] = {
        "Risk level (high to low)": "risk_level",
        "Risk score (high to low)": "risk_score",
        "Confidence (high to low)": "confidence",
        "Finding ID (ascending)": "finding_id",
    }
    sort_choice = st.selectbox("Sort order", list(sort_labels), index=0)
    conf_slider = st.slider(
        "Minimum confidence", min_value=0.0, max_value=1.0, value=0.0, step=0.05
    )
    filters = DashboardFilters(
        category=None if cat_filter == "All" else cat_filter,
        risk_level=None if risk_filter == "All" else RiskLevel(risk_filter),
        algorithm_family=None if family_filter == "All" else AlgorithmFamily(family_filter),
        min_confidence=conf_slider,
        search_query=search or None,
    )
    displayed_rows = filter_and_sort_inventory(rows, filters, sort_by=sort_labels[sort_choice])
    st.markdown(f"**Displaying {len(displayed_rows)} of {len(rows)} findings**")
    table_data = [
        {
            "Finding ID": row.finding_id,
            "Category": row.category,
            "Algorithm": row.algorithm_name or "—",
            "Family": row.algorithm_family or "—",
            "Key size bits": row.key_size_bits if row.key_size_bits is not None else "—",
            "Lifecycle": row.lifecycle_status or "—",
            "Risk level": row.risk_level.value,
            "Score": row.risk_score if row.risk_score is not None else "—",
            "Confidence": row.confidence,
            "Evidence count": row.evidence_count,
        }
        for row in displayed_rows
    ]
    st.dataframe(table_data, use_container_width=True, hide_index=True)
    st.markdown("##### Inspect finding details")
    options = [row.finding_id for row in displayed_rows]
    if not options:
        return

    def _fmt_opt(fid: str) -> str:
        name = next(
            (row.algorithm_name or row.category for row in displayed_rows if row.finding_id == fid),
            "",
        )
        return f"{fid} ({name})"

    selected_id = st.selectbox("Select a finding ID", options, format_func=_fmt_opt)
    if st.button("Open finding detail"):
        st.session_state["selected_finding_id"] = selected_id
        st.session_state["active_tab"] = "Finding Detail"
        st.rerun()
