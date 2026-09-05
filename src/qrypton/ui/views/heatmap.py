"""Risk heatmap view: Mosca urgency × business criticality matrix."""

from __future__ import annotations

from typing import Literal

import streamlit as st

from qrypton.contracts.enums import RiskLevel
from qrypton.ui.contracts import DashboardRunView

CriticalityLabel = Literal["low", "medium", "high", "critical", "unclassified"]


def render_heatmap_view(view: DashboardRunView) -> None:
    """Render the Mosca urgency × business criticality heatmap from persisted cells."""
    st.subheader("Risk heatmap: Mosca urgency × business criticality")
    st.caption("Cell counts are aggregated from persisted assessments only.")
    st.info(
        "Business criticality is not stored on current runs. Findings remain in Unclassified."
    )
    cell_map = {
        (cell.mosca_urgency, cell.business_criticality): cell for cell in view.heatmap_cells
    }
    urgency_rows = (
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.INFORMATIONAL,
        RiskLevel.UNKNOWN,
    )
    crit_cols: tuple[CriticalityLabel, ...] = ("critical", "high", "medium", "low", "unclassified")
    col_labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "unclassified": "Unclassified",
    }
    grid_rows = []
    z_values: list[list[int]] = []
    for urgency in urgency_rows:
        row_dict: dict[str, str | int] = {"Mosca urgency": urgency.value}
        z_row: list[int] = []
        for column in crit_cols:
            cell = cell_map.get((urgency, column))
            count = cell.finding_count if cell else 0
            row_dict[col_labels[column]] = count
            z_row.append(count)
        grid_rows.append(row_dict)
        z_values.append(z_row)
    try:
        import plotly.graph_objects as go

        figure = go.Figure(
            data=go.Heatmap(
                z=z_values,
                x=[col_labels[column] for column in crit_cols],
                y=[urgency.value for urgency in urgency_rows],
                colorscale="Reds",
                hoverongaps=False,
            )
        )
        figure.update_layout(xaxis_title="Business criticality", yaxis_title="Mosca urgency")
        st.plotly_chart(figure, use_container_width=True)
    except ImportError:
        st.dataframe(grid_rows, use_container_width=True, hide_index=True)

    st.markdown("##### Inspect cell findings")
    s_col1, s_col2 = st.columns(2)
    with s_col1:
        sel_urgency = st.selectbox("Urgency", [item.value for item in urgency_rows], index=0)
    with s_col2:
        sel_crit = st.selectbox(
            "Criticality",
            crit_cols,
            format_func=lambda column: col_labels[column],
            index=4,
        )
    cell = cell_map.get((RiskLevel(sel_urgency), sel_crit))
    if cell and cell.finding_ids:
        st.dataframe([{"Finding ID": fid} for fid in cell.finding_ids], hide_index=True)
    else:
        st.write("No findings in selected cell.")
