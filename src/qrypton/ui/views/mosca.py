"""Mosca view: persisted X/Y/Z when present; otherwise an explicit unavailable state."""

from __future__ import annotations

import streamlit as st

from qrypton.ui.contracts import DashboardRunView


def render_mosca_view(view: DashboardRunView) -> None:
    """Render Mosca timelines from persisted evaluations only."""
    st.subheader("Mosca quantum threat timeline")
    st.caption("Values are copied from persisted Mosca evaluations. Nothing is recalculated here.")
    points = view.mosca_points
    if not points:
        st.info("No findings evaluated in this run.")
        return
    unavailable = [point for point in points if point.timeline_state == "unavailable"]
    if unavailable:
        st.warning(
            "Structured Mosca timelines are unavailable for one or more findings "
            "(migration required). X, Y, Z, X+Y, and margin are not inferred from rationale text."
        )
    table_data = [
        {
            "Finding ID": point.finding_id,
            "Urgency": point.urgency.value,
            "Exposure score": point.exposure_score if point.exposure_score is not None else "—",
            "X (data lifetime years)": point.x_data_lifetime_years
            if point.x_data_lifetime_years is not None
            else "unavailable",
            "Y (migration years)": point.y_migration_years
            if point.y_migration_years is not None
            else "unavailable",
            "Z (CRQC horizon years)": point.z_crqc_horizon_years
            if point.z_crqc_horizon_years is not None
            else "unavailable",
            "X+Y": point.required_security_years
            if point.required_security_years is not None
            else "unavailable",
            "Margin": (
                point.time_margin_years if point.time_margin_years is not None else "unavailable"
            ),
            "Timeline state": point.timeline_state,
        }
        for point in points
    ]
    st.dataframe(table_data, use_container_width=True, hide_index=True)
    persisted = [point for point in points if point.timeline_state == "persisted"]
    if not persisted:
        return
    try:
        import plotly.express as px

        figure = px.scatter(
            {
                "finding_id": [point.finding_id for point in persisted],
                "required_security_years": [point.required_security_years for point in persisted],
                "horizon_years": [point.z_crqc_horizon_years for point in persisted],
                "margin": [point.time_margin_years for point in persisted],
            },
            x="horizon_years",
            y="required_security_years",
            hover_name="finding_id",
            color="margin",
        )
        st.plotly_chart(figure, use_container_width=True)
    except ImportError:
        return
