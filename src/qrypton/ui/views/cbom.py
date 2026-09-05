"""CBOM export view: download exact persisted CycloneDX bytes."""

from __future__ import annotations

import json

import streamlit as st

from qrypton.ui.contracts import DashboardRunView
from qrypton.ui.provider import DashboardDataProvider


def render_cbom_view(
    view: DashboardRunView, provider: DashboardDataProvider, tenant_id: str, run_id: str
) -> None:
    """Render CBOM export delivering exact persisted bytes."""
    st.subheader("CycloneDX 1.6 CBOM")
    st.caption("Exact artifact persisted at scan time. The dashboard does not regenerate CBOM.")
    cbom_bytes = provider.get_persisted_cbom(tenant_id=tenant_id, run_id=run_id)
    if cbom_bytes is None:
        st.warning("No persisted CBOM is available for this tenant and run.")
        return
    st.markdown(f"**Tenant ID:** `{tenant_id}`")
    st.markdown(f"**Run ID:** `{run_id}`")
    st.markdown(f"**Size (bytes):** `{len(cbom_bytes)}`")
    if view.cbom_digest:
        st.markdown(f"**Digest:** `{view.cbom_digest}`")
    st.download_button(
        label="Download persisted CBOM",
        data=cbom_bytes,
        file_name=f"cbom_{run_id}.cdx.json",
        mime="application/json",
        use_container_width=True,
    )
    with st.expander("Preview persisted CBOM JSON", expanded=False):
        try:
            st.json(json.loads(cbom_bytes.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            st.write("Persisted CBOM is not valid UTF-8 JSON; download the stored bytes.")
