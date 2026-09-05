"""Streamlit entrypoint for the QRYPTON read-only dashboard."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import streamlit as st

from qrypton.ui.errors import ERR_VIEW_LOAD_FAILED
from qrypton.ui.mock_provider import MockDashboardDataProvider
from qrypton.ui.provider import DashboardDataProvider
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from qrypton.ui.views.cbom import render_cbom_view
from qrypton.ui.views.detail import render_finding_detail_view
from qrypton.ui.views.executive import render_executive_view
from qrypton.ui.views.heatmap import render_heatmap_view
from qrypton.ui.views.inventory import render_inventory_view
from qrypton.ui.views.mosca import render_mosca_view
from qrypton.ui.views.roadmap import render_roadmap_view

st.set_page_config(
    page_title="QRYPTON Cryptographic Posture Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)


def get_provider(tenant_id: str | None = None) -> DashboardDataProvider:
    """Composition root: bind SQLite provider if database has runs, otherwise fallback to Mock."""
    candidates: list[Path] = []
    env_db = os.environ.get("QRYPTON_DB")
    if env_db:
        candidates.append(Path(env_db))
    candidates.extend([Path("qrypton.db"), Path("qrypton.sqlite3"), Path("qrypton_demo.db")])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                sqlite_provider = SqliteDashboardDataProvider(candidate)
                runs = sqlite_provider.list_runs(tenant_id=tenant_id)
                if runs:
                    return sqlite_provider
            except Exception:
                continue

    return MockDashboardDataProvider()


def main() -> None:
    st.title("QRYPTON Enterprise Cryptographic Dashboard")
    tenant_scope = os.environ.get("QRYPTON_TENANT_ID") or None
    provider = get_provider(tenant_id=tenant_scope)
    st.sidebar.title("Scope")
    st.sidebar.caption("Read-only presentation")
    if isinstance(provider, MockDashboardDataProvider):
        st.sidebar.info("Demo Mode: Displaying sample cryptographic posture data.")

    try:
        available_runs = provider.list_runs(tenant_id=tenant_scope)
    except Exception:
        provider = MockDashboardDataProvider()
        available_runs = provider.list_runs(tenant_id=tenant_scope)

    if not available_runs and not isinstance(provider, MockDashboardDataProvider):
        provider = MockDashboardDataProvider()
        available_runs = provider.list_runs(tenant_id=tenant_scope)

    if not available_runs:
        st.warning("No runs found in persisted storage.")
        return

    def _format_run(index: int) -> str:
        run = available_runs[index]
        findings = run.total_findings if run.total_findings is not None else "unknown"
        return f"{run.run_id} | {run.status.value} ({findings} findings)"

    selected_idx = st.sidebar.selectbox(
        "Persisted run", range(len(available_runs)), format_func=_format_run
    )
    selected_run = available_runs[selected_idx]
    tenant_id = selected_run.tenant_id
    run_id = selected_run.run_id
    st.sidebar.markdown(f"**Tenant:** `{tenant_id}`")
    st.sidebar.markdown(f"**Run ID:** `{run_id}`")
    st.sidebar.markdown(f"**Status:** `{selected_run.status.value}`")
    st.sidebar.markdown(f"**Record:** `{selected_run.record_state}`")
    if selected_run.record_state == "metadata_only":
        st.error("This run has no persisted result payload (migration required).")
        return
    try:
        view = provider.get_run_view(tenant_id=tenant_id, run_id=run_id)
    except Exception:
        request_id = str(uuid.uuid4())
        st.error(f"Safe error [{ERR_VIEW_LOAD_FAILED}]: request {request_id}")
        return
    if view is None:
        st.error("Run view could not be loaded for the selected tenant and run.")
        return
    tabs = st.tabs(
        [
            "Executive Posture",
            "Crypto Inventory",
            "Risk Heatmap",
            "Mosca Analysis",
            "Finding Detail",
            "CBOM Export",
            "PQC Roadmap",
        ]
    )
    with tabs[0]:
        render_executive_view(view)
    with tabs[1]:
        render_inventory_view(view)
    with tabs[2]:
        render_heatmap_view(view)
    with tabs[3]:
        render_mosca_view(view)
    with tabs[4]:
        render_finding_detail_view(view, provider, tenant_id, run_id)
    with tabs[5]:
        render_cbom_view(view, provider, tenant_id, run_id)
    with tabs[6]:
        render_roadmap_view(view)


if __name__ == "__main__":
    main()
