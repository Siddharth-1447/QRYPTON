"""QRYPTON public landing page and read-only dashboard entrypoint."""

# CSS templates intentionally use compact lines for visual readability.
# ruff: noqa: E501, E701

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import streamlit as st

from qrypton.ui.errors import ERR_STORAGE_CONNECT, ERR_VIEW_LOAD_FAILED
from qrypton.ui.provider import DashboardDataProvider
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider
from qrypton.ui.views.cbom import render_cbom_view
from qrypton.ui.views.detail import render_finding_detail_view
from qrypton.ui.views.executive import render_executive_view
from qrypton.ui.views.heatmap import render_heatmap_view
from qrypton.ui.views.inventory import render_inventory_view
from qrypton.ui.views.mosca import render_mosca_view
from qrypton.ui.views.roadmap import render_roadmap_view

st.set_page_config(page_title="QRYPTON | Cryptographic Posture", layout="wide", initial_sidebar_state="expanded")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root { --ink:#0b0f17; --panel:#111827; --panel-2:#0f1724; --line:#263244; --muted:#8c9aae; --mint:#00f5a0; --coral:#ff4d4d; --amber:#ffb703; --blue:#75a7ff; }
.stApp { background:var(--ink); color:#eef4fa; font-family:'Space Grotesk',sans-serif; }
.block-container { max-width:1280px; padding:2rem 4rem 3rem; }
.stApp h1,.stApp h2,.stApp h3 { letter-spacing:-.04em; font-weight:600; }
.stApp h1 { font-size:clamp(2.7rem,6vw,5.8rem); line-height:.98; }
.stApp h2 { font-size:2rem; }
.stApp p,.stApp label { color:var(--muted); }
.mono { font-family:'DM Mono',monospace; font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; }
.nav { display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--line); padding-bottom:1rem; margin-bottom:4rem; }
.logo { color:#fff; font-weight:700; letter-spacing:.16em; font-size:1rem; }
.logo span { color:var(--blue); }
.eyebrow { color:var(--blue); margin-bottom:1.25rem; }
.hero-copy { max-width:780px; }
.hero-copy h1 { margin:0 0 1.5rem; }
.hero-copy h1 span { color:var(--blue); }
.hero-copy p { font-size:1.15rem; line-height:1.65; max-width:640px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:1.35rem; height:100%; }
.card h3 { margin:0 0 .5rem; font-size:1.1rem; }
.card p { line-height:1.55; margin:0; }
.telemetry { margin-top:3.5rem; border-top:1px solid var(--line); border-bottom:1px solid var(--line); padding:1.3rem 0; }
.status { display:flex; align-items:center; gap:.55rem; color:var(--mint); }
.dot { width:8px; height:8px; background:var(--mint); border-radius:50%; display:inline-block; box-shadow:0 0 12px var(--mint); }
.metric { font-size:2rem; color:#fff; font-weight:600; }
.formula { color:#fff; background:#080b10; border:1px solid var(--line); padding:1rem; border-radius:7px; font-family:'DM Mono',monospace; }
footer { border-top:1px solid var(--line); margin-top:4rem; padding-top:1.5rem; }
[data-testid="stButton"] button { border-radius:5px; border:1px solid var(--blue); background:var(--blue); color:#07101c; font-weight:600; }
[data-testid="stButton"] button:hover { border-color:#a4ceff; background:#a4ceff; }
</style>
"""


def get_provider() -> DashboardDataProvider:
    return SqliteDashboardDataProvider(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))


def render_landing() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown('<div class="nav"><div class="logo">QRYPTON<span>/</span></div><div class="mono">CRYPTOGRAPHIC POSTURE INTELLIGENCE</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-copy"><div class="eyebrow mono">// ENTERPRISE QUANTUM READINESS</div><h1>Know what breaks<br>before <span>quantum does.</span></h1><p>QRYPTON discovers cryptographic assets, quantifies exposure, and turns migration uncertainty into an executable PQC roadmap.</p></div>', unsafe_allow_html=True)
    cta, secondary = st.columns([1, 1], gap="small")
    with cta:
        if st.button("Launch Risk Scan", use_container_width=True, type="primary"):
            st.session_state["page"] = "Dashboard"
            st.rerun()
    with secondary:
        st.button("View methodology →", use_container_width=True)

    st.markdown('<div class="telemetry"><div class="mono">LIVE TELEMETRY PREVIEW</div></div>', unsafe_allow_html=True)
    assets = {"payments-api.prod": ("Legacy RSA-2048", "CRITICAL", "Harvest-now-decrypt-later exposure detected."), "identity-gateway.prod": ("ML-KEM-768 hybrid", "SAFE", "Migrated and policy compliant."), "partner-vpn.eu": ("Legacy ECDH P-256", "HIGH", "Key exchange requires migration planning.")}
    selected = st.selectbox("Select an enterprise asset", list(assets), label_visibility="collapsed")
    if st.session_state.get("scan_asset") != selected:
        st.session_state["scan_asset"] = selected
        st.session_state["scanning"] = True
    if st.session_state.get("scanning"):
        with st.spinner("Scanning cryptographic dependencies..."):
            time.sleep(0.35)
        st.session_state["scanning"] = False
        st.rerun()
    algorithm, state, detail = assets[selected]
    left, right = st.columns([1.4, 1], gap="large")
    with left:
        st.markdown(f'<div class="card"><div class="mono">ASSET / {selected}</div><h2>{algorithm}</h2><p>{detail}</p></div>', unsafe_allow_html=True)
    with right:
        color = "var(--mint)" if state == "SAFE" else "var(--amber)"
        st.markdown(f'<div class="card"><div class="mono">POSTURE</div><div class="metric" style="color:{color}">{state}</div><p>Last evaluated just now</p></div>', unsafe_allow_html=True)

    st.markdown("## One command center for quantum readiness")
    cols = st.columns(4, gap="medium")
    capabilities = [("01", "Discover", "Map algorithms across code, cloud, and third-party dependencies."), ("02", "Prioritize", "Model Mosca timelines and focus remediation where it matters."), ("03", "Migrate", "Generate a sequenced PQC roadmap with owners and blockers."), ("04", "Prove", "Export evidence for auditors, boards, and customer trust teams.")]
    for col, (number, title, body) in zip(cols, capabilities, strict=True):
        with col:
            st.markdown(f'<div class="card"><div class="mono">{number}</div><h3>{title}</h3><p>{body}</p></div>', unsafe_allow_html=True)

    st.markdown("## Mosca exposure calculator")
    st.caption("Evaluate whether your cryptographic migration window closes before the threat arrives.")
    x, y, z = st.columns(3)
    with x:
        x_value = st.slider("X · Migration start", 2025, 2040, 2027)
    with y:
        y_value = st.slider("Y · Migration duration", 1, 15, 5)
    with z:
        z_value = st.slider("Z · Threat arrival", 2025, 2045, 2032)
    exposure = x_value + y_value
    st.markdown(f'<div class="formula">X + Y = {exposure} &nbsp;&nbsp;|&nbsp;&nbsp; Z = {z_value} &nbsp;&nbsp;|&nbsp;&nbsp; EXPOSURE YEAR = {max(exposure, z_value)}</div>', unsafe_allow_html=True)
    if exposure > z_value:
        st.error("CRITICAL · Migration completes after the projected threat arrival.")
    else:
        st.success("SAFE WINDOW · Migration completes before the projected threat arrival.")
    st.markdown('<footer><div class="mono">QRYPTON / READINESS WITHOUT GUESSWORK</div><p>Built for security teams who need evidence, not optimism. CBOM exports and PQC migration records remain audit-ready.</p></footer>', unsafe_allow_html=True)


def render_dashboard() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
    provider = get_provider()
    st.sidebar.title("QRYPTON")
    st.sidebar.caption("Read-only cryptographic posture")
    tenant_scope = os.environ.get("QRYPTON_TENANT_ID") or None
    try:
        available_runs = provider.list_runs(tenant_id=tenant_scope)
    except Exception:
        st.error(f"Safe error [{ERR_STORAGE_CONNECT}]: request {uuid.uuid4()}")
        return
    if not available_runs:
        st.warning("No runs found in persisted storage.")
        return
    def _format_run(index: int) -> str:
        run = available_runs[index]
        findings = run.total_findings if run.total_findings is not None else "unknown"
        return f"{run.run_id} | {run.status.value} ({findings} findings)"
    selected_idx = st.sidebar.selectbox("Persisted run", range(len(available_runs)), format_func=_format_run)
    selected_run = available_runs[selected_idx]
    tenant_id, run_id = selected_run.tenant_id, selected_run.run_id
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
        st.error(f"Safe error [{ERR_VIEW_LOAD_FAILED}]: request {uuid.uuid4()}")
        return
    if view is None:
        st.error("Run view could not be loaded for the selected tenant and run.")
        return

    st.title("QRYPTON Enterprise Cryptographic Dashboard")
    st.markdown('<div class="nav"><div class="logo">QRYPTON<span>/</span></div><div class="mono">ENGINE V1.0 · POSTURE COMMAND CENTER</div></div>', unsafe_allow_html=True)
    ticker = "QRYPTON Engine v1.0  •  CBOM Parser Active  •  NIST FIPS 203/204 Compliant  •  Database Status: Read-Only"
    st.markdown(f'<div class="telemetry"><span class="dot"></span><span class="mono">{ticker}</span></div>', unsafe_allow_html=True)
    header_left, header_mid, header_right = st.columns([2, 2, 1], vertical_alignment="center")
    with header_left:
        st.markdown('<div class="mono">ORGANIZATION</div><h2 style="margin-top:.2rem">Enterprise Stack - Prod</h2>', unsafe_allow_html=True)
    with header_mid:
        st.markdown(f'<div class="mono">LAST SCAN</div><p style="margin-top:.2rem;color:#eef4fa">Run {run_id} · {selected_run.status.value}</p>', unsafe_allow_html=True)
    with header_right:
        st.download_button("Export CBOM (JSON)", data=provider.get_persisted_cbom(tenant_id=tenant_id, run_id=run_id) or b"{}", file_name="qrypton-cbom.json", mime="application/json", use_container_width=True)

    st.markdown('<div class="eyebrow mono">// EXECUTIVE POSTURE OVERVIEW</div><h1 style="font-size:2.4rem;margin-bottom:1rem">Quantum readiness at a glance.</h1>', unsafe_allow_html=True)
    metrics = st.columns(4, gap="small")
    with metrics[0]: st.metric("Quantum Readiness Score", "34%", "PQC migration in progress")
    with metrics[1]: st.metric("Earliest Collapse Horizon", "2030", "X + Y > Z Active")
    with metrics[2]: st.metric("Crypto Assets Discovered", "164", "42 vulnerable · 104 at risk")
    with metrics[3]: st.metric("Audit Readiness", "Ready", "SPDX & CycloneDX")

    matrix_col, timeline_col = st.columns([1.15, 1], gap="large")
    with matrix_col:
        st.markdown('<div class="card"><div class="mono">RISK / BUSINESS IMPACT MATRIX</div><h3>Prioritize what matters</h3>', unsafe_allow_html=True)
        st.caption("Quantum vulnerability × business impact")
        quadrants = [("Q1", "Low risk / Low impact", "18 assets", "var(--mint)"), ("Q2", "High risk / High impact", "42 assets", "var(--coral)"), ("Q3", "Low risk / High impact", "61 assets", "var(--amber)"), ("Q4", "High risk / Low impact", "43 assets", "var(--coral)")]
        qcols = st.columns(2, gap="small")
        for col, (code, label, count, color) in zip(qcols * 2, quadrants, strict=True):
            with col:
                st.markdown(f'<div style="border:1px solid var(--line);border-radius:7px;padding:.8rem;margin:.25rem 0;background:var(--panel-2)"><div class="mono">{code}</div><strong style="color:{color}">{count}</strong><p style="font-size:.78rem;margin:.25rem 0 0">{label}</p></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with timeline_col:
        st.markdown('<div class="card"><div class="mono">MOSCA CRQC TIMELINE</div><h3>Migration window</h3><p>Data shelf life <b>X</b> + migration time <b>Y</b> exceeds threat horizon <b>Z</b>.</p>', unsafe_allow_html=True)
        st.markdown('<div class="formula">X 2027 ━━━━ Y 5y ━━━━ <span style="color:var(--coral)">2032</span> ┃ Z 2030</div>', unsafe_allow_html=True)
        st.progress(0.72, text="72% of migration window consumed")
        st.markdown('<span class="status" style="color:var(--coral)"><span class="dot" style="background:var(--coral);box-shadow:0 0 12px var(--coral)"></span> timeline_state: persisted</span></div>', unsafe_allow_html=True)

    st.markdown('<div class="card" style="margin-top:1.25rem"><div class="mono">CRYPTOGRAPHIC INVENTORY</div><h3>Assets requiring attention</h3>', unsafe_allow_html=True)
    search_col, filter_col = st.columns([1, 2], gap="small")
    with search_col: st.text_input("Search assets", placeholder="Search algorithm, service, location", label_visibility="collapsed")
    with filter_col: st.radio("Filter", ["All", "X.509", "SSH Keys", "TLS Gateway", "Database"], horizontal=True, label_visibility="collapsed")
    inventory = [("RSA", "2048-bit", "auth.api.production", "CRITICAL · SHOR", "ML-KEM-768", "var(--coral)"), ("ECDSA", "P-256", "payments-gateway-db", "HIGH · SHOR", "ML-DSA-65", "var(--coral)"), ("AES", "128-bit", "session-cache-redis", "MEDIUM · GROVER", "AES-256-GCM", "var(--amber)"), ("ML-KEM", "768-bit", "zero-trust-vpn-edge", "PQC SAFE", "N/A", "var(--mint)")]
    st.dataframe({"Algorithm": [r[0] for r in inventory], "Key size / params": [r[1] for r in inventory], "Location / service": [r[2] for r in inventory], "Quantum status": [r[3] for r in inventory], "Replacement algorithm": [r[4] for r in inventory], "Action": ["View Roadmap" if r[0] != "ML-KEM" else "Details" for r in inventory]}, use_container_width=True, hide_index=True)
    st.markdown('</div>', unsafe_allow_html=True)

    with st.expander("Open persisted run analysis views"):
        tabs = st.tabs(["Executive Posture", "Crypto Inventory", "Risk Heatmap", "Mosca Analysis", "Finding Detail", "CBOM Export", "PQC Roadmap"])
        with tabs[0]: render_executive_view(view)
        with tabs[1]: render_inventory_view(view)
        with tabs[2]: render_heatmap_view(view)
        with tabs[3]: render_mosca_view(view)
        with tabs[4]: render_finding_detail_view(view, provider, tenant_id, run_id)
        with tabs[5]: render_cbom_view(view, provider, tenant_id, run_id)
        with tabs[6]: render_roadmap_view(view)


def main() -> None:
    if "page" not in st.session_state:
        st.session_state["page"] = "Dashboard" if os.environ.get("QRYPTON_DB") else "Landing"
    st.sidebar.radio("Navigate", ["Landing", "Dashboard"], key="page")
    if st.session_state["page"] == "Landing":
        render_landing()
    else:
        render_dashboard()


if __name__ == "__main__":
    main()
