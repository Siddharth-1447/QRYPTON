# type: ignore
"""FastAPI backend application for QRYPTON cryptographic posture and inventory."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from qrypton.ui.contracts import (
    DashboardRunView,
    ExecutivePosture,
    FindingDetail,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
)
from qrypton.ui.mock_provider import MockDashboardDataProvider
from qrypton.ui.provider import DashboardDataProvider
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider

app = FastAPI(title="QRYPTON Cryptographic Inventory API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_provider(tenant_id: str | None = None) -> DashboardDataProvider:
    """Try SqliteDashboardDataProvider and fall back to MockDashboardDataProvider."""
    candidates: list[Path] = []
    env_db = os.environ.get("QRYPTON_DB")
    if env_db:
        candidates.append(Path(env_db))
    else:
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


def _resolve_view(
    provider: DashboardDataProvider,
    tenant_id: str | None = None,
    run_id: str | None = None,
) -> DashboardRunView:
    try:
        runs = provider.list_runs(tenant_id=tenant_id)
    except Exception:
        provider = MockDashboardDataProvider()
        runs = provider.list_runs(tenant_id=tenant_id)

    if not runs and not isinstance(provider, MockDashboardDataProvider):
        provider = MockDashboardDataProvider()
        runs = provider.list_runs(tenant_id=tenant_id)

    if not runs:
        raise HTTPException(status_code=404, detail="No cryptographic runs found")

    if run_id is not None:
        target_run = next((r for r in runs if r.run_id == run_id), None)
        if target_run is None:
            tid = tenant_id or runs[0].tenant_id
            view = provider.get_run_view(tenant_id=tid, run_id=run_id)
            if view is not None:
                return view
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        selected_tenant = target_run.tenant_id
        selected_run = target_run.run_id
    else:
        selected_tenant = runs[0].tenant_id
        selected_run = runs[0].run_id

    view = provider.get_run_view(tenant_id=selected_tenant, run_id=selected_run)
    if view is None:
        raise HTTPException(status_code=404, detail="Run view could not be loaded")
    return view


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    """Healthcheck endpoint returning system operational status."""
    return {"status": "ok", "service": "QRYPTON Cryptographic Inventory API"}


@app.get("/api/v1/inventory")
def get_inventory(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[InventoryRow]:
    """Retrieve cryptographic findings inventory for the active or requested run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.inventory)


@app.get("/api/v1/posture")
def get_posture(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> ExecutivePosture:
    """Retrieve executive cryptographic posture metrics for the active or requested run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return view.posture


class ScanRequest(BaseModel):
    target_type: str
    repository: str
    environment: str
    business_criticality: str
    data_lifetime: float
    migration_time: float
    crqc_horizon: float


@app.post("/api/v1/scans")
def create_scan(request: ScanRequest) -> dict[str, Any]:
    """Runs/simulates the scan and saves context."""
    return {
        "status": "accepted",
        "message": "Scan simulated/started",
        "request": request.model_dump(),
    }


@app.get("/api/v1/findings/{finding_id}")
def get_finding(
    finding_id: str,
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> FindingDetail:
    """Returns finding evidence details."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    detail = provider.get_finding_detail(
        tenant_id=view.summary.tenant_id, run_id=view.summary.run_id, finding_id=finding_id
    )
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return detail


@app.get("/api/v1/mosca/eval")
def get_mosca_eval(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[MoscaPoint]:
    """Calculates Mosca timeline exposure."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.mosca_points)


@app.get("/api/v1/heatmap")
def get_heatmap(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[RiskHeatmapCell]:
    """Returns finding counts categorized into a matrix."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.heatmap_cells)


@app.get("/api/v1/roadmap")
def get_roadmap(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[RoadmapRow]:
    """Returns an ordered PQC Migration Roadmap."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.roadmap)
