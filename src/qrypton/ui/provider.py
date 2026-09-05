"""Small, read-only DashboardDataProvider interface consumed by Streamlit."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from qrypton.ui.contracts import DashboardRunSummary, DashboardRunView, FindingDetail


class DashboardDataProvider(Protocol):
    """Read-only data access port decoupled from presentation."""

    def list_runs(self, *, tenant_id: str | None = None) -> Sequence[DashboardRunSummary]:
        """List persisted runs, optionally filtered by tenant_id."""
        ...

    def get_run_view(self, *, tenant_id: str, run_id: str) -> DashboardRunView | None:
        """Fetch pre-aggregated, read-only view model for a run."""
        ...

    def get_finding_detail(
        self, *, tenant_id: str, run_id: str, finding_id: str
    ) -> FindingDetail | None:
        """Fetch canonical finding details, risk assessment, recommendations, and evidence."""
        ...

    def get_persisted_cbom(self, *, tenant_id: str, run_id: str) -> bytes | None:
        """Return exact persisted CBOM bytes without modification or regeneration."""
        ...
