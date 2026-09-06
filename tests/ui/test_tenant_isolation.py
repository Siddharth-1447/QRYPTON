"""Unit tests verifying cross-tenant isolation in dashboard data access."""

from __future__ import annotations

from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider


def test_cross_tenant_isolation(populated_sqlite_store: tuple[SqliteRunStore, str, str]) -> None:
    store, tenant_a, run_a = populated_sqlite_store
    provider = SqliteDashboardDataProvider(store)
    tenant_b = f"tenant_{'b' * 52}"

    # Tenant B cannot access Tenant A's run view
    view_b = provider.get_run_view(tenant_id=tenant_b, run_id=run_a)
    assert view_b is None

    # Tenant B cannot access Tenant A's CBOM
    cbom_b = provider.get_persisted_cbom(tenant_id=tenant_b, run_id=run_a)
    assert cbom_b is None

    # Listing scoped to Tenant B returns empty
    runs_b = provider.list_runs(tenant_id=tenant_b)
    assert len(runs_b) == 0

    # Detail lookup with mismatched tenant returns None
    detail_b = provider.get_finding_detail(tenant_id=tenant_b, run_id=run_a, finding_id="finding_1")
    assert detail_b is None
