"""Unit tests ensuring exact byte-fidelity of CBOM exports."""

from __future__ import annotations

from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider


def test_cbom_export_byte_for_byte_fidelity(
    populated_sqlite_store: tuple[SqliteRunStore, str, str],
) -> None:
    store, tenant_id, run_id = populated_sqlite_store
    provider = SqliteDashboardDataProvider(store)

    # Fetch directly from store
    direct_bytes = store.get_cbom(tenant_id=tenant_id, run_id=run_id)
    assert direct_bytes is not None

    # Fetch through dashboard provider
    provider_bytes = provider.get_persisted_cbom(tenant_id=tenant_id, run_id=run_id)
    assert provider_bytes is not None

    # Exact byte equality
    assert provider_bytes == direct_bytes
