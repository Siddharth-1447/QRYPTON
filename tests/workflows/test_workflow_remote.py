"""Remote-acquisition integration test (opt-in, never runs by default).

Uses the real public OpenSSL repository through the existing Source Code scan
path (GitHub tarball acquisition). Run explicitly with:
    QRYPTON_RUN_NETWORK_TESTS=1 python -m pytest tests/workflows/test_workflow_remote.py
"""

from __future__ import annotations

from typing import Any

from .conftest import (
    cbom_root,
    fresh_store,
    needs_network,
    root_properties,
    scan_payload,
    settle_scan,
    submit_scan,
)


@needs_network
def test_openssl_source_workflow(isolated_backend: dict[str, Any]) -> None:
    """TEST 1 (remote): openssl -> source scanner -> CBOM/risk/history."""
    scan_id = submit_scan(
        scan_payload(
            target_type="source_repo",
            repository="https://github.com/openssl/openssl",
            branch="master",
        )
    )
    assert settle_scan(scan_id, timeout_seconds=300) in ("COMPLETED", "PARTIAL")

    store = fresh_store(isolated_backend["db"])
    try:
        result = store.get_run(tenant_id=isolated_backend["tenant"], run_id=scan_id)  # type: ignore[arg-type]
        runs = store.list_runs(tenant_id=isolated_backend["tenant"])  # type: ignore[arg-type]
    finally:
        store.close()
    assert result is not None
    scanners = {entry.scanner_name for entry in result.scanner_results}
    assert scanners == {"qrypton-source"}, f"unexpected scanner set {scanners}"
    assert len(result.findings) >= 1, "openssl produced no findings"
    assert result.cbom, f"CBOM missing: {result.failures}"
    assert any(entry[1] == scan_id for entry in runs), "history missing openssl run"

    client = isolated_backend["client"]
    status = client.get(f"/api/v1/scans/{scan_id}").json()
    assert status["status"] in ("COMPLETED", "PARTIAL")
    cbom = client.get(f"/api/v1/scans/{scan_id}/cbom").content
    props = root_properties(cbom_root(cbom))
    tags = [props[k] for k in props if k == "org.qrypton.asset.tag"]
    assert "target:source_repo" in tags
    assert "source:git_repository" in tags
    assert "provider:github" in tags
    assert "openssl" in props.get("org.qrypton.asset.external-reference", "")
