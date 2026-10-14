"""Scan-engine contract: one normalized request, target-specific scanners.

Architecture under test:
    USER INPUT -> TARGET-SPECIFIC INPUT -> TARGET NORMALIZATION
    -> SCAN REQUEST -> TARGET-SPECIFIC SCANNER -> FINDINGS -> CBOM -> RISK/MOSCA.

Normalization must preserve the original target type, and each target family
must route to its own scanner:

    SOURCE_CODE -> source scanner (qrypton-source)
    BINARY -> binary scanner (qrypton-binary)
    LIBRARY -> library/dependency scanner (qrypton-library)
    CONTAINER -> container scanner (qrypton-container)
    CLOUD_KMS -> cloud/KMS scanner (qrypton-kms)
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from qrypton.api.app import SCANNER_ROUTING
from qrypton.application.config import QryptonConfig, build_services
from qrypton.contracts.enums import AssetKind, ScanTargetKind


def test_routing_preserves_every_target_family() -> None:
    assert SCANNER_ROUTING["source_repo"] == (
        ScanTargetKind.SOURCE_TREE,
        "qrypton-source",
        AssetKind.REPOSITORY,
    )
    assert SCANNER_ROUTING["source_archive"] == (
        ScanTargetKind.GIT_ARCHIVE,
        "qrypton-source",
        AssetKind.REPOSITORY,
    )
    assert SCANNER_ROUTING["binary"] == (
        ScanTargetKind.FILE,
        "qrypton-binary",
        AssetKind.BINARY,
    )
    assert SCANNER_ROUTING["dependency_manifest"] == (
        ScanTargetKind.FILE,
        "qrypton-library",
        AssetKind.OTHER,
    )
    assert SCANNER_ROUTING["container_image"] == (
        ScanTargetKind.OCI_IMAGE,
        "qrypton-container",
        AssetKind.CONTAINER_IMAGE,
    )
    assert SCANNER_ROUTING["cloud_kms"] == (
        ScanTargetKind.FILE,
        "qrypton-kms",
        AssetKind.OTHER,
    )


def test_services_register_every_routed_scanner(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    database = tmp_path / "contract.sqlite3"
    config = QryptonConfig(
        workspace_root=workspace,
        database_path=database,
        id_secret=b"x" * 32,
    )
    services = build_services(config)
    try:
        scanners = list(services.scanners)
        names = {scanner.name for scanner in scanners}
        for _target_type, (_kind, scanner_name, _asset_kind) in SCANNER_ROUTING.items():
            assert scanner_name in names, f"scanner {scanner_name!r} not registered"
        # Each routed scanner must accept the target kind it is routed for.
        # (Several scanners share the "qrypton-source" name, so match on any
        # scanner carrying the routed name.)
        for _target_type, (kind, scanner_name, _asset_kind) in SCANNER_ROUTING.items():
            assert any(
                kind in scanner.supported_targets
                for scanner in scanners
                if scanner.name == scanner_name
            ), f"no {scanner_name!r} scanner accepts {kind.value!r}"
    finally:
        with suppress(OSError):
            services.store.close()
