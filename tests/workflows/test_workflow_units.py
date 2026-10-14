"""Unit tests: dispatch contracts, schema shape, and provider validation.

No network, no scans. These pin the five workflow contracts:
    SOURCE_CODE -> source scanner (qrypton-source)
    BINARY -> binary scanner (qrypton-binary)
    LIBRARY/PACKAGE -> library scanner (qrypton-library)
    CONTAINER -> container scanner (qrypton-container)
    CLOUD_KMS -> cloud/KMS scanner (qrypton-kms)
"""

from __future__ import annotations

import pytest

from qrypton.api.app import (
    SCANNER_ROUTING,
    ScanRequest,
    _is_docker_hub_reference,
    _is_kms_identifier,
)
from qrypton.application.config import QryptonConfig, build_services
from qrypton.contracts.enums import AssetKind, ScanTargetKind

# target_type -> (scan target kind, scanner name, asset kind, needs_repository_url)
WORKFLOWS: dict[str, tuple[ScanTargetKind, str, AssetKind, bool]] = {
    "source_repo": (ScanTargetKind.SOURCE_TREE, "qrypton-source", AssetKind.REPOSITORY, True),
    "source_archive": (ScanTargetKind.GIT_ARCHIVE, "qrypton-source", AssetKind.REPOSITORY, False),
    "binary": (ScanTargetKind.FILE, "qrypton-binary", AssetKind.BINARY, False),
    "dependency_manifest": (ScanTargetKind.FILE, "qrypton-library", AssetKind.OTHER, False),
    "container_image": (
        ScanTargetKind.OCI_IMAGE,
        "qrypton-container",
        AssetKind.CONTAINER_IMAGE,
        False,
    ),
    "cloud_kms": (ScanTargetKind.FILE, "qrypton-kms", AssetKind.OTHER, False),
}


@pytest.mark.parametrize("target_type,expected", list(WORKFLOWS.items()))
def test_routing_maps_each_workflow_to_its_own_scanner(
    target_type: str, expected: tuple[ScanTargetKind, str, AssetKind, bool]
) -> None:
    kind, scanner_name, asset_kind, _ = expected
    assert SCANNER_ROUTING[target_type] == (kind, scanner_name, asset_kind)


def test_routing_covers_every_workflow_exactly_once() -> None:
    assert set(SCANNER_ROUTING) == set(WORKFLOWS)


def test_every_routed_scanner_is_registered_with_a_matching_target(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = QryptonConfig(
        workspace_root=workspace,
        database_path=tmp_path / "units.sqlite3",
        id_secret=b"x" * 32,
    )
    services = build_services(config)
    try:
        scanners = list(services.scanners)
        for target_type, (kind, scanner_name, _asset_kind, _needs_repo) in WORKFLOWS.items():
            matches = [s for s in scanners if s.name == scanner_name]
            assert matches, f"{target_type}: scanner {scanner_name!r} not registered"
            assert any(
                kind == member or kind.value in getattr(member, "value", member)
                for scanner in matches
                for member in scanner.supported_targets
            ), f"{target_type}: no {scanner_name!r} accepts {kind.value!r}"
    finally:
        services.store.close()


def _base_kwargs(**overrides):  # type: ignore[no-untyped-def]
    kwargs = {
        "target_type": "binary",
        "repository": "",
        "environment": "production",
        "business_criticality": "critical",
        "data_lifetime": 7,
        "migration_time": 4,
        "crqc_horizon": 8,
    }
    kwargs.update(overrides)
    return kwargs


@pytest.mark.parametrize(
    "target_type", ["binary", "dependency_manifest", "container_image", "cloud_kms"]
)
def test_non_repository_workflows_require_no_repository_url(target_type: str) -> None:
    """Failure condition: the backend schema must not demand a repo URL here."""
    request = ScanRequest(**_base_kwargs(target_type=target_type))
    assert request.repository == ""
    assert request.target_type == target_type


def test_source_workflow_keeps_repository_and_branch() -> None:
    request = ScanRequest(
        **_base_kwargs(
            target_type="source_repo",
            repository="https://github.com/openssl/openssl",
            branch="master",
        )
    )
    assert request.repository == "https://github.com/openssl/openssl"
    assert request.branch == "master"


@pytest.mark.parametrize(
    "identifier",
    [
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "arn:aws:kms:eu-west-1:123456789012:alias/prod-key",
        "12345678-1234-1234-1234-123456789012",
        "alias/prod-key",
        "https://myvault.vault.azure.net/keys/mykey/abc123",
        "https://myvault.vault.azure.net/keys/mykey",
        "projects/p/locations/global/keyRings/r/cryptoKeys/k",
        "projects/p/locations/eu/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    ],
)
def test_kms_identifier_accepts_all_supported_providers(identifier: str) -> None:
    assert _is_kms_identifier(identifier)


@pytest.mark.parametrize(
    "identifier",
    [
        "",
        "not-a-key",
        "arn:aws:s3:::mybucket",
        "https://example.com/keys/x",
        "https://myvault.vault.azure.net/secrets/s",
        "projects/p/locations/global/keyRings/r",
        "key with spaces",
    ],
)
def test_kms_identifier_rejects_non_kms_values(identifier: str) -> None:
    assert not _is_kms_identifier(identifier)


@pytest.mark.parametrize("reference", ["nginx:latest", "company/service:1.4.2", "redis:7"])
def test_container_reference_accepts_docker_hub_style(reference: str) -> None:
    assert _is_docker_hub_reference(reference)


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "registry.enterprise.io/app:v1.0.4",
        "localhost:5000/app:latest",
        "https://example.com/image",
        "UPPERCASE/image:latest",
        "has space/image:1",
    ],
)
def test_container_reference_rejects_registries_and_garbage(reference: str) -> None:
    assert not _is_docker_hub_reference(reference)
