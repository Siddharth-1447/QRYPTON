"""CLI version output reflects the installed package and component declarations."""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version as package_version

from qrypton.exporters.cyclonedx_1_6 import CycloneDx16CbomExporter
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.extended import (
    CloudKmsScanner,
    ContainerImageScanner,
    ExtendedStaticScanner,
    LibraryDependencyScanner,
)
from qrypton.scanners.source.scanner import LocalSourceScanner


def test_cli_version_lists_package_and_components() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "qrypton.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert f"qrypton {package_version('qrypton')}" in result.stdout
    components = (
        ("source scanner", LocalSourceScanner),
        ("binary scanner", LocalBinaryScanner),
        ("extended static adapter", ExtendedStaticScanner),
        ("library dependency adapter", LibraryDependencyScanner),
        ("container image adapter", ContainerImageScanner),
        ("cloud KMS adapter", CloudKmsScanner),
        ("CBOM exporter", CycloneDx16CbomExporter),
    )
    for label, component in components:
        assert f"{label} ({component.name}) {component.version}" in result.stdout
