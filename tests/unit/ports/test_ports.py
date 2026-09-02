from __future__ import annotations

from qrypton.application.orchestration import QryptonServices
from qrypton.ports import (
    CBOMExporter,
    EvidenceNormalizer,
    FindingNormalizer,
    RecommendationEngine,
    RiskEngine,
    ScannerPlugin,
)


def test_application_container_has_only_port_dependencies() -> None:
    annotations = QryptonServices.__annotations__
    assert set(annotations) == {
        "scanners",
        "evidence_normalizers",
        "finding_normalizers",
        "risk_engine",
        "recommendation_engine",
        "cbom_exporter",
    }
    ports = (
        CBOMExporter,
        EvidenceNormalizer,
        FindingNormalizer,
        RecommendationEngine,
        RiskEngine,
        ScannerPlugin,
    )
    assert all(port.__module__.startswith("qrypton.ports") for port in ports)
