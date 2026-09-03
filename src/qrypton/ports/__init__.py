"""Dependency-inverted ports for future QRYPTON adapters."""

from qrypton.ports.exporters import CBOMExporter
from qrypton.ports.normalizers import EvidenceNormalizer, FindingNormalizer
from qrypton.ports.recommendations import RecommendationEngine
from qrypton.ports.risk import RiskEngine
from qrypton.ports.scanners import (
    BinaryObservation,
    BinaryScanner,
    ScanLimits,
    ScannerPlugin,
    ScanRequest,
    SourceObservation,
    SourceScanner,
)

__all__ = [
    "CBOMExporter",
    "EvidenceNormalizer",
    "FindingNormalizer",
    "RecommendationEngine",
    "RiskEngine",
    "ScanLimits",
    "BinaryObservation",
    "BinaryScanner",
    "ScanRequest",
    "ScannerPlugin",
    "SourceObservation",
    "SourceScanner",
]
