"""Dependency-inverted ports for future QRYPTON adapters."""

from qrypton.ports.correlation import CorrelationEngine
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
from qrypton.ports.storage import RunStore

__all__ = [
    "CBOMExporter",
    "CorrelationEngine",
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
    "RunStore",
]
