"""Dependency-inverted ports for future QRYPTON adapters."""

from qrypton.ports.exporters import CBOMExporter
from qrypton.ports.normalizers import EvidenceNormalizer, FindingNormalizer
from qrypton.ports.recommendations import RecommendationEngine
from qrypton.ports.risk import RiskEngine
from qrypton.ports.scanners import ScanLimits, ScannerPlugin, ScanRequest

__all__ = [
    "CBOMExporter",
    "EvidenceNormalizer",
    "FindingNormalizer",
    "RecommendationEngine",
    "RiskEngine",
    "ScanLimits",
    "ScanRequest",
    "ScannerPlugin",
]
