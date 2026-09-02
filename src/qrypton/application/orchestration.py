"""Dependency container; orchestration behavior belongs to a later phase."""

from dataclasses import dataclass

from qrypton.ports.exporters import CBOMExporter
from qrypton.ports.normalizers import EvidenceNormalizer, FindingNormalizer
from qrypton.ports.recommendations import RecommendationEngine
from qrypton.ports.risk import RiskEngine
from qrypton.ports.scanners import ScannerPlugin


@dataclass(frozen=True, slots=True)
class QryptonServices:
    """Explicit dependency composition with no concrete adapters or UI imports."""

    scanners: tuple[ScannerPlugin, ...]
    evidence_normalizers: tuple[EvidenceNormalizer, ...]
    finding_normalizers: tuple[FindingNormalizer, ...]
    risk_engine: RiskEngine
    recommendation_engine: RecommendationEngine
    cbom_exporter: CBOMExporter
