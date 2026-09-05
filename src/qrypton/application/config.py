"""Validated, fail-closed local configuration and dependency composition."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from pydantic import Field, HttpUrl, TypeAdapter

from qrypton.application.correlation import DeterministicCorrelationEngine
from qrypton.application.logging import JsonSafeLogger
from qrypton.application.orchestration import QryptonOrchestrator, QryptonServices
from qrypton.contracts.ids import HmacIdDeriver
from qrypton.contracts.models import DomainModel, Provenance
from qrypton.exporters.cyclonedx_1_6 import CycloneDx16CbomExporter
from qrypton.policies.pqc import PqcRecommendationPolicy, RiskPolicy
from qrypton.ports.scanners import ScannerPlugin
from qrypton.recommendations.engine import PqcRecommendationEngine
from qrypton.risk.mosca import MoscaParameters, MoscaRiskEngine
from qrypton.scanners.binary.normalization import BinaryNormalizer
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.source.normalization import SourceNormalizer
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.scanner import LocalSourceScanner
from qrypton.storage.sqlite import SqliteRunStore


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class QryptonConfig(DomainModel):
    workspace_root: Path
    database_path: Path
    id_secret: bytes = Field(min_length=32)
    max_concurrency: int = Field(default=1, ge=1, le=32)
    mosca_parameters: MoscaParameters = Field(
        default_factory=lambda: MoscaParameters(
            data_shelf_life_years=5, migration_time_years=2, quantum_threat_horizon_years=10
        )
    )


def build_services(config: QryptonConfig) -> QryptonServices:
    root = config.workspace_root.resolve(strict=True)
    deriver = HmacIdDeriver(config.id_secret)
    config_digest = f"sha256:{hashlib.sha256(b'qrypton-default-v1').hexdigest()}"
    provenance = Provenance(
        scanner_name="qrypton-recommendation",
        scanner_version="1.0.0",
        scanner_config_digest=config_digest,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    source = LocalSourceScanner(SourceScanPolicy(allowed_root=root))
    binary = LocalBinaryScanner(allowed_root=root)
    scanners = cast(tuple[ScannerPlugin, ...], (source, binary))
    return QryptonServices(
        scanners=scanners,
        evidence_normalizers=(SourceNormalizer(), BinaryNormalizer()),
        finding_normalizers=(SourceNormalizer(), BinaryNormalizer()),
        risk_engine=MoscaRiskEngine(parameters=config.mosca_parameters, id_deriver=deriver),
        recommendation_engine=PqcRecommendationEngine(id_deriver=deriver, provenance=provenance),
        cbom_exporter=CycloneDx16CbomExporter(),
        correlation_engine=DeterministicCorrelationEngine(),
        store=SqliteRunStore(config.database_path),
        id_deriver=deriver,
        clock=SystemClock(),
        logger=JsonSafeLogger(),
    )


def build_orchestrator(config: QryptonConfig) -> QryptonOrchestrator:
    return QryptonOrchestrator(build_services(config), max_concurrency=config.max_concurrency)


def default_risk_policy(reference_time: datetime) -> RiskPolicy:
    return RiskPolicy(
        profile_id="qrypton-default-risk", profile_version="1", published_at=reference_time
    )


def default_recommendation_policy(reference_time: datetime) -> PqcRecommendationPolicy:
    return PqcRecommendationPolicy(
        profile_id="qrypton-default-pqc",
        profile_version="1",
        published_at=reference_time,
        nist_references=(
            TypeAdapter(HttpUrl).validate_python("https://csrc.nist.gov/pubs/fips/203/final"),
        ),
    )
