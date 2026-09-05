"""Unit tests for crypto inventory filtering and deterministic sorting."""

from __future__ import annotations

from datetime import UTC, datetime

from qrypton.contracts.enums import AlgorithmFamily, RiskLevel
from qrypton.ui.contracts import DashboardFilters, InventoryRow
from qrypton.ui.filtering import filter_and_sort_inventory


def create_row(
    fid: str,
    cat: str,
    alg: str,
    fam: str,
    lvl: RiskLevel,
    score: float,
    conf: float,
) -> InventoryRow:
    return InventoryRow(
        finding_id=fid,
        category=cat,
        algorithm_name=alg,
        algorithm_family=fam,
        key_size_bits=1024,
        lifecycle_status="deprecated",
        risk_level=lvl,
        risk_score=score,
        confidence=conf,
        evidence_count=1,
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _rows() -> tuple[InventoryRow, ...]:
    return (
        create_row(
            "f1", "algorithm_use", "RSA", "asymmetric_encryption", RiskLevel.CRITICAL, 95.0, 0.95
        ),
        create_row("f2", "algorithm_use", "SHA-1", "hash", RiskLevel.HIGH, 75.0, 0.90),
        create_row("f3", "key_material", "AES", "symmetric_cipher", RiskLevel.LOW, 20.0, 0.80),
    )


def test_inventory_filters() -> None:
    rows = _rows()
    by_category = filter_and_sort_inventory(rows, DashboardFilters(category="key_material"))
    assert [row.finding_id for row in by_category] == ["f3"]
    by_risk = filter_and_sort_inventory(rows, DashboardFilters(risk_level=RiskLevel.CRITICAL))
    assert [row.finding_id for row in by_risk] == ["f1"]
    by_confidence = filter_and_sort_inventory(rows, DashboardFilters(min_confidence=0.92))
    assert [row.finding_id for row in by_confidence] == ["f1"]
    by_search = filter_and_sort_inventory(rows, DashboardFilters(search_query="SHA"))
    assert [row.finding_id for row in by_search] == ["f2"]
    by_family = filter_and_sort_inventory(
        rows, DashboardFilters(algorithm_family=AlgorithmFamily.HASH)
    )
    assert [row.finding_id for row in by_family] == ["f2"]


def test_inventory_deterministic_sorting() -> None:
    rows = (
        create_row("f_low", "algorithm_use", "AES", "symmetric", RiskLevel.LOW, 20.0, 0.80),
        create_row("f_crit", "algorithm_use", "RSA", "asymmetric", RiskLevel.CRITICAL, 95.0, 0.95),
        create_row("f_high", "algorithm_use", "SHA-1", "hash", RiskLevel.HIGH, 75.0, 0.90),
    )
    by_level = filter_and_sort_inventory(rows, DashboardFilters(), sort_by="risk_level")
    assert [row.finding_id for row in by_level] == ["f_crit", "f_high", "f_low"]
    by_score = filter_and_sort_inventory(rows, DashboardFilters(), sort_by="risk_score")
    assert [row.finding_id for row in by_score] == ["f_crit", "f_high", "f_low"]
    by_id = filter_and_sort_inventory(rows, DashboardFilters(), sort_by="finding_id")
    assert [row.finding_id for row in by_id] == ["f_crit", "f_high", "f_low"]
    by_confidence = filter_and_sort_inventory(rows, DashboardFilters(), sort_by="confidence")
    assert [row.finding_id for row in by_confidence] == ["f_crit", "f_high", "f_low"]
