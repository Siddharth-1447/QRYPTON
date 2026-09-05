"""Pure inventory filter and sort helpers with no Streamlit or engine imports."""

from __future__ import annotations

from typing import Literal

from qrypton.contracts.enums import RiskLevel
from qrypton.ui.contracts import DashboardFilters, InventoryRow

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
    RiskLevel.INFORMATIONAL: 4,
    RiskLevel.UNKNOWN: 5,
}

SortBy = Literal["risk_level", "risk_score", "confidence", "finding_id"]


def filter_and_sort_inventory(
    rows: tuple[InventoryRow, ...],
    filters: DashboardFilters,
    *,
    sort_by: SortBy = "risk_level",
) -> list[InventoryRow]:
    """Deterministic filtering and sorting of inventory rows."""
    filtered: list[InventoryRow] = []
    query = filters.search_query.strip().casefold() if filters.search_query else None
    for row in rows:
        if row.confidence < filters.min_confidence:
            continue
        if filters.category is not None and row.category != filters.category:
            continue
        if filters.risk_level is not None and row.risk_level is not filters.risk_level:
            continue
        if (
            filters.algorithm_family is not None
            and (row.algorithm_family or "") != filters.algorithm_family.value
        ):
            continue
        if query:
            match_id = query in row.finding_id.casefold()
            match_alg = query in (row.algorithm_name or "").casefold()
            match_fam = query in (row.algorithm_family or "").casefold()
            if not (match_id or match_alg or match_fam):
                continue
        filtered.append(row)

    if sort_by == "risk_level":
        filtered.sort(
            key=lambda item: (
                _RISK_ORDER.get(item.risk_level, 99),
                -(item.risk_score if item.risk_score is not None else -1.0),
                item.finding_id,
            )
        )
    elif sort_by == "risk_score":
        filtered.sort(
            key=lambda item: (
                -(item.risk_score if item.risk_score is not None else -1.0),
                _RISK_ORDER.get(item.risk_level, 99),
                item.finding_id,
            )
        )
    elif sort_by == "confidence":
        filtered.sort(
            key=lambda item: (
                -item.confidence,
                _RISK_ORDER.get(item.risk_level, 99),
                item.finding_id,
            )
        )
    else:
        filtered.sort(key=lambda item: item.finding_id)
    return filtered
