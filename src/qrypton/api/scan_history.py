"""Read canonical scan summaries without materializing evidence or CBOM blobs."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime
from typing import Any


def scan_history_page(
    connection: sqlite3.Connection,
    tenant_id: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    where = " WHERE tenant_id=?" if tenant_id is not None else ""
    params = (tenant_id,) if tenant_id is not None else ()
    total = connection.execute("SELECT COUNT(*) FROM qrypton_runs" + where, params).fetchone()[0]
    query = (
        """
        SELECT tenant_id, run_id, status,
            json_extract(result_json, '$.status', '$.started_at', '$.completed_at',
                '$.asset.id', '$.asset.external_reference', '$.asset.tags'),
            (SELECT json_group_array(json_extract(value, '$.id'))
                FROM json_each(qrypton_runs.result_json, '$.findings')),
            (SELECT json_group_array(json_array(json_extract(value, '$.finding_id'),
                    json_extract(value, '$.level')))
                FROM json_each(qrypton_runs.result_json, '$.assessments'))
        FROM qrypton_runs
    """
        + where
        + " ORDER BY rowid DESC LIMIT ? OFFSET ?"
    )
    result = []
    tiers = ("critical", "high", "medium", "low", "informational", "unknown")
    for (
        tenant,
        run_id,
        stored_status,
        metadata,
        finding_json,
        assessment_json,
    ) in connection.execute(
        query,
        (*params, limit, offset),
    ):
        values = json.loads(metadata) if metadata else [None] * 6
        status, started, completed, asset_id, reference, tags = values
        tags = tags or []
        findings = json.loads(finding_json)
        # Match the existing last-assessment-per-finding projection exactly.
        assessments = dict(json.loads(assessment_json))
        counts = Counter(assessments.values())
        unassessed = sum(finding not in assessments for finding in findings)
        result.append(
            {
                "scan_id": run_id,
                "run_id": run_id,
                "tenant_id": tenant,
                "status": (status or stored_status).upper(),
                "started_at": datetime.fromisoformat(started) if started else None,
                "completed_at": datetime.fromisoformat(completed) if completed else None,
                "artifact": reference if asset_id else "unavailable",
                "target_type": next(
                    (tag[7:] for tag in tags if tag.startswith("target:")), "unknown"
                ),
                "environment": next(
                    (tag[12:] for tag in tags if tag.startswith("environment:")), "unknown"
                ),
                "total_findings": len(findings),
                "highest_risk": next(
                    (tier for tier in tiers if counts[tier]), "unassessed" if unassessed else None
                ),
                **{f"{tier}_findings_count": counts[tier] for tier in tiers},
                "unassessed_findings_count": unassessed,
                "sample_data": "sample-data" in tags,
            }
        )
    return result, total


def export_summary(connection: sqlite3.Connection, tenant_id: str, run_id: str) -> dict | None:
    """Export availability needs counts and identities, not evidence model objects."""
    row = connection.execute(
        """
        SELECT json_extract(result_json, '$.asset.name', '$.target.kind', '$.status'),
            (SELECT json_group_array(json_extract(value, '$.id'))
                FROM json_each(qrypton_runs.result_json, '$.findings')),
            (SELECT json_group_array(json_array(json_extract(value, '$.finding_id'),
                    json_extract(value, '$.level')))
                FROM json_each(qrypton_runs.result_json, '$.assessments')),
            (SELECT count(*) FROM (
                SELECT json_extract(value, '$.asset_id') AS asset_id
                    FROM json_each(qrypton_runs.result_json, '$.findings')
                UNION SELECT json_extract(value, '$.asset_id')
                    FROM json_each(qrypton_runs.result_json, '$.evidence'))),
            cbom IS NOT NULL
        FROM qrypton_runs WHERE tenant_id=? AND run_id=? AND result_json IS NOT NULL
    """,
        (tenant_id, run_id),
    ).fetchone()
    if row is None:
        return None
    name, target, status = json.loads(row[0])
    findings = json.loads(row[1])
    assessments = json.loads(row[2])
    assessed_ids = {item[0] for item in assessments}
    counts = Counter(item[1] for item in assessments)
    tiers = ("critical", "high", "medium", "low", "informational", "unknown")
    return {
        "run_id": run_id,
        "scope": name or "Unknown asset",
        "target_type": target or "unknown",
        "asset_count": row[3],
        "finding_count": len(findings),
        "risk_summary": {
            **{tier: counts[tier] for tier in tiers},
            "unassessed": sum(item not in assessed_ids for item in findings),
        },
        "cbom_available": bool(row[4]),
        "report_available": status == "completed",
        "provenance": "Persisted scan result; source excerpts and key material excluded",
    }
