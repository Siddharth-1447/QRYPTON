"""Durable, tenant-scoped scan telemetry and previous-context lookup."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from qrypton.application.progress import StageState


def initialize(path: Path) -> None:
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS qrypton_scan_progress (
            tenant TEXT NOT NULL, run TEXT NOT NULL, target TEXT NOT NULL,
            context TEXT NOT NULL, stages TEXT NOT NULL, findings INTEGER,
            created INTEGER NOT NULL, PRIMARY KEY (tenant, run))""")


def register(path: Path, tenant: str, run: str, target: str, context: dict[str, Any]) -> None:
    initialize(path)
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.execute(
            "INSERT INTO qrypton_scan_progress VALUES (?, ?, ?, ?, ?, NULL, "
            "(SELECT COALESCE(MAX(created), 0) + 1 FROM qrypton_scan_progress))",
            (tenant, run, target, json.dumps(context), json.dumps(["pending"] * 8)),
        )


def record(path: Path, tenant: str, run: str, stage: int, state: StageState,
           findings: int | None = None) -> None:
    if not 0 <= stage < 8 or (findings is not None and findings < 0):
        raise ValueError("Invalid scan progress")
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT stages FROM qrypton_scan_progress WHERE tenant=? AND run=?", (tenant, run)
        ).fetchone()
        if row is None:
            return
        stages = json.loads(row[0])
        # A later successful scanner must not erase an earlier scanner warning.
        if state == "failed" or stages[stage] not in {"warning", "failed"}:
            stages[stage] = state
        db.execute(
            "UPDATE qrypton_scan_progress SET stages=?, findings=COALESCE(?, findings) "
            "WHERE tenant=? AND run=?", (json.dumps(stages), findings, tenant, run),
        )


def snapshot(path: Path, tenant: str, run: str, status: str) -> dict[str, Any]:
    initialize(path)
    with closing(sqlite3.connect(path, timeout=10)) as db:
        row = db.execute(
            "SELECT stages, findings FROM qrypton_scan_progress WHERE tenant=? AND run=?",
            (tenant, run),
        ).fetchone()
    if row is None:
        return {"stages": None, "findings_discovered": None}
    stages = json.loads(row[0])
    if status == "FAILED":
        stages = ["failed" if state == "running" else state for state in stages]
    elif status == "PARTIAL":
        stages = ["warning" if state == "running" else state for state in stages]
    return {"stages": stages, "findings_discovered": row[1]}


def previous(path: Path, tenant: str, target: str) -> dict[str, Any] | None:
    initialize(path)
    with closing(sqlite3.connect(path, timeout=10)) as db:
        row = db.execute(
            "SELECT p.context FROM qrypton_scan_progress p JOIN qrypton_runs r "
            "ON r.tenant_id=p.tenant AND r.run_id=p.run "
            "WHERE p.tenant=? AND p.target=? ORDER BY p.created DESC LIMIT 1",
            (tenant, target),
        ).fetchone()
    return json.loads(row[0]) if row else None
