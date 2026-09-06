"""SQLite implementation storing only sanitized canonical run artifacts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from qrypton.application.schemas import RunRequest, RunResult, ScannerExecutionResult
from qrypton.contracts.primitives import EntityId, TenantId


class SqliteRunStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._connection = sqlite3.connect(path)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS qrypton_schema_version (version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS qrypton_runs (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, status TEXT NOT NULL,
                result_json TEXT, cbom BLOB, PRIMARY KEY (tenant_id, run_id)
            );
            CREATE TABLE IF NOT EXISTS qrypton_scanner_results (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, scanner_name TEXT NOT NULL,
                result_json TEXT NOT NULL, PRIMARY KEY (tenant_id, run_id, scanner_name),
                FOREIGN KEY (tenant_id, run_id) REFERENCES qrypton_runs (tenant_id, run_id)
            );
        """)
        if (
            self._connection.execute("SELECT COUNT(*) FROM qrypton_schema_version").fetchone()[0]
            == 0
        ):
            self._connection.execute("INSERT INTO qrypton_schema_version(version) VALUES (1)")
        self._connection.commit()
        self._active: tuple[str, str] | None = None

    def begin_run(self, request: RunRequest, *, run_id: EntityId) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
            (request.tenant_id, run_id, "pending"),
        )
        # The request is intentionally never serialized: it contains a target locator.
        self._active = (request.tenant_id, run_id)
        self._connection.commit()

    def persist_scanner_result(self, result: ScannerExecutionResult) -> None:
        if self._active is None:
            raise RuntimeError("no active run")
        tenant_id, run_id = self._active
        self._connection.execute(
            "INSERT OR REPLACE INTO qrypton_scanner_results VALUES (?,?,?,?)",
            (tenant_id, run_id, result.scanner_name, result.model_dump_json()),
        )
        self._connection.commit()

    @staticmethod
    def _sanitized(result: RunResult) -> dict[str, object]:
        document = result.model_dump(mode="json")
        for evidence in document["evidence"]:
            evidence["excerpt"] = None
            evidence["attributes"] = {}
            evidence["raw_content_digest"] = None
            evidence["location"] = {}
        document["cbom"] = None
        return document

    def persist_artifacts(self, result: RunResult) -> None:
        payload = json.dumps(self._sanitized(result), separators=(",", ":"), sort_keys=True)
        upsert = (
            "INSERT INTO qrypton_runs(tenant_id,run_id,status,result_json,cbom) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(tenant_id,run_id) DO UPDATE SET "
            "status=excluded.status,result_json=excluded.result_json,cbom=excluded.cbom"
        )
        self._connection.execute(
            upsert,
            (result.tenant_id, result.run_id, result.status.value, payload, result.cbom),
        )
        self._connection.commit()

    def finalize_run(self, result: RunResult) -> None:
        self.persist_artifacts(result)
        self._active = None

    def get_run(self, *, tenant_id: TenantId, run_id: EntityId) -> RunResult | None:
        row = self._connection.execute(
            "SELECT result_json FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        return RunResult.model_validate_json(row[0]) if row and row[0] else None

    def get_cbom(self, *, tenant_id: TenantId, run_id: EntityId) -> bytes | None:
        row = self._connection.execute(
            "SELECT cbom FROM qrypton_runs WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
        ).fetchone()
        return bytes(row[0]) if row and row[0] is not None else None

    def list_runs(
        self, *, tenant_id: TenantId | None = None
    ) -> tuple[tuple[TenantId, EntityId, str], ...]:
        if tenant_id is None:
            rows = self._connection.execute(
                "SELECT tenant_id, run_id, status FROM qrypton_runs ORDER BY rowid DESC"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT tenant_id, run_id, status FROM qrypton_runs "
                "WHERE tenant_id=? ORDER BY rowid DESC",
                (tenant_id,),
            ).fetchall()
        return tuple((str(r[0]), str(r[1]), str(r[2])) for r in rows)
