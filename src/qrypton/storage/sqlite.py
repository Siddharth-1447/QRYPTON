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
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = DELETE")
        self._connection.execute("PRAGMA busy_timeout = 30000")
        self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS qrypton_schema_version (version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS qrypton_runs (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, status TEXT NOT NULL,
                result_json TEXT, cbom BLOB, content_hash TEXT,
                PRIMARY KEY (tenant_id, run_id)
            );
            CREATE TABLE IF NOT EXISTS qrypton_scanner_results (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, scanner_name TEXT NOT NULL,
                result_json TEXT NOT NULL, PRIMARY KEY (tenant_id, run_id, scanner_name),
                FOREIGN KEY (tenant_id, run_id) REFERENCES qrypton_runs (tenant_id, run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_qrypton_runs_tenant_status
                ON qrypton_runs(tenant_id, status);
            CREATE TABLE IF NOT EXISTS qrypton_run_heartbeats (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, updated_at REAL NOT NULL,
                PRIMARY KEY (tenant_id, run_id),
                FOREIGN KEY (tenant_id, run_id) REFERENCES qrypton_runs (tenant_id, run_id)
                    ON DELETE CASCADE
            );
        """)
        columns = {
            str(row[1]) for row in self._connection.execute("PRAGMA table_info(qrypton_runs)")
        }
        if "content_hash" not in columns:
            self._connection.execute("ALTER TABLE qrypton_runs ADD COLUMN content_hash TEXT")
        if (
            self._connection.execute("SELECT COUNT(*) FROM qrypton_schema_version").fetchone()[0]
            == 0
        ):
            self._connection.execute("INSERT INTO qrypton_schema_version(version) VALUES (1)")
        self._connection.commit()
        self._active: tuple[str, str] | None = None

    def begin_run(self, request: RunRequest, *, run_id: EntityId) -> None:
        existing = self._connection.execute(
            "SELECT status,result_json FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (request.tenant_id, run_id),
        ).fetchone()
        if existing and existing[1] is not None and existing[0] in {
            "completed", "partial", "failed"
        }:
            raise ValueError("Finalized scan snapshots cannot be restarted")
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
        auditable_attributes = {
            "subject_kind",
            "subject_value",
            "algorithm_name",
            "key_size_bits",
            "mode",
            "crypto_role",
            "module",
            "service",
            "package_name",
            "package_version",
            "image_layer_digest",
            "format",
            "language",
            "detector_type",
            "rule_id",
            "evidence_quality",
        }
        document = result.model_dump(mode="json")
        for evidence in document["evidence"]:
            # Preserve stable location, surface, provenance, and bounded
            # semantic attributes. They are required to audit a correlation
            # decision after a process restart. Excerpts and raw byte digests
            # remain excluded from historical storage.
            evidence["excerpt"] = None
            evidence["attributes"] = {
                key: value
                for key, value in evidence["attributes"].items()
                if key in auditable_attributes
            }
            evidence["raw_content_digest"] = None
        document["cbom"] = None
        return document

    def persist_artifacts(self, result: RunResult) -> None:
        payload = json.dumps(self._sanitized(result), separators=(",", ":"), sort_keys=True)
        upsert = (
            "INSERT INTO qrypton_runs(tenant_id,run_id,status,result_json,cbom) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(tenant_id,run_id) DO UPDATE SET "
            "status=excluded.status,result_json=excluded.result_json,cbom=excluded.cbom "
            "WHERE qrypton_runs.result_json IS NULL OR qrypton_runs.status NOT IN "
            "('completed','partial','failed')"
        )
        cursor = self._connection.execute(
            upsert,
            (result.tenant_id, result.run_id, result.status.value, payload, result.cbom),
        )
        if cursor.rowcount == 0:
            existing = self._connection.execute(
                "SELECT status,result_json,cbom FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
                (result.tenant_id, result.run_id),
            ).fetchone()
            if existing != (result.status.value, payload, result.cbom):
                raise ValueError("Finalized scan snapshots are immutable")
        self._connection.commit()

    def finalize_run(self, result: RunResult) -> None:
        self.persist_artifacts(result)
        self._active = None

    def get_run(self, *, tenant_id: TenantId, run_id: EntityId) -> RunResult | None:
        row = self._connection.execute(
            "SELECT result_json, cbom FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        if not row or not row[0]:
            return None
        # The JSON document deliberately excludes the potentially large CBOM;
        # rehydrate it from its authoritative blob column after a DB reopen.
        result = RunResult.model_validate_json(row[0])
        return result.model_copy(update={"cbom": bytes(row[1]) if row[1] is not None else None})

    def get_cbom(self, *, tenant_id: TenantId, run_id: EntityId) -> bytes | None:
        row = self._connection.execute(
            "SELECT cbom FROM qrypton_runs WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
        ).fetchone()
        return bytes(row[0]) if row and row[0] is not None else None

    def get_content_hash(self, *, tenant_id: TenantId, run_id: EntityId) -> str | None:
        row = self._connection.execute(
            "SELECT content_hash FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        return str(row[0]) if row and row[0] is not None else None

    def bind_content_hash(self, *, tenant_id: TenantId, run_id: EntityId, digest: str) -> None:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("invalid content hash")
        cursor = self._connection.execute(
            "UPDATE qrypton_runs SET content_hash=? WHERE tenant_id=? AND run_id=? "
            "AND result_json IS NOT NULL AND content_hash IS NULL",
            (digest, tenant_id, run_id),
        )
        if (
            cursor.rowcount == 0
            and self.get_content_hash(tenant_id=tenant_id, run_id=run_id) != digest
        ):
            raise ValueError("immutable run content hash differs")
        self._connection.commit()

    def delete_run(self, *, tenant_id: TenantId, run_id: EntityId) -> bool:
        """Delete one tenant-scoped historical run and its scanner records."""
        self._connection.execute(
            "DELETE FROM qrypton_scanner_results WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        )
        cursor = self._connection.execute(
            "DELETE FROM qrypton_runs WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
        )
        self._connection.commit()
        return cursor.rowcount > 0

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

    def list_runs_with_asset_tag(
        self, *, tenant_id: TenantId, tag: str
    ) -> tuple[EntityId, ...]:
        """Find tagged runs without rehydrating unrelated scan artifacts."""
        rows = self._connection.execute(
            "SELECT run_id FROM qrypton_runs "
            "WHERE tenant_id=? AND result_json IS NOT NULL "
            "AND json_valid(result_json) "
            "AND EXISTS (SELECT 1 FROM json_each(result_json, '$.asset.tags') "
            "WHERE value=?) ORDER BY rowid DESC",
            (tenant_id, tag),
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def close(self) -> None:
        if self._connection:
            self._connection.close()
            self._connection = None  # type: ignore
