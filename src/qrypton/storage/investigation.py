"""Tenant-scoped analyst decisions, independent of immutable scan evidence."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

LEGACY_STATUS = {
    "untriaged": "New",
    "planned": "Accepted for Migration",
    "in_progress": "In Progress",
    "blocked": "In Progress",
    "migrated": "Mitigated",
    "accepted": "Reviewed",
}

MigrationStatus = Literal["untriaged", "planned", "in_progress", "blocked", "migrated", "accepted"]


class InvestigationDecision(BaseModel):
    owner: str | None = None
    migration_status: str = "New"
    in_roadmap: bool = False


class InventoryViewConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    q: str = Field(default="", max_length=512)
    application: str = Field(default="", max_length=512)
    algorithm: str = Field(default="", max_length=512)
    finding: str = Field(default="", max_length=512)
    risk: str = Field(default="", max_length=128)
    family: str = Field(default="", max_length=128)
    quantum: str = Field(default="", max_length=128)
    surface: str = Field(default="", max_length=128)
    criticality: str = Field(default="", max_length=128)
    environment: str = Field(default="", max_length=128)
    exposure: str = Field(default="", max_length=128)
    confidence: str = Field(default="", max_length=128)
    migration: str = Field(default="", max_length=128)
    urgency: str = Field(default="", max_length=128)
    context: str = Field(default="", max_length=128)
    timeline: str = Field(default="", max_length=128)
    view: Literal["grouped", "raw"] = "grouped"
    sort: Literal[
        "risk_score",
        "risk_level",
        "algorithm_name",
        "last_observed_at",
        "confidence",
        "application",
        "business_criticality",
        "migration_status",
        "finding_id",
    ] = "risk_level"
    direction: Literal["asc", "desc"] = "desc"
    expanded: list[Annotated[str, Field(max_length=1024)]] = Field(
        default_factory=list, max_length=5000
    )


class SavedInventoryView(BaseModel):
    id: str
    name: str
    state: InventoryViewConfig


class InvestigationStore:
    def __init__(self, path: Path) -> None:
        self._db = sqlite3.connect(path, timeout=10)
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS qrypton_investigation (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                owner TEXT, migration_status TEXT NOT NULL DEFAULT 'untriaged',
                in_roadmap INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, run_id, finding_id),
                FOREIGN KEY (tenant_id, run_id) REFERENCES qrypton_runs(tenant_id, run_id)
                    ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS qrypton_inventory_views (
                tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, name));
        """)

    def close(self) -> None:
        self._db.close()

    def decisions(self, tenant: str, run: str) -> dict[str, InvestigationDecision]:
        rows = self._db.execute(
            "SELECT finding_id,owner,migration_status,in_roadmap FROM qrypton_investigation "
            "WHERE tenant_id=? AND run_id=?",
            (tenant, run),
        ).fetchall()
        decisions = {
            row[0]: InvestigationDecision(
                owner=row[1],
                migration_status=LEGACY_STATUS.get(row[2], "New"),
                in_roadmap=bool(row[3]),
            )
            for row in rows
        }
        if self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='finding_lifecycle'"
        ).fetchone():
            for finding, status in self._db.execute(
                "SELECT finding,status FROM finding_lifecycle WHERE tenant=? AND run=?",
                (tenant, run),
            ):
                decision = decisions.get(finding, InvestigationDecision())
                decisions[finding] = decision.model_copy(update={"migration_status": status})
        return decisions

    def apply(
        self,
        tenant: str,
        run: str,
        finding_ids: list[str],
        action: Literal["roadmap", "owner", "status"],
        *,
        owner: str | None = None,
        status: MigrationStatus | None = None,
    ) -> int:
        """Validate the entire batch and commit all decisions atomically."""
        ids = sorted(set(finding_ids))
        if action not in {"owner", "status", "roadmap"}:
            raise ValueError("Unknown investigation action")
        if not ids or len(ids) > 5000:
            raise ValueError("Select between 1 and 5,000 findings")
        if action == "owner" and (owner is None or not owner.strip() or len(owner) > 256):
            raise ValueError("Provide an owner of 1 to 256 characters")
        if action == "status" and status not in {
            "untriaged",
            "planned",
            "in_progress",
            "blocked",
            "migrated",
            "accepted",
        }:
            raise ValueError("Provide a valid migration status")
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._db.execute(
                "SELECT result_json FROM qrypton_runs WHERE tenant_id=? AND run_id=?", (tenant, run)
            ).fetchone()
            if row is None or row[0] is None:
                raise LookupError("Run not found")
            valid = {finding["id"] for finding in json.loads(row[0])["findings"]}
            if not set(ids).issubset(valid):
                raise LookupError("The selection contains findings outside this run")
            now = datetime.now(UTC).isoformat()
            self._db.executemany(
                "INSERT OR IGNORE INTO qrypton_investigation"
                "(tenant_id,run_id,finding_id,updated_at) VALUES (?,?,?,?)",
                [(tenant, run, finding, now) for finding in ids],
            )
            for finding in ids:
                if action == "roadmap":
                    self._db.execute(
                        "UPDATE qrypton_investigation SET in_roadmap=1, updated_at=? "
                        "WHERE tenant_id=? AND run_id=? AND finding_id=?",
                        (now, tenant, run, finding),
                    )
                elif action == "owner":
                    assert owner is not None
                    self._db.execute(
                        "UPDATE qrypton_investigation SET owner=?,updated_at=? "
                        "WHERE tenant_id=? AND run_id=? AND finding_id=?",
                        (owner.strip(), now, tenant, run, finding),
                    )
                elif action == "status":
                    self._db.execute(
                        "UPDATE qrypton_investigation SET migration_status=?,updated_at=? "
                        "WHERE tenant_id=? AND run_id=? AND finding_id=?",
                        (status, now, tenant, run, finding),
                    )
        return len(ids)

    def views(self, tenant: str) -> list[SavedInventoryView]:
        return [
            SavedInventoryView(id=row[0], name=row[1], state=json.loads(row[2]))
            for row in self._db.execute(
                "SELECT id,name,state FROM qrypton_inventory_views WHERE tenant_id=? "
                "ORDER BY name COLLATE NOCASE",
                (tenant,),
            ).fetchall()
        ]

    def save_view(self, tenant: str, name: str, state: InventoryViewConfig) -> SavedInventoryView:
        name = name.strip()
        if not name or len(name) > 80:
            raise ValueError("View name must contain 1 to 80 characters")
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            existing = self._db.execute(
                "SELECT id FROM qrypton_inventory_views WHERE tenant_id=? AND name=?",
                (tenant, name),
            ).fetchone()
            if existing is None and len(self.views(tenant)) >= 100:
                raise ValueError("A tenant can save at most 100 inventory views")
            view_id = existing[0] if existing else "view_" + uuid4().hex
            self._db.execute(
                "INSERT INTO qrypton_inventory_views VALUES (?,?,?,?) "
                "ON CONFLICT(tenant_id,name) DO UPDATE SET state=excluded.state",
                (tenant, view_id, name, state.model_dump_json()),
            )
        return SavedInventoryView(id=view_id, name=name, state=state)

    def delete_view(self, tenant: str, view_id: str) -> bool:
        with self._db:
            return (
                self._db.execute(
                    "DELETE FROM qrypton_inventory_views WHERE tenant_id=? AND id=?",
                    (tenant, view_id),
                ).rowcount
                > 0
            )
