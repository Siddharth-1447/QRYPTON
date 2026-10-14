"""Immutable scan comparisons and transactional analyst lifecycle with bounded undo."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from qrypton.api.access import principal, require_ci_publisher, require_engineer
from qrypton.contracts.primitives import EntityId
from qrypton.storage.investigation import LEGACY_STATUS
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider

Status = Literal[
    "New",
    "Reviewed",
    "Accepted for Migration",
    "In Progress",
    "Mitigated",
    "Verified",
    "Closed",
    "Risk Accepted",
]
STAGES = [
    "New",
    "Reviewed",
    "Accepted for Migration",
    "In Progress",
    "Mitigated",
    "Verified",
    "Closed",
]


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: Status
    version: int = Field(ge=0)
    reason: str = Field(default="", max_length=2000)


class CiReport(BaseModel):
    """A completed PR or CI event supplied by a separately provisioned publisher."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    provider: str = Field(min_length=1, max_length=64)
    external_id: str = Field(min_length=1, max_length=256)
    repository: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=256)
    ref: str = Field(min_length=1, max_length=256)
    result: Literal["success", "failure", "cancelled", "pending"]
    url: HttpUrl
    completed_at: datetime
    run_id: EntityId | None = None
    introduced_finding_ids: tuple[EntityId, ...] = ()
    gate_effect: Literal["blocks", "warns", "not_evaluated"] = "not_evaluated"

    @field_validator("url")
    @classmethod
    def https_only(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("CI result URLs must use HTTPS")
        return value

    @field_validator("completed_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Completion time must include a timezone")
        return value


def progress_router(open_runs: Callable[[], SqliteRunStore]) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    def tenant() -> str:
        return os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)

    def connection() -> sqlite3.Connection:
        runs = open_runs()
        try:
            db = sqlite3.connect(runs._path, timeout=10)
            db.row_factory = sqlite3.Row
            db.executescript("""
                CREATE TABLE IF NOT EXISTS finding_lifecycle (
                    tenant TEXT, run TEXT, finding TEXT, status TEXT NOT NULL,
                    reason TEXT NOT NULL, version INTEGER NOT NULL,
                    PRIMARY KEY(tenant,run,finding));
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    token TEXT PRIMARY KEY, tenant TEXT, run TEXT, finding TEXT,
                    actor TEXT, before_status TEXT, before_reason TEXT,
                    after_status TEXT, after_reason TEXT, version INTEGER,
                    expires REAL, undone INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS ci_results (
                    tenant TEXT NOT NULL, provider TEXT NOT NULL,
                    repository TEXT NOT NULL, external_id TEXT NOT NULL,
                    completed_at TEXT NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY(tenant,provider,repository,external_id));
                CREATE INDEX IF NOT EXISTS ci_results_recent
                    ON ci_results(tenant,completed_at DESC);
            """)
            return db
        finally:
            runs.close()

    def validate_finding(db: sqlite3.Connection, run: str, finding: str) -> None:
        row = db.execute(
            "SELECT result_json FROM qrypton_runs WHERE tenant_id=? AND run_id=?", (tenant(), run)
        ).fetchone()
        if (
            row is None
            or not row[0]
            or finding not in {f["id"] for f in json.loads(row[0])["findings"]}
        ):
            raise HTTPException(404, "Finding not found in this scan")

    def current(db: sqlite3.Connection, run: str, finding: str) -> dict:
        row = db.execute(
            "SELECT status,reason,version FROM finding_lifecycle "
            "WHERE tenant=? AND run=? AND finding=?",
            (tenant(), run, finding),
        ).fetchone()
        if row:
            return dict(row)
        legacy = None
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='qrypton_investigation'").fetchone():
            legacy = db.execute(
                "SELECT migration_status FROM qrypton_investigation "
                "WHERE tenant_id=? AND run_id=? AND finding_id=?",
                (tenant(), run, finding),
            ).fetchone()
        return {
            "status": LEGACY_STATUS.get(legacy[0], "New") if legacy else "New",
            "reason": "",
            "version": 0,
        }

    @router.get("/session")
    def session(request: Request) -> dict:
        return principal(request).model_dump()

    @router.post("/integrations/ci-results", status_code=201)
    def publish_ci_result(body: CiReport, request: Request) -> dict:
        require_ci_publisher(request)
        if body.introduced_finding_ids and body.run_id is None:
            raise HTTPException(422, "Introduced findings require an associated scan")
        if len(set(body.introduced_finding_ids)) != len(body.introduced_finding_ids):
            raise HTTPException(422, "Introduced finding IDs must be unique")
        payload = body.model_dump_json()
        db = connection()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if (
                    body.run_id is not None
                    and db.execute(
                        "SELECT 1 FROM qrypton_runs WHERE tenant_id=? AND run_id=?",
                        (tenant(), body.run_id),
                    ).fetchone()
                    is None
                ):
                    raise HTTPException(404, "Associated scan not found")
                if body.introduced_finding_ids:
                    store = open_runs()
                    try:
                        run = store.get_run(tenant_id=tenant(), run_id=body.run_id)
                    finally:
                        store.close()
                    if run is None or not set(body.introduced_finding_ids).issubset(
                        {finding.id for finding in run.findings}
                    ):
                        raise HTTPException(422, "Introduced finding not present in the scan")
                key = (tenant(), body.provider, body.repository, body.external_id)
                existing = db.execute(
                    "SELECT payload FROM ci_results WHERE tenant=? AND provider=? "
                    "AND repository=? AND external_id=?",
                    key,
                ).fetchone()
                if existing is not None:
                    if existing[0] != payload:
                        raise HTTPException(409, "CI result identity already exists")
                    return body.model_dump(mode="json")
                db.execute(
                    "INSERT INTO ci_results VALUES (?,?,?,?,?,?)",
                    (*key, body.completed_at.astimezone(UTC).isoformat(), payload),
                )
                return body.model_dump(mode="json")
        finally:
            db.close()

    @router.get("/integrations/ci-results")
    def recent_ci_results(limit: int = Query(default=5, ge=1, le=20)) -> list[dict]:
        db = connection()
        try:
            rows = db.execute(
                "SELECT payload FROM ci_results WHERE tenant=? "
                "ORDER BY completed_at DESC, rowid DESC LIMIT ?",
                (tenant(), limit),
            ).fetchall()
            results = [json.loads(row[0]) for row in rows]
        finally:
            db.close()
        store = open_runs()
        try:
            for result in results:
                introduced = []
                result.setdefault("gate_effect", "not_evaluated")
                if result.get("run_id") and result.get("introduced_finding_ids"):
                    run = store.get_run(tenant_id=tenant(), run_id=result["run_id"])
                    if run is not None:
                        inventory = {
                            row.finding_id: row
                            for row in SqliteDashboardDataProvider.run_view_from_result(
                                run
                            ).inventory
                        }
                        for finding_id in result["introduced_finding_ids"]:
                            row = inventory.get(finding_id)
                            if row is not None:
                                introduced.append(
                                    {
                                        "finding_id": finding_id,
                                        "label": row.identity_label,
                                        "severity": row.risk_level.value,
                                        "href": "/finding?"
                                        + urlencode(
                                            {"run_id": result["run_id"], "finding_id": finding_id}
                                        ),
                                    }
                                )
                result["introduced"] = introduced
            return results
        finally:
            store.close()

    @router.get("/workspace-search")
    def search(q: str = Query(default="", max_length=512)) -> list[dict[str, str]]:
        """Search stored runs without recomputing measurements or trusting client role claims."""
        words = q.casefold().split()
        store = open_runs()
        results: list[dict[str, str]] = []
        applications: set[str] = set()
        try:
            for _, run_id, _ in store.list_runs(tenant_id=tenant()):
                run = store.get_run(tenant_id=tenant(), run_id=run_id)
                if run is None:
                    continue
                name = str(run.asset.name if run.asset else "Unknown application")
                # Application DTO names preserve declared ownership context.
                view = SqliteDashboardDataProvider.run_view_from_result(run)
                if view.inventory:
                    name = view.inventory[0].application or name
                if all(word in f"{name} {run_id}".casefold() for word in words):
                    results.append(
                        {
                            "id": run_id,
                            "kind": "Scan",
                            "label": f"{name} · {run_id[-8:]}",
                            "href": "/?" + urlencode({"id": run_id}) + "#results-section",
                        }
                    )
                if name not in applications and all(word in name.casefold() for word in words):
                    applications.add(name)
                    results.append(
                        {
                            "id": name,
                            "kind": "Application",
                            "label": name,
                            "href": "/?"
                            + urlencode({"id": run_id, "iv.application": name})
                            + "#inventory",
                        }
                    )
                for item in view.inventory:
                    row = item.model_dump(mode="json")
                    text = " ".join(
                        str(row.get(field) or "")
                        for field in (
                            "finding_id",
                            "algorithm_name",
                            "algorithm_family",
                            "identity_label",
                            "risk_level",
                            "application",
                            "category",
                        )
                    ).casefold()
                    exposure = row.get("observations", {}).get("exposure", {})
                    if all(
                        (exposure.get("state") == "observed" and exposure.get("value") is True)
                        if word == "internet-facing"
                        else word in text
                        for word in words
                    ):
                        results.append(
                            {
                                "id": run_id + ":" + item.finding_id,
                                "kind": "Finding",
                                "label": f"{item.identity_label} · "
                                f"{item.risk_level.value} · {name}",
                                "href": "/finding?"
                                + urlencode({"run_id": run_id, "finding_id": item.finding_id}),
                            }
                        )
                    if len(results) >= 100:
                        return results[:100]
            return results[:100]
        finally:
            store.close()

    @router.get("/scans/{run}/findings/{finding}/status")
    def read_status(run: EntityId, finding: EntityId) -> dict:
        db = connection()
        try:
            validate_finding(db, run, finding)
            return current(db, run, finding)
        finally:
            db.close()

    @router.patch("/scans/{run}/findings/{finding}/status")
    def change_status(
        run: EntityId, finding: EntityId, body: StatusChange, request: Request
    ) -> dict:
        actor = require_engineer(request)
        db = connection()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                validate_finding(db, run, finding)
                old = current(db, run, finding)
                if body.version != old["version"]:
                    raise HTTPException(409, "Status changed; refresh before retrying")
                allowed = []
                if old["status"] in STAGES[:-1]:
                    allowed = [STAGES[STAGES.index(old["status"]) + 1], "Risk Accepted"]
                if body.status not in allowed:
                    raise HTTPException(422, "Follow the finding lifecycle in order")
                if body.status == "Risk Accepted" and not body.reason.strip():
                    raise HTTPException(422, "Risk acceptance requires an explicit reason")
                version = old["version"] + 1
                token = secrets.token_urlsafe(32)
                expires = time.time() + 5
                db.execute(
                    "INSERT INTO finding_lifecycle VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(tenant,run,finding) DO UPDATE SET "
                    "status=excluded.status,reason=excluded.reason,version=excluded.version",
                    (tenant(), run, finding, body.status, body.reason, version),
                )
                db.execute(
                    "INSERT INTO lifecycle_events VALUES (?,?,?,?,?,?,?,?,?,?,?,0)",
                    (
                        token,
                        tenant(),
                        run,
                        finding,
                        actor.subject,
                        old["status"],
                        old["reason"],
                        body.status,
                        body.reason,
                        version,
                        expires,
                    ),
                )
                return {
                    "status": body.status,
                    "reason": body.reason,
                    "version": version,
                    "undo_token": token,
                    "undo_expires_at": expires,
                }
        finally:
            db.close()

    @router.post("/finding-status/undo/{token}")
    def undo(token: str, request: Request) -> dict:
        actor = require_engineer(request)
        db = connection()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                event = db.execute(
                    "SELECT * FROM lifecycle_events WHERE token=? AND tenant=? AND actor=?",
                    (token, tenant(), actor.subject),
                ).fetchone()
                if event is None:
                    raise HTTPException(404, "Undo not found")
                validate_finding(db, event["run"], event["finding"])
                state = current(db, event["run"], event["finding"])
                if event["undone"] or event["expires"] < time.time():
                    raise HTTPException(409, "Undo window expired")
                if state["version"] != event["version"]:
                    raise HTTPException(409, "A subsequent change prevents undo")
                version = state["version"] + 1
                db.execute(
                    "UPDATE finding_lifecycle SET status=?,reason=?,version=? "
                    "WHERE tenant=? AND run=? AND finding=?",
                    (
                        event["before_status"],
                        event["before_reason"],
                        version,
                        tenant(),
                        event["run"],
                        event["finding"],
                    ),
                )
                db.execute("UPDATE lifecycle_events SET undone=1 WHERE token=?", (token,))
                return {
                    "status": event["before_status"],
                    "reason": event["before_reason"],
                    "version": version,
                }
        finally:
            db.close()

    @router.get("/scan-comparison/options")
    def comparison_options() -> list[dict]:
        """Bounded metadata-only choices; do not load every historical finding."""
        db = connection()
        try:
            rows = db.execute(
                "SELECT run_id, json_extract(result_json, '$.asset.id'), "
                "json_extract(result_json, '$.asset.name'), "
                "json_extract(result_json, '$.started_at') "
                "FROM qrypton_runs WHERE tenant_id=? AND status='completed' "
                "AND json_extract(result_json, '$.asset.id') IS NOT NULL "
                "ORDER BY rowid DESC LIMIT 500",
                (tenant(),),
            ).fetchall()
            return [
                {"id": row[0], "asset_id": row[1], "target": row[2], "timestamp": row[3]}
                for row in rows
            ]
        finally:
            db.close()

    @router.get("/scan-comparison")
    def compare(before: EntityId, after: EntityId) -> dict:
        if before == after:
            raise HTTPException(422, "Select two different scans")
        store = open_runs()
        try:
            left = store.get_run(tenant_id=tenant(), run_id=before)
            right = store.get_run(tenant_id=tenant(), run_id=after)
            if left is None or right is None:
                raise HTTPException(404, "Scan not found")
            if left.status.value != "completed" or right.status.value != "completed":
                raise HTTPException(422, "Compare completed scans to avoid false resolutions")
            if left.asset is None or right.asset is None or left.asset.id != right.asset.id:
                raise HTTPException(422, "Scans must belong to the same application asset")
            if left.started_at > right.started_at:
                raise HTTPException(422, "Baseline must precede the current scan")
            views = [SqliteDashboardDataProvider.run_view_from_result(run) for run in (left, right)]
            indexed = [
                {row.finding_id: row.model_dump(mode="json") for row in view.inventory}
                for view in views
            ]
            categories: dict[str, list] = {
                key: [] for key in ("New", "Resolved", "Changed", "Persistent")
            }
            fields = (
                "algorithm_name",
                "algorithm_variant",
                "key_size_bits",
                "risk_level",
                "risk_score",
                "business_criticality",
                "quantum_status",
                "mosca_urgency",
                "confidence",
                "environment",
            )
            for key in sorted(indexed[0].keys() | indexed[1].keys()):
                old, new = indexed[0].get(key), indexed[1].get(key)
                changes = [
                    field for field in fields if old and new and old.get(field) != new.get(field)
                ]
                category = (
                    "New"
                    if old is None
                    else "Resolved"
                    if new is None
                    else ("Changed" if changes else "Persistent")
                )
                categories[category].append(
                    {"finding_id": key, "before": old, "after": new, "changed_fields": changes}
                )
            totals = [
                sum(row["risk_score"] for row in rows.values() if row.get("risk_score") is not None)
                for rows in indexed
            ]
            return {
                "before": before,
                "after": after,
                "categories": categories,
                "risk_before": totals[0],
                "risk_after": totals[1],
                "unscored": [
                    sum(row.get("risk_score") is None for row in rows.values()) for rows in indexed
                ],
                "risk_measure": "Sum of persisted finding scores (unscored excluded)",
            }
        finally:
            store.close()

    return router
