"""Persist analyst decisions and saved views without modifying scanner measurements."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from qrypton.api.access import require_engineer
from qrypton.contracts.primitives import EntityId
from qrypton.storage.investigation import (
    InventoryViewConfig,
    InvestigationDecision,
    InvestigationStore,
    MigrationStatus,
    SavedInventoryView,
)
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import DashboardRunView, RoadmapRow


class BulkAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    run_id: EntityId
    finding_ids: list[EntityId] = Field(min_length=1, max_length=5000)
    action: Literal["roadmap", "owner", "status"]
    owner: str | None = Field(default=None, min_length=1, max_length=256)
    status: MigrationStatus | None = None

    @model_validator(mode="after")
    def required_value(self) -> BulkAction:
        if self.action == "owner" and self.owner is None:
            raise ValueError("Provide an owner")
        if self.action == "status" and self.status is None:
            raise ValueError("Provide a migration status")
        return self


class SaveView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=80)
    state: InventoryViewConfig


@contextmanager
def open_investigation(open_runs: Callable[[], SqliteRunStore]) -> Iterator[InvestigationStore]:
    try:
        runs = open_runs()
        try:
            store = InvestigationStore(runs._path)
        finally:
            runs.close()
        try:
            yield store
        finally:
            store.close()
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=503, detail="Investigation persistence unavailable"
        ) from error


def with_decisions(
    view: DashboardRunView, decisions: dict[str, InvestigationDecision],
) -> DashboardRunView:
    inventory = tuple(row.model_copy(update={
        **decisions[row.finding_id].model_dump(exclude={"owner"}),
        "assigned_owner": decisions[row.finding_id].owner or row.assigned_owner,
    }) if row.finding_id in decisions else row for row in view.inventory)
    inventory_by_id = {row.finding_id: row for row in inventory}
    roadmap = []
    for row in view.roadmap:
        decision = decisions.get(row.finding_id)
        roadmap.append(row.model_copy(update={
            **decision.model_dump(exclude={"owner"}),
            "assigned_owner": decision.owner or inventory_by_id[row.finding_id].assigned_owner,
        }) if decision else row)
    existing = {row.finding_id for row in roadmap}
    for row in inventory:
        if row.in_roadmap and row.finding_id not in existing:
            roadmap.append(RoadmapRow(
                finding_id=row.finding_id, priority=1,
                action="Analyst added to migration roadmap: review evidence and plan migration.",
                assigned_owner=row.assigned_owner, migration_status=row.migration_status,
                in_roadmap=True,
            ))
    return view.model_copy(update={"inventory": inventory, "roadmap": tuple(roadmap)})


def investigation_router(open_runs: Callable[[], SqliteRunStore]) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    def tenant() -> str:
        return os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)

    @router.patch("/inventory/actions")
    def bulk_action(request: BulkAction, http_request: Request) -> dict[str, int]:
        require_engineer(http_request)
        if request.action == "status":
            raise HTTPException(410, "Use the versioned finding lifecycle endpoint")
        try:
            with open_investigation(open_runs) as store:
                updated = store.apply(
                    tenant(), request.run_id, request.finding_ids, request.action,
                    owner=request.owner, status=request.status,
                )
            return {"updated": updated}
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except sqlite3.Error as error:
            raise HTTPException(
                status_code=503, detail="Investigation persistence unavailable"
            ) from error

    @router.get("/inventory/views")
    def saved_views() -> list[SavedInventoryView]:
        with open_investigation(open_runs) as store:
            return store.views(tenant())

    @router.post("/inventory/views")
    def save_view(request: SaveView) -> SavedInventoryView:
        try:
            with open_investigation(open_runs) as store:
                return store.save_view(tenant(), request.name, request.state)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @router.delete("/inventory/views/{view_id}")
    def delete_view(view_id: str) -> dict[str, bool]:
        with open_investigation(open_runs) as store:
            if not store.delete_view(tenant(), view_id):
                raise HTTPException(status_code=404, detail="Saved view not found")
        return {"deleted": True}

    return router
