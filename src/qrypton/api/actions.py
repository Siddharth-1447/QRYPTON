"""Persisted finding actions and truthful, scan-specific export previews."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as UrlRequest

from fastapi import APIRouter, HTTPException, Request

from qrypton.api.access import require_ticket_creator
from qrypton.api.scan_history import export_summary
from qrypton.contracts.identity import finding_identity_label
from qrypton.contracts.primitives import EntityId
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider


def _line(value: object, maximum: int = 300) -> str:
    """Keep scanner-controlled labels on one Markdown line, without raw excerpts."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()[:maximum]


def _github_repository() -> str | None:
    repository = os.environ.get("QRYPTON_GITHUB_ISSUES_REPO", "").strip()
    token = os.environ.get("QRYPTON_GITHUB_ISSUES_TOKEN", "")
    if not repository or not token:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise HTTPException(503, "GitHub Issues integration repository is invalid")
    return repository


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def _open_github(request: UrlRequest, timeout: int):
    """Never forward the integration credential to a redirected host."""
    return build_opener(_NoRedirect()).open(request, timeout=timeout)


def actions_router(open_runs: Callable[[], SqliteRunStore]) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    def tenant() -> str:
        return os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)

    def load(run_id: str):
        store = open_runs()
        try:
            run = store.get_run(tenant_id=tenant(), run_id=run_id)
        finally:
            store.close()
        if run is None:
            raise HTTPException(404, "Scan not found")
        return run

    def ticket(run_id: str, finding_id: str) -> dict:
        run = load(run_id)
        finding = next((item for item in run.findings if item.id == finding_id), None)
        if finding is None:
            raise HTTPException(404, "Finding not found in this scan")
        view = SqliteDashboardDataProvider.run_view_from_result(run)
        inventory = next((item for item in view.inventory if item.finding_id == finding_id), None)
        roadmap = next((item for item in view.roadmap if item.finding_id == finding_id), None)
        assessment = next((item for item in run.assessments if item.finding_id == finding_id), None)
        evidence = {item.id: item for item in run.evidence}
        locations = []
        for evidence_id in finding.evidence_ids:
            item = evidence.get(evidence_id)
            if item is None:
                continue
            location = item.location
            if location.relative_path:
                line = f":{location.line_start}" if location.line_start else ""
                locations.append(f"{_line(location.relative_path)}{line}")
        severity = inventory.risk_level.value if inventory else "unknown"
        identity = _line(finding_identity_label(finding))
        reasons = (
            "; ".join(_line(reason, 300) for reason in assessment.factors.rationale[:3])
            if assessment
            else ""
        )
        if not reasons:
            reasons = f"Persisted {severity} assessment; review recorded factors and uncertainty."
        asset_name = _line(run.asset.name if run.asset else "asset")
        title = f"[{severity.upper()}] Migrate {identity} in {asset_name}"[:256]
        recommendation = (
            _line(roadmap.action, 1000)
            if roadmap
            else "Validate the cryptographic role before selecting a PQC migration target."
        )
        targets = ", ".join(_line(item) for item in roadmap.target_algorithms) if roadmap else ""
        hybrid = _line(roadmap.hybrid_mode) if roadmap and roadmap.hybrid_mode else "Not specified"
        public_url = os.environ.get("QRYPTON_PUBLIC_URL", "").rstrip("/")
        if public_url and (
            urlsplit(public_url).scheme != "https" or not urlsplit(public_url).netloc
        ):
            public_url = ""
        finding_path = f"/finding?run_id={quote(run_id)}&finding_id={quote(finding_id)}"
        body = "\n".join(
            [
                f"**Finding:** {identity}",
                f"**Severity:** {severity}",
                f"**Risk reason:** {reasons}",
                "**Evidence location:** " + (", ".join(locations) if locations else "Not recorded"),
                f"**Recommended path:** {recommendation}",
                f"**PQC targets:** {targets or 'Not specified'}",
                f"**Hybrid mode:** {hybrid}",
                f"**Scan:** {run_id}",
                f"**Full finding:** {public_url + finding_path if public_url else finding_path}",
                "\nNo source excerpts, credentials, or key material are included.",
            ]
        )
        return {"mode": "github" if _github_repository() else "copy", "title": title, "body": body}

    @router.get("/scans/{run_id}/findings/{finding_id}/ticket")
    def ticket_preview(run_id: EntityId, finding_id: EntityId) -> dict:
        return ticket(run_id, finding_id)

    @router.post("/scans/{run_id}/findings/{finding_id}/ticket")
    def create_ticket(run_id: EntityId, finding_id: EntityId, request: Request) -> dict:
        require_ticket_creator(request)
        draft = ticket(run_id, finding_id)
        repository = _github_repository()
        if repository is None:
            raise HTTPException(409, "No issue integration configured; copy the ticket draft")
        store = open_runs()
        try:
            db_path = store._path
        finally:
            store.close()
        with sqlite3.connect(db_path, timeout=10) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS finding_tickets ("
                "tenant TEXT NOT NULL, run TEXT NOT NULL, finding TEXT NOT NULL, "
                "url TEXT, started REAL NOT NULL, PRIMARY KEY(tenant,run,finding))"
            )
            key = (tenant(), run_id, finding_id)
            with db:
                db.execute(
                    "DELETE FROM finding_tickets WHERE tenant=? AND run=? AND finding=? "
                    "AND url IS NULL AND started<?",
                    (*key, time.time() - 60),
                )
                existing = db.execute(
                    "SELECT url FROM finding_tickets WHERE tenant=? AND run=? AND finding=?", key
                ).fetchone()
                if existing:
                    if existing[0]:
                        return {"url": existing[0], "created": False}
                    raise HTTPException(409, "Ticket creation is already in progress")
                db.execute(
                    "INSERT INTO finding_tickets VALUES (?,?,?,?,?)", (*key, None, time.time())
                )
            try:
                data = json.dumps({"title": draft["title"], "body": draft["body"]}).encode()
                upstream = UrlRequest(
                    f"https://api.github.com/repos/{repository}/issues",
                    data=data,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "Authorization": f"Bearer {os.environ['QRYPTON_GITHUB_ISSUES_TOKEN']}",
                        "Content-Type": "application/json",
                        "User-Agent": "qrypton-ticket-action",
                    },
                    method="POST",
                )
                with _open_github(upstream, timeout=10) as response:
                    if response.status != 201:
                        raise HTTPException(
                            502, f"GitHub issue creation returned HTTP {response.status}"
                        )
                    result = json.loads(response.read(65536))
                issue_url = result.get("html_url", "")
                if not re.fullmatch(
                    rf"https://github\.com/{re.escape(repository)}/issues/[0-9]+", issue_url
                ):
                    raise HTTPException(502, "GitHub returned an invalid issue link")
                with db:
                    db.execute(
                        "UPDATE finding_tickets SET url=? WHERE tenant=? AND run=? AND finding=?",
                        (issue_url, *key),
                    )
                return {"url": issue_url, "created": True}
            except (HTTPError, URLError, OSError, ValueError, KeyError, HTTPException) as error:
                with db:
                    db.execute(
                        "DELETE FROM finding_tickets WHERE tenant=? AND run=? AND finding=? "
                        "AND url IS NULL",
                        key,
                    )
                if isinstance(error, HTTPError):
                    raise HTTPException(
                        502, f"GitHub issue creation failed (HTTP {error.code})"
                    ) from error
                if isinstance(error, HTTPException):
                    raise
                raise HTTPException(
                    502, "GitHub issue creation failed; retry or copy the draft"
                ) from error

    @router.get("/scans/{run_id}/export-preview")
    def export_preview(run_id: EntityId) -> dict:
        store = open_runs()
        try:
            summary = export_summary(store._connection, tenant(), run_id)
        finally:
            store.close()
        if summary is None:
            raise HTTPException(404, "Scan not found")
        return summary

    return router
