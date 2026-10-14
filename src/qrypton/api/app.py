# type: ignore
"""FastAPI backend application for QRYPTON cryptographic posture and inventory."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil
import sqlite3
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, ValidationError

from qrypton.api import scan_progress
from qrypton.api.accounts import router as accounts_router
from qrypton.api.actions import actions_router
from qrypton.api.investigation import investigation_router, open_investigation, with_decisions
from qrypton.api.oauth import router as oauth_router
from qrypton.api.progress import progress_router
from qrypton.api.reporting import executive_pdf
from qrypton.api.scan_errors import public_failure_message, resolution_failure_code
from qrypton.api.scan_history import scan_history_page
from qrypton.application.config import (
    QryptonConfig,
    build_orchestrator,
    default_recommendation_policy,
    default_risk_policy,
)
from qrypton.application.progress import StageState, observer, report
from qrypton.application.schemas import PolicyGate, PolicyOutcome, RunFailure, RunRequest, RunResult
from qrypton.contracts.enums import (
    AssetKind,
    Criticality,
    ObservationState,
    RiskLevel,
    RunStatus,
    ScanTargetKind,
)
from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, BusinessContext, Observation, Provenance, ScanTarget
from qrypton.exporters.cyclonedx_1_6 import sanitize_persisted_cbom
from qrypton.ports.scanners import ScanLimits
from qrypton.risk.mosca import MoscaParameters
from qrypton.storage.sqlite import SqliteRunStore
from qrypton.ui.contracts import (
    DashboardRunView,
    ExecutivePosture,
    FindingDetail,
    InventoryRow,
    MoscaPoint,
    RiskHeatmapCell,
    RoadmapRow,
)
from qrypton.ui.provider import DashboardDataProvider
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider

app = FastAPI(title="QRYPTON Cryptographic Inventory API")
_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="qrypton-scan")
_ACTIVE_SCANS: dict[str, str] = {}
_ACTIVE_SCANS_LOCK = threading.Lock()
_SAMPLE_WORKSPACE_LOCK = threading.Lock()
_SAMPLE_TAG = "sample-data"
_REMOTE_ACQUISITION_TIMEOUT_SECONDS = 30
_SOURCE_SCAN_TIMEOUT_SECONDS = 90

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(?:localhost|127\.0\.0\.1):[0-9]{1,5}$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],
)


def _open_run_store() -> SqliteRunStore:
    """Open the same configured persistence source for dashboards and reports."""
    candidates: list[Path] = []
    env_db = os.environ.get("QRYPTON_DB")
    if env_db:
        candidates.append(Path(env_db))
    else:
        candidates.extend([Path("qrypton.db"), Path("qrypton.sqlite3"), Path("qrypton_demo.db")])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                return SqliteRunStore(candidate)
            except Exception:
                continue
    raise HTTPException(status_code=503, detail="scan persistence is unavailable")


def get_provider(tenant_id: str | None = None) -> DashboardDataProvider:
    """Return authoritative persisted data; never substitute mock scan results."""
    return SqliteDashboardDataProvider(_open_run_store())


def _resolve_view(
    provider: DashboardDataProvider,
    tenant_id: str | None = None,
    run_id: str | None = None,
) -> DashboardRunView:
    # A selected run is the normal dashboard path.  Every API-created run
    # uses this tenant, so load it directly instead of deserializing every
    # historical run merely to locate the requested ID.
    if run_id is not None:
        selected_tenant = tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
        view = provider.get_run_view(tenant_id=selected_tenant, run_id=run_id)
        if view is not None:
            return view
        if tenant_id is not None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    runs = provider.list_runs(tenant_id=tenant_id)

    if not runs:
        raise HTTPException(status_code=404, detail="No cryptographic runs found")

    if run_id is not None:
        target_run = next((r for r in runs if r.run_id == run_id), None)
        if target_run is None:
            tid = tenant_id or runs[0].tenant_id
            view = provider.get_run_view(tenant_id=tid, run_id=run_id)
            if view is not None:
                return view
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        selected_tenant = target_run.tenant_id
        selected_run = target_run.run_id
    else:
        selected_tenant = runs[0].tenant_id
        selected_run = runs[0].run_id

    view = provider.get_run_view(tenant_id=selected_tenant, run_id=selected_run)
    if view is None:
        raise HTTPException(status_code=404, detail="Run view could not be loaded")
    return view


def _investigation_view(view: DashboardRunView) -> DashboardRunView:
    with open_investigation(_open_run_store) as store:
        decisions = store.decisions(view.summary.tenant_id, view.summary.run_id)
    return with_decisions(view, decisions)


app.include_router(investigation_router(_open_run_store))
app.include_router(progress_router(_open_run_store))
app.include_router(actions_router(_open_run_store))
app.include_router(oauth_router)
app.include_router(accounts_router)


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    """Healthcheck endpoint returning system operational status."""
    return {"status": "ok", "service": "QRYPTON Cryptographic Inventory API"}


@app.get("/api/v1/inventory")
def get_inventory(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[InventoryRow]:
    """Retrieve cryptographic findings inventory for the active or requested run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(_investigation_view(view).inventory)


@app.get("/api/v1/posture")
def get_posture(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> ExecutivePosture:
    """Retrieve executive cryptographic posture metrics for the active or requested run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return view.posture


class DashboardSnapshot(BaseModel):
    """Typed snapshot lets Pydantic serialize large inventories in one pass."""

    posture: ExecutivePosture
    inventory: tuple[InventoryRow, ...]
    mosca: tuple[MoscaPoint, ...]
    heatmap: tuple[RiskHeatmapCell, ...]
    roadmap: tuple[RoadmapRow, ...]


@app.get("/api/v1/dashboard")
def get_dashboard_snapshot(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> DashboardSnapshot:
    """Return one internally consistent dashboard snapshot for a persisted run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    view = _investigation_view(view)
    return DashboardSnapshot(
        posture=view.posture,
        inventory=view.inventory,
        mosca=view.mosca_points,
        heatmap=view.heatmap_cells,
        roadmap=view.roadmap,
    )


class TargetSource(BaseModel):
    """Structured original-artifact descriptor. Extra provider-specific keys allowed."""

    model_config = {"extra": "allow"}

    type: str = ""
    provider: str | None = None
    url: str | None = None
    identifier: str | None = None
    reference: str | None = None
    name: str | None = None
    format: str | None = None
    location: str | None = None
    branch: str | None = None


class ArtifactMetadata(BaseModel):
    """Original upload/file metadata. Extra keys allowed for forward compat."""

    model_config = {"extra": "allow"}

    name: str | None = None
    format: str | None = None
    size_bytes: int | None = None
    content_type: str | None = None
    location: str | None = None


class BusinessContextPayload(BaseModel):
    """Explicit business-context block so it is never folded into the locator."""

    model_config = {"extra": "allow"}

    system_name: str = ""
    owner: str = ""
    environment: str | None = None
    business_criticality: str | None = None
    data_sensitivity: str | None = None
    internet_exposure: bool | None = None
    regulatory_relevance: str | None = None
    migration_complexity: str | None = None
    data_lifetime: float | None = Field(default=None, ge=0, le=10_000, allow_inf_nan=False)
    migration_time: float | None = Field(default=None, ge=0, le=10_000, allow_inf_nan=False)
    crqc_horizon: float = Field(default=0, ge=0, le=10_000, allow_inf_nan=False)


class ScanRequest(BaseModel):
    target_type: str
    repository: str = ""
    artifact_id: str | None = None
    branch: str = "main"
    environment: str | None = None
    business_criticality: str | None = None
    system_name: str = ""
    owner: str = ""
    data_sensitivity: str | None = None
    internet_exposure: bool | None = None
    regulatory_relevance: str | None = None
    migration_complexity: str | None = None
    data_lifetime: float | None = Field(default=None, ge=0, le=10_000, allow_inf_nan=False)
    migration_time: float = Field(ge=0, le=10_000, allow_inf_nan=False)
    crqc_horizon: float = Field(ge=0, le=10_000, allow_inf_nan=False)
    # Structured original-artifact preservation (preferred; legacy
    # repository/artifact_id fields above remain accepted for compat).
    target_source: TargetSource | None = None
    artifact_metadata: ArtifactMetadata | None = None
    business_context: BusinessContextPayload | None = None


_API_SECRET = os.environ.get("QRYPTON_ID_SECRET", "").encode() or os.urandom(32)


def _size_scaled_timeout_seconds(size_bytes: int | None, target_type: str | None = None) -> int:
    """Use the same budget for API surface names and canonical scanner target kinds."""
    if target_type in {"source_repo", "source_archive", "source_tree", "git_archive"}:
        return _SOURCE_SCAN_TIMEOUT_SECONDS
    return 1200


def _limits(size_bytes: int | None = None, target_type: str | None = None) -> ScanLimits:
    wall_time = _size_scaled_timeout_seconds(size_bytes, target_type)
    return ScanLimits(
        max_compressed_bytes=64 * 1024 * 1024,
        max_expanded_bytes=512 * 1024 * 1024,
        max_file_count=100_000,
        max_nesting_depth=8,
        max_layer_count=128,
        max_ast_nodes=1_000_000,
        max_evidence_count=100_000,
        max_wall_time_seconds=wall_time,
        max_memory_bytes=512 * 1024 * 1024,
    )


def _observed(value: Any, evidence_id: str) -> Observation[Any]:
    return Observation(
        state=ObservationState.OBSERVED, value=value, basis_evidence_ids=(evidence_id,)
    )


_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
_KMS_ARN = re.compile(r"^arn:[^:]+:kms:[^:]*:[^:]*:(key|alias)/.+$", re.IGNORECASE)
_KMS_KEY_ID = re.compile(r"^(?:[0-9a-fA-F-]{8,}|alias/[A-Za-z0-9/_-]+)$")
# Azure Key Vault key identifier:
#   https://<vault>.vault.azure.net/keys/<name>[/<version>]
_KMS_AZURE = re.compile(
    r"^https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9]+)?/?$",
    re.IGNORECASE,
)
# GCP Cloud KMS resource identifier:
#   projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<v>]
_KMS_GCP = re.compile(
    r"^projects/[^/\s]+/locations/[^/\s]+/keyRings/[^/\s]+/cryptoKeys/[^/\s]+"
    r"(?:/cryptoKeyVersions/[^/\s]+)?$",
    re.IGNORECASE,
)
# Short Docker Hub image reference (no registry hostname): nginx:latest,
# company/service:1.4.2. A first path component containing '.' or ':' denotes a
# registry hostname, which we do NOT pull — those must be supplied as a
# `docker save` archive or server-local path.
_CONTAINER_REF_COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
_CONTAINER_REF = re.compile(
    rf"^{_CONTAINER_REF_COMPONENT}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}})?"
    rf"(?:@{_CONTAINER_REF_COMPONENT}:[A-Fa-f0-9]+)?"
    rf"(?:/{_CONTAINER_REF_COMPONENT}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}})?"
    rf"(?:@{_CONTAINER_REF_COMPONENT}:[A-Fa-f0-9]+)?)*$"
)


def _is_kms_identifier(value: str) -> bool:
    """Validate AWS ARN / AWS key ID-or-alias, Azure Key Vault, or GCP KMS identifiers."""
    raw = value.strip()
    return bool(
        _KMS_ARN.match(raw)
        or _KMS_KEY_ID.match(raw)
        or _KMS_AZURE.match(raw)
        or _KMS_GCP.match(raw)
    )


def _is_docker_hub_reference(value: str) -> bool:
    """Validate a Docker Hub style image reference (nginx:latest, company/service:1.4.2).

    Registry hostnames (first component containing '.' or ':') are excluded —
    those require an uploaded `docker save` archive instead of a pull.
    """
    raw = value.strip()
    if not raw or len(raw) > 255 or "://" in raw or " " in raw:
        return False
    if not _CONTAINER_REF.match(raw):
        return False
    first = raw.split("/", 1)[0]
    if "/" in raw:
        # A first path component containing '.' or ':' denotes a registry
        # hostname (optionally with port) — those must be supplied as an
        # uploaded archive, never pulled.
        if "." in first or ":" in first:
            return False
    else:
        # Single-component reference (e.g. nginx:latest): ':' is a tag, not a host.
        first_name = re.split(r"[:@]", first, maxsplit=1)[0]
        if "." in first_name:
            return False
    return True


def _uploads_dir() -> Path:
    root = Path(os.environ.get("QRYPTON_UPLOADS", "artifacts/uploads"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def _sanitize_filename(name: str | None) -> str:
    base = Path(name or "artifact").name
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "artifact"
    return safe[:120]


def _artifact_format(filename: str) -> str:
    """Derive a human-readable artifact format from the filename (tar.gz, zip, dll...)."""
    name = (filename or "").casefold()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2"):
        if name.endswith(compound):
            return compound.lstrip(".")
    suffix = Path(name).suffix.lstrip(".")
    return suffix or "unknown"


def _read_upload_meta(artifact_id: str) -> dict[str, Any]:
    """Return preserved upload metadata sidecar for an artifact_id (never raises)."""
    token = (artifact_id or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{16,64}", token):
        return {}
    for sidecar in sorted(_uploads_dir().glob(f"{token}__*.meta.json")):
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}
    return {}


def _strip_upload_scheme(reference: str) -> str:
    """Remove a case-insensitive upload:// scheme prefix (never raises)."""
    token = (reference or "").strip()
    if token[:9].lower() == "upload://":
        token = token[9:]
    return token.strip()


def _resolve_upload(reference: str) -> Path:
    import logging as _logging

    token = _strip_upload_scheme(reference)
    if not re.fullmatch(r"[0-9a-fA-F]{16,64}", token):
        _logging.warning("_resolve_upload rejected malformed reference=%r", reference[:64])
        raise ValueError("unknown artifact reference")
    try:
        matches = sorted(
            p for p in _uploads_dir().glob(f"{token}__*") if not p.name.endswith(".meta.json")
        )
    except OSError as error:
        _logging.exception("_resolve_upload listing failed for token=%r", token[:32])
        raise ValueError(f"uploaded artifact lookup failed: {error}") from error
    if not matches or not matches[0].is_file() or matches[0].is_symlink():
        _logging.warning("_resolve_upload missing/expired token=%r", token[:32])
        raise ValueError("uploaded artifact not found or expired")
    try:
        return matches[0].resolve(strict=True)
    except OSError as error:
        _logging.exception("_resolve_upload resolve failed for token=%r", token[:32])
        raise ValueError(f"uploaded artifact could not be resolved: {error}") from error


def _fetch_tarball_to_source_dir(url: str, prefix: str) -> Path:
    """Download a bounded remote tarball and extract it without executing targets."""
    workspace = Path(tempfile.mkdtemp(prefix=prefix))
    archive_path = workspace / "repository.tar.gz"
    deadline = time.monotonic() + _REMOTE_ACQUISITION_TIMEOUT_SECONDS

    def require_remaining_time() -> None:
        if time.monotonic() >= deadline:
            raise ValueError("repository acquisition exceeded the 30-second limit")

    try:
        with urllib.request.urlopen(url, timeout=10) as response, archive_path.open("wb") as output:
            size = 0
            while chunk := response.read(1024 * 1024):
                require_remaining_time()
                size += len(chunk)
                if size > 64 * 1024 * 1024:
                    raise ValueError("repository archive exceeds download limit")
                output.write(chunk)
        extracted = workspace / "source"
        extracted.mkdir()
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive.getmembers():
                require_remaining_time()
                if not member.isfile():
                    continue
                target = (extracted / member.name).resolve()
                target.relative_to(extracted.resolve())
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is not None:
                    target.write_bytes(source.read(64 * 1024 * 1024))
        archive_path.unlink(missing_ok=True)
        directories = [item for item in extracted.iterdir() if item.is_dir()]
        return directories[0] if len(directories) == 1 else extracted
    except (OSError, tarfile.TarError, urllib.error.URLError, ValueError) as error:
        shutil.rmtree(workspace, ignore_errors=True)
        raise ValueError(f"repository acquisition failed: {error}") from error


def _materialize_kms_descriptor(value: str) -> Path:
    """Persist a KMS key identifier as a static JSON descriptor for inspection.

    Key material is never fetched; only the identifier the user supplied is recorded
    so the scan pipeline has a concrete local artifact to attribute findings to.
    Failures are logged with the (truncated) identifier and re-raised as
    ValueError so the scan endpoint returns a real 422 message instead of an
    empty 500 with no server-side explanation.
    """
    import logging as _logging

    try:
        work = Path(tempfile.mkdtemp(prefix="qrypton-kms-"))
        descriptor = {
            "kms_key_id": value.strip(),
            "note": "KMS key descriptor; static metadata only, no key material accessed.",
        }
        path = work / "kms-key.json"
        path.write_text(json.dumps(descriptor, indent=2), encoding="utf-8")
        return path
    except Exception as error:
        _logging.exception("_materialize_kms_descriptor failed for identifier=%r", value[:64])
        raise ValueError(f"KMS descriptor could not be prepared: {error}") from error


def _materialize_container_descriptor(value: str) -> Path:
    """Persist a container image reference as a static JSON descriptor.

    Registries are never pulled and containers are never started; only the
    image reference the user supplied is recorded so the scan pipeline has a
    concrete local artifact to associate CBOM findings with. Uploaded
    `docker save` archives still take the deep-inspection path (layers, files,
    packages, libraries, configuration). Failures are logged and re-raised as
    ValueError so the caller returns a real error message.
    """
    import logging as _logging

    try:
        work = Path(tempfile.mkdtemp(prefix="qrypton-container-"))
        descriptor = {
            "container_image_reference": value.strip(),
            "note": "Container image reference descriptor; static metadata only, "
            "registry not pulled, container never started.",
        }
        path = work / "container-image.json"
        path.write_text(json.dumps(descriptor, indent=2), encoding="utf-8")
        return path
    except Exception as error:
        _logging.exception("_materialize_container_descriptor failed for reference=%r", value[:64])
        raise ValueError(f"container descriptor could not be prepared: {error}") from error


_HOSTED_GIT_ERROR = "only HTTPS GitHub, GitLab, or Bitbucket source repositories are supported"


def _resolve_repository_locator(request: ScanRequest, fetch_remote: bool = True) -> Path:
    """Resolve uploaded bytes, hosted git URLs, KMS identifiers, or local paths.

    The resolved Path is the *filesystem input for the scanner*. The original
    user-facing artifact (identifier, URL, filename) is preserved separately
    via ``_canonical_target_source`` — resolution never rewrites the request
    into a fake repository representation.
    """
    # Explicit structured source wins over legacy flat fields.
    explicit = _explicit_source(request)
    if explicit.get("type") == "uploaded_artifact":
        for key in ("artifact_id", "artifactId", "id", "locator", "location"):
            value = explicit.get(key)
            if isinstance(value, str) and value.strip():
                token = value.strip()
                if token.lower().startswith("upload://"):
                    return _resolve_upload(token)
                if re.fullmatch(r"[0-9a-fA-F]{16,64}", token):
                    return _resolve_upload(token)
    if explicit.get("type") == "kms_identifier" and explicit.get("identifier"):
        import logging as _logging

        descriptor = _materialize_kms_descriptor(str(explicit["identifier"]))
        _logging.info(
            "_materialize_kms_descriptor type=kms_identifier identifier=%r -> %s",
            str(explicit["identifier"])[:128],
            descriptor,
        )
        return descriptor
    if explicit.get("type") == "container_reference" and explicit.get("reference"):
        ref = str(explicit["reference"]).strip()
        if _is_docker_hub_reference(ref):
            import logging as _logging

            descriptor = _materialize_container_descriptor(ref)
            _logging.info(
                "_materialize_container_descriptor reference=%r -> %s", ref[:128], descriptor
            )
            return descriptor
    if explicit.get("type") == "git_repository" and explicit.get("url"):
        legacy = request.model_copy(
            update={
                "repository": str(explicit["url"]),
                "branch": str(explicit.get("branch") or request.branch or "main"),
                "target_source": None,
            }
        )
        return _resolve_repository_locator(legacy, fetch_remote=fetch_remote)
    if explicit.get("type") == "local_file" and explicit.get("location"):
        return Path(str(explicit["location"])).expanduser().resolve(strict=True)
    artifact_ref = (getattr(request, "artifact_id", None) or "").strip()
    if artifact_ref:
        return _resolve_upload(artifact_ref)
    raw = (request.repository or "").strip()
    if raw.lower().startswith("upload://"):
        return _resolve_upload(raw)
    # Cloud KMS identifiers are resolved before generic HTTPS handling so Azure
    # Key Vault URLs (https://<vault>.vault.azure.net/keys/...) are treated as
    # infrastructure cryptographic assets, never as source repositories.
    if request.target_type == "cloud_kms" and raw:
        candidate = Path(raw).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
            if resolved.is_file() and not resolved.is_symlink():
                return resolved
        except OSError:
            pass
        if _is_kms_identifier(raw):
            import logging as _logging

            descriptor = _materialize_kms_descriptor(raw)
            _logging.info(
                "_materialize_kms_descriptor legacy target_type=cloud_kms identifier=%r -> %s",
                raw[:128],
                descriptor,
            )
            return descriptor
        raise ValueError(
            "cloud KMS target must be an AWS KMS key ARN/ID "
            "(arn:aws:kms:...) , an Azure Key Vault key identifier "
            "(https://<vault>.vault.azure.net/keys/<name>[/<version>]), a GCP KMS "
            "resource (projects/.../keyRings/.../cryptoKeys/...), or an uploaded "
            "KMS JSON export"
        )
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme in {"http", "https"}:
        if parsed.scheme != "https":
            raise ValueError(_HOSTED_GIT_ERROR)
        host = parsed.netloc.casefold()
        branch = urllib.parse.quote(request.branch or "main", safe="")
        if host == "github.com":
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) != 2:
                raise ValueError("GitHub repository URL must identify an owner and repository")
            owner, repository = parts
            repository = repository.removesuffix(".git")
            url = f"https://github.com/{owner}/{repository}/archive/refs/heads/{branch}.tar.gz"
            return (
                Path(tempfile.gettempdir())
                if not fetch_remote
                else _fetch_tarball_to_source_dir(url, prefix="qrypton-github-")
            )
        if host in {"gitlab.com", "www.gitlab.com"}:
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) < 2:
                raise ValueError("GitLab repository URL must identify a group and repository")
            parts[-1] = parts[-1].removesuffix(".git")
            full_path = "/".join(parts)
            repo_name = parts[-1]
            url = f"https://gitlab.com/{full_path}/-/archive/{branch}/{repo_name}-{branch}.tar.gz"
            return (
                Path(tempfile.gettempdir())
                if not fetch_remote
                else _fetch_tarball_to_source_dir(url, prefix="qrypton-gitlab-")
            )
        if host in {"bitbucket.org", "www.bitbucket.org"}:
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) != 2:
                raise ValueError("Bitbucket repository URL must identify an owner and repository")
            owner, repository = parts
            repository = repository.removesuffix(".git")
            url = f"https://bitbucket.org/{owner}/{repository}/get/{branch}.tar.gz"
            return (
                Path(tempfile.gettempdir())
                if not fetch_remote
                else _fetch_tarball_to_source_dir(url, prefix="qrypton-bitbucket-")
            )
        raise ValueError(_HOSTED_GIT_ERROR)
    if request.target_type == "container_image" and raw and "://" not in raw:
        try:
            exists = Path(raw).expanduser().exists()
        except OSError:
            exists = False
        if not exists:
            if _is_docker_hub_reference(raw):
                import logging as _logging

                descriptor = _materialize_container_descriptor(raw)
                _logging.info(
                    "_materialize_container_descriptor legacy reference=%r -> %s",
                    raw[:128],
                    descriptor,
                )
                return descriptor
            if "/" in raw or ":" in raw:
                raise ValueError(
                    "container registries cannot be pulled; upload a docker archive "
                    "(`docker save -o image.tar <image>`) or provide a server-local path"
                )
    return Path(raw).expanduser().resolve(strict=True)


@app.post("/api/v1/uploads")
def upload_artifact(file: Annotated[UploadFile, File()]) -> dict[str, Any]:
    """Accept a real scan artifact (binary, archive, manifest, image tar, KMS export).

    The stored bytes are scanned statically and never executed.
    """
    try:
        data = file.file.read(_MAX_UPLOAD_BYTES + 1)
    finally:
        with contextlib.suppress(OSError):
            file.file.close()
    if not data:
        raise HTTPException(status_code=422, detail="uploaded file is empty")
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="uploaded file exceeds 64 MiB limit")
    artifact_id = secrets.token_hex(16)
    safe_name = _sanitize_filename(file.filename)
    fmt = _artifact_format(safe_name)
    content_type = getattr(file, "content_type", None) or "application/octet-stream"
    path = _uploads_dir() / f"{artifact_id}__{safe_name}"
    try:
        path.write_bytes(data)
        # Preserve original artifact metadata alongside the bytes so the scan
        # pipeline (and later review screens) see the real artifact — name,
        # format, size — instead of a bare temp path.
        sidecar = path.with_name(path.name + ".meta.json")
        sidecar.write_text(
            json.dumps(
                {
                    "artifact_id": artifact_id,
                    "filename": safe_name,
                    "format": fmt,
                    "size_bytes": len(data),
                    "content_type": content_type,
                    "locator": f"upload://{artifact_id}",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError as error:
        raise HTTPException(status_code=503, detail="artifact storage is unavailable") from error
    return {
        "artifact_id": artifact_id,
        "filename": safe_name,
        "format": fmt,
        "content_type": content_type,
        "size_bytes": len(data),
        "locator": f"upload://{artifact_id}",
    }


def _kms_provider(value: str) -> str:
    """Classify a KMS identifier as aws, azure, or gcp (default aws for key IDs)."""
    raw = (value or "").strip()
    if _KMS_AZURE.match(raw):
        return "azure"
    if _KMS_GCP.match(raw):
        return "gcp"
    return "aws"


def _git_provider(host: str) -> str:
    host = (host or "").casefold()
    if "gitlab" in host:
        return "gitlab"
    if "bitbucket" in host:
        return "bitbucket"
    return "github"


def _explicit_source(request: ScanRequest) -> dict[str, Any]:
    """Return the caller-supplied structured target_source, if any (never raises)."""
    try:
        ts = getattr(request, "target_source", None)
        if ts is None:
            return {}
        return ts.model_dump(exclude_none=True) if hasattr(ts, "model_dump") else dict(ts)
    except (ValueError, TypeError, AttributeError):
        return {}


def _upload_meta_for_request(request: ScanRequest) -> dict[str, Any]:
    """Fetch preserved upload sidecar metadata for legacy or structured upload refs."""
    explicit = _explicit_source(request)
    candidates: list[str] = []
    artifact_ref = (getattr(request, "artifact_id", None) or "").strip()
    if artifact_ref:
        candidates.append(artifact_ref)
    raw = (request.repository or "").strip()
    if raw.lower().startswith("upload://"):
        candidates.append(_strip_upload_scheme(raw))
    for key in ("artifact_id", "artifactId", "id", "locator", "location"):
        value = explicit.get(key)
        if isinstance(value, str) and value.strip():
            token = _strip_upload_scheme(value.strip())
            candidates.append(token)
    for token in candidates:
        meta = _read_upload_meta(token)
        if meta:
            return meta
    return {}


def _canonical_target_source(
    request: ScanRequest, upload_meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Derive the preserved original-artifact descriptor (never a fake repo).

    Preference order: explicit ``target_source`` block from the caller, then
    legacy ``repository``/``artifact_id`` fields interpreted per ``target_type``.
    """
    upload_meta = upload_meta or {}
    explicit = _explicit_source(request)
    if explicit.get("type"):
        return dict(explicit)
    target_type = (request.target_type or "").strip()
    raw = (request.repository or "").strip()
    artifact_ref = (getattr(request, "artifact_id", None) or "").strip()
    if target_type == "binary":
        if artifact_ref or raw.lower().startswith("upload://") or upload_meta:
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename") or upload_meta.get("name"),
                "format": upload_meta.get("format"),
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        return {"type": "local_file", "format": "binary", "location": raw}
    if target_type == "source_archive":
        if artifact_ref or raw.lower().startswith("upload://") or upload_meta:
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename"),
                "format": upload_meta.get("format"),
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        return {"type": "local_file", "format": "archive", "location": raw}
    if target_type == "dependency_manifest":
        if artifact_ref or raw.lower().startswith("upload://") or upload_meta:
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename"),
                "format": upload_meta.get("format"),
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        return {"type": "local_file", "format": "manifest", "location": raw}
    if target_type == "container_image":
        if artifact_ref or (upload_meta and upload_meta.get("filename")):
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename"),
                "format": upload_meta.get("format") or "docker_archive",
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        if raw and _is_docker_hub_reference(raw):
            return {"type": "container_reference", "reference": raw}
        return {"type": "local_file", "format": "docker_archive", "location": raw}
    if target_type == "cloud_kms":
        if artifact_ref or (upload_meta and upload_meta.get("filename")):
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename"),
                "format": upload_meta.get("format") or "kms_export",
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        if raw:
            return {
                "type": "kms_identifier",
                "provider": _kms_provider(raw),
                "identifier": raw,
            }
        return {"type": "kms_identifier", "provider": "aws", "identifier": ""}
    if target_type == "source_repo":
        if artifact_ref or raw.lower().startswith("upload://") or upload_meta:
            return {
                "type": "uploaded_artifact",
                "name": upload_meta.get("filename"),
                "format": upload_meta.get("format") or "source_archive",
                "location": upload_meta.get("locator")
                or (f"upload://{artifact_ref}" if artifact_ref else raw),
            }
        try:
            parsed = urllib.parse.urlparse(raw)
            host = parsed.netloc.casefold() if parsed.scheme in {"http", "https"} else ""
        except (ValueError, AttributeError):
            host = ""
        if not host:
            return {"type": "local_file", "format": "source_tree", "location": raw}
        return {
            "type": "git_repository",
            "provider": _git_provider(host),
            "url": raw,
            "branch": (request.branch or "main"),
        }
    return {"type": "unknown", "location": raw}


def _canonical_artifact_metadata(
    request: ScanRequest,
    target_source: dict[str, Any],
    upload_meta: dict[str, Any] | None = None,
    locator: Path | None = None,
) -> dict[str, Any]:
    """Derive preserved artifact name/format/size (never raises)."""
    upload_meta = upload_meta or {}
    try:
        explicit = getattr(request, "artifact_metadata", None)
        explicit_meta = explicit.model_dump(exclude_none=True) if explicit is not None else {}
    except (ValueError, TypeError, AttributeError):
        explicit_meta = {}
    name = (
        explicit_meta.get("name")
        or upload_meta.get("filename")
        or target_source.get("name")
        or target_source.get("identifier")
        or target_source.get("reference")
        or (locator.name if locator is not None else None)
    )
    fmt = (
        explicit_meta.get("format")
        or upload_meta.get("format")
        or target_source.get("format")
        or (_artifact_format(str(name)) if name else "unknown")
    )
    size = explicit_meta.get("size_bytes", upload_meta.get("size_bytes"))
    try:
        size_int = int(size) if size is not None else None
    except (ValueError, TypeError):
        size_int = None
    meta: dict[str, Any] = {}
    if name:
        meta["name"] = name
    if fmt:
        meta["format"] = fmt
    if size_int is not None:
        meta["size_bytes"] = size_int
    content_type = explicit_meta.get("content_type", upload_meta.get("content_type"))
    if content_type:
        meta["content_type"] = content_type
    location = (
        explicit_meta.get("location")
        or upload_meta.get("locator")
        or target_source.get("location")
        or target_source.get("url")
        or target_source.get("identifier")
        or target_source.get("reference")
    )
    if location:
        meta["location"] = location
    return meta


def _original_reference(
    request: ScanRequest,
    target_source: dict[str, Any],
    artifact_metadata: dict[str, Any],
) -> str:
    """Human-meaningful original reference for Asset.external_reference (<=512 chars).

    The preserved artifact NAME wins over bare locators so uploads surface as
    ``libcrypto-3.dll (upload://…)`` instead of an opaque ``upload://…`` id.
    """
    name = artifact_metadata.get("name") or target_source.get("name")
    location = artifact_metadata.get("location")
    if isinstance(name, str) and name.strip():
        if isinstance(location, str) and location.strip() and location.strip() != name.strip():
            return f"{name.strip()} ({location.strip()})"[:512]
        return name.strip()[:512]
    for key in ("identifier", "reference", "url", "location"):
        value = target_source.get(key)
        if isinstance(value, str) and value.strip():
            if key == "url" and target_source.get("branch"):
                return f"{value.strip()} ({target_source['branch']})"[:512]
            return value.strip()[:512]
    raw = (request.repository or "").strip()
    if raw:
        return raw[:512]
    artifact_ref = (getattr(request, "artifact_id", None) or "").strip()
    if artifact_ref:
        return f"upload://{artifact_ref}"[:512]
    return (request.target_type or "unknown")[:512]


# Scanner selection: one normalized SCAN REQUEST concept, target-specific
# scanners. The original target type is preserved (target_source, artifact
# metadata, asset tags) and selects the scanner — never collapsed into a
# generic repository scan.
#
#   SOURCE_CODE (source_repo, source_archive) → source scanner
#   BINARY                                   → binary scanner
#   LIBRARY (dependency_manifest)            → library/dependency scanner
#   CONTAINER (container_image)              → container scanner
#   CLOUD_KMS (cloud_kms)                    → cloud/KMS scanner
SCANNER_ROUTING: dict[str, tuple[ScanTargetKind, str, AssetKind]] = {
    "source_repo": (ScanTargetKind.SOURCE_TREE, "qrypton-source", AssetKind.REPOSITORY),
    "source_archive": (ScanTargetKind.GIT_ARCHIVE, "qrypton-source", AssetKind.REPOSITORY),
    "binary": (ScanTargetKind.FILE, "qrypton-binary", AssetKind.BINARY),
    "dependency_manifest": (ScanTargetKind.FILE, "qrypton-library", AssetKind.OTHER),
    "container_image": (
        ScanTargetKind.OCI_IMAGE,
        "qrypton-container",
        AssetKind.CONTAINER_IMAGE,
    ),
    "cloud_kms": (ScanTargetKind.FILE, "qrypton-kms", AssetKind.OTHER),
}


def _check_locator_shape(
    request: ScanRequest, locator: Path
) -> tuple[ScanTargetKind, str, AssetKind]:
    """Routing-table lookup plus target-specific locator-shape checks.

    Shared by the lightweight pre-queue validation and the full background
    build so both reject the same inputs with identical messages.
    """
    route = SCANNER_ROUTING.get(request.target_type)
    if route is None:
        raise ValueError("unsupported target type")
    target_kind, scanner, asset_kind = route
    if request.target_type == "source_repo":
        if not locator.is_dir():
            raise ValueError("source repository must be a local directory")
    elif request.target_type in {
        "source_archive",
        "binary",
        "dependency_manifest",
        "cloud_kms",
        "container_image",
    } and not locator.is_file():
        if request.target_type == "source_archive":
            raise ValueError(
                "source archive must be an uploaded archive or a server-local file"
            )
        if request.target_type == "binary":
            raise ValueError("binary must be an uploaded binary or a server-local file")
        if request.target_type == "cloud_kms":
            raise ValueError(
                "cloud KMS target must be an AWS KMS key ARN/ID, an Azure Key Vault "
                "key identifier, a GCP KMS resource identifier, or an uploaded KMS JSON export"
            )
        if request.target_type == "container_image":
            raise ValueError(
                "container image must be an image reference (e.g. nginx:latest), "
                "an uploaded docker archive "
                "(`docker save -o image.tar <image>`) or a server-local path"
            )
        raise ValueError(
            "dependency target must be an uploaded package/manifest or a server-local file"
        )
    return target_kind, scanner, asset_kind


def _validate_scan_locator(request: ScanRequest) -> Path:
    """Fast synchronous pre-queue check for POST /api/v1/scans.

    Resolves the locator and verifies route + file/dir shape WITHOUT hashing
    file contents or constructing Asset/Target records — the full
    ``_build_request`` (read_bytes + sha256 + HMAC derivations) runs in the
    background worker. This keeps queue-accept latency flat across target
    types and sizes so the browser's POST timeout never fires on large
    binaries while a prior scan holds the SQLite lock.
    """
    locator = _resolve_repository_locator(request, fetch_remote=False)
    if locator.is_symlink() or not locator.is_file() and not locator.is_dir():
        raise ValueError("target must be an existing local file or directory")
    _check_locator_shape(request, locator)
    return locator


def _build_request(request: ScanRequest, fetch_remote: bool = True) -> tuple[RunRequest, Path]:
    """TARGET NORMALIZATION: user input → target-specific input → SCAN REQUEST.

    Pipeline: USER INPUT → TARGET-SPECIFIC INPUT (upload bytes, KMS
    identifier, image reference, git URL, local path) → TARGET NORMALIZATION
    (this function: resolve a scanner-readable locator while preserving the
    original target in ``target_source``/``artifact_metadata``/asset tags) →
    SCAN REQUEST (RunRequest) → TARGET-SPECIFIC SCANNER (see
    ``SCANNER_ROUTING``) → CRYPTOGRAPHIC FINDINGS → CBOM → RISK/MOSCA →
    DASHBOARD. Normalization never destroys the original target type.
    """
    now = datetime.now(UTC)
    locator = _resolve_repository_locator(request, fetch_remote=fetch_remote)
    report(0, "completed")
    report(1, "running")
    if locator.is_symlink() or not locator.is_file() and not locator.is_dir():
        raise ValueError("target must be an existing local file or directory")
    # Preserve the ORIGINAL artifact (never a fake repo): the filesystem
    # `locator` above feeds the scanner, while `original_reference`,
    # `target_source`, and `artifact_metadata` below preserve what the user
    # actually supplied (upload name/format, KMS identifier+provider,
    # container reference, git URL+provider).
    upload_meta = _upload_meta_for_request(request)
    target_source = _canonical_target_source(request, upload_meta)
    artifact_metadata = _canonical_artifact_metadata(request, target_source, upload_meta, locator)
    original_reference = _original_reference(request, target_source, artifact_metadata)
    # TARGET-SPECIFIC SCANNER selection from the routing table (fail-closed on
    # unknown target types). Locator-shape validation stays target-specific so
    # each error message names the actual target the user selected.
    target_kind, scanner, asset_kind = _check_locator_shape(request, locator)
    tenant_id = os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    deriver = HmacIdDeriver(_API_SECRET)
    source_bytes = locator.read_bytes() if locator.is_file() else str(locator).encode()
    digest = f"sha256:{hashlib.sha256(source_bytes).hexdigest()}"
    provenance = Provenance(
        scanner_name="qrypton-api",
        scanner_version="1.0.0",
        scanner_config_digest=f"sha256:{hashlib.sha256(b'qrypton-api-v1').hexdigest()}",
        observed_at=now,
        source_digest=digest,
    )
    asset_id = deriver.derive(
        namespace="asset",
        tenant_id=tenant_id,
        canonical_payload=canonical_json_bytes(
            {"reference": original_reference, "kind": asset_kind.value}
        ),
    )
    system_name = str(
        getattr(request, "system_name", "")
        or getattr(request.business_context, "system_name", "")
        or artifact_metadata.get("name")
        or target_source.get("identifier")
        or target_source.get("reference")
        or locator.name
    )[:512]
    owner = str(getattr(request, "owner", "") or "").strip() or None
    data_sensitivity = getattr(request, "data_sensitivity", None)
    regulatory_relevance = getattr(request, "regulatory_relevance", None)
    asset_tags: list[str] = []
    asset_tags.append(f"target:{request.target_type}"[:128])
    if request.environment:
        asset_tags.append(f"environment:{request.environment}"[:128])
    source_type = str(target_source.get("type") or "unknown")[:64]
    asset_tags.append(f"source:{source_type}"[:128])
    provider = target_source.get("provider")
    if isinstance(provider, str) and provider.strip():
        asset_tags.append(f"provider:{provider.strip()}"[:128])
    fmt = artifact_metadata.get("format") or target_source.get("format")
    if isinstance(fmt, str) and fmt.strip() and fmt.strip().casefold() != "unknown":
        asset_tags.append(f"format:{fmt.strip()}"[:128])
    asset = Asset(
        id=asset_id,
        tenant_id=tenant_id,
        kind=asset_kind,
        external_reference=original_reference,
        name=system_name,
        owner_reference=owner,
        tags=tuple(asset_tags),
        created_at=now,
        updated_at=now,
        provenance=provenance,
    )
    target_id = deriver.derive(
        namespace="target",
        tenant_id=tenant_id,
        canonical_payload=canonical_json_bytes(
            {"asset": asset_id, "kind": target_kind.value, "locator": str(locator)}
        ),
    )
    target = ScanTarget(
        id=target_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        kind=target_kind,
        locator=str(locator),
        content_digest=_observed(digest, target_id),
        declared_size_bytes=_observed(locator.stat().st_size, target_id),
        requested_at=now,
        provenance=provenance,
    )
    explicit_ctx = getattr(request, "business_context", None)

    def _ctx_field(name: str, default: Any) -> Any:
        try:
            value = getattr(explicit_ctx, name, None) if explicit_ctx is not None else None
        except (ValueError, AttributeError):
            value = None
        if value is None:
            value = default
        if isinstance(value, str) and value.strip().casefold() in {"", "unclassified"}:
            return None
        return value

    ctx_criticality = _ctx_field("business_criticality", request.business_criticality)
    ctx_sensitivity = _ctx_field("data_sensitivity", data_sensitivity)
    ctx_exposure = _ctx_field("internet_exposure", getattr(request, "internet_exposure", None))
    ctx_regulatory = _ctx_field("regulatory_relevance", regulatory_relevance)
    ctx_owner = _ctx_field("owner", owner)
    ctx_environment = _ctx_field("environment", request.environment)
    ctx_migration_complexity = _ctx_field("migration_complexity", request.migration_complexity)

    def context_observation(value: Any, *, unknown_rationale: str) -> Observation[Any]:
        if value is None or (isinstance(value, str) and not value.strip()):
            return Observation(state=ObservationState.UNKNOWN, rationale=unknown_rationale)
        return _observed(value, context_id)

    criticality_value = (
        None
        if ctx_criticality is None or str(ctx_criticality).casefold() in {"", "unclassified"}
        else Criticality(str(ctx_criticality).casefold())
    )

    context_id = deriver.derive(
        namespace="business_context",
        tenant_id=tenant_id,
        canonical_payload=canonical_json_bytes(
            {
                "asset": asset_id,
                "system": system_name,
                "owner": owner,
                "criticality": ctx_criticality,
                "sensitivity": ctx_sensitivity,
                "exposure": ctx_exposure,
                "regulatory": ctx_regulatory,
                "environment": ctx_environment,
                "migration_complexity": ctx_migration_complexity,
                "mosca_x_data_lifetime_years": getattr(explicit_ctx, "data_lifetime", None),
                "mosca_y_migration_years": getattr(explicit_ctx, "migration_time", None),
            }
        ),
    )
    context = BusinessContext(
        id=context_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        criticality=(
            _observed(criticality_value, context_id)
            if criticality_value is not None
            else Observation(
                state=ObservationState.UNKNOWN,
                rationale=(
                    "Business context needs a business criticality value "
                    "to assess business impact."
                ),
            )
        ),
        data_classification=context_observation(
            ctx_sensitivity, unknown_rationale="Data classification was not provided."
        ),
        internet_exposed=context_observation(
            ctx_exposure, unknown_rationale="Internet exposure was not provided."
        ),
        regulatory_scopes=(ctx_regulatory,)
        if ctx_regulatory is not None and str(ctx_regulatory).casefold() not in {"", "none"}
        else (),
        owner_reference=context_observation(
            ctx_owner, unknown_rationale="Business owner was not provided."
        ),
        environment=(
            str(ctx_environment)
            if ctx_environment is not None and str(ctx_environment).casefold() != "unclassified"
            else None
        ),
        migration_complexity=(
            str(ctx_migration_complexity)
            if ctx_migration_complexity is not None
            and str(ctx_migration_complexity).casefold() != "unclassified"
            else None
        ),
        mosca_x_data_lifetime_years=(
            float(explicit_ctx.data_lifetime)
            if explicit_ctx is not None and explicit_ctx.data_lifetime is not None
            else None
        ),
        mosca_y_migration_years=(
            float(explicit_ctx.migration_time)
            if explicit_ctx is not None and explicit_ctx.migration_time is not None
            else None
        ),
        provenance=provenance,
    )
    size_hint: int | None = None
    try:
        explicit_meta = getattr(request, "artifact_metadata", None)
        if explicit_meta is not None and getattr(explicit_meta, "size_bytes", None) is not None:
            size_hint = int(explicit_meta.size_bytes)
        else:
            size_hint = int(locator.stat().st_size) if locator.exists() else None
    except (ValueError, TypeError, OSError):
        size_hint = None
    run_request = RunRequest(
        tenant_id=tenant_id,
        asset=asset,
        target=target,
        limits=_limits(size_hint, request.target_type),
        selected_scanners=(scanner,),
        risk_policy=default_risk_policy(now),
        recommendation_policy=default_recommendation_policy(now),
        business_context=context,
        config_digest=provenance.scanner_config_digest,
        policy_gate=PolicyGate(
            max_allowed_risk=RiskLevel.CRITICAL, fail_on_partial=False, fail_on_scanner_failure=True
        ),
        reference_time=now,
    )
    return run_request, locator


def _status_label(status: Any) -> str:
    value = getattr(status, "value", status)
    return str(value or "").replace("-", "_").replace(" ", "_").upper()


def _exit_code_for_status(status: str) -> int | None:
    if status in {"COMPLETED", "PARTIAL", "SUCCESS"}:
        return 0
    if status in {"FAILED", "FAILURE", "ERROR"}:
        return 2
    return None


def _set_scan_state(scan_id: str, stage: str) -> None:
    with _ACTIVE_SCANS_LOCK:
        _ACTIVE_SCANS[scan_id] = stage


def _clear_scan_state(scan_id: str) -> None:
    with _ACTIVE_SCANS_LOCK:
        _ACTIVE_SCANS.pop(scan_id, None)


def _scan_stage(scan_id: str) -> str | None:
    with _ACTIVE_SCANS_LOCK:
        return _ACTIVE_SCANS.get(scan_id)


def _persist_scan_status(scan_id: str, *, tenant_id: str, status: str) -> None:
    """Persist a lightweight lifecycle state before a full RunResult exists."""
    database_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    with contextlib.closing(sqlite3.connect(database_path, timeout=10)) as connection, connection:
        connection.execute(
            "UPDATE qrypton_runs SET status=? WHERE tenant_id=? AND run_id=?",
            (status, tenant_id, scan_id),
        )
        if status == "running":
            connection.execute(
                "INSERT INTO qrypton_run_heartbeats VALUES (?,?,?) "
                "ON CONFLICT(tenant_id,run_id) DO UPDATE SET updated_at=excluded.updated_at",
                (tenant_id, scan_id, time.time()),
            )


def _orphan_grace_seconds() -> float:
    try:
        seconds = float(os.environ.get("QRYPTON_SCAN_ORPHAN_GRACE_SECONDS", "60"))
        if math.isfinite(seconds) and seconds > 0:
            return seconds
    except ValueError:
        pass
    return 60.0


def _refresh_scan_heartbeat(database: Path, tenant_id: str, scan_id: str) -> None:
    with contextlib.closing(sqlite3.connect(database, timeout=1)) as connection, connection:
        connection.execute(
            "INSERT INTO qrypton_run_heartbeats(tenant_id,run_id,updated_at) "
            "SELECT tenant_id,run_id,? FROM qrypton_runs "
            "WHERE tenant_id=? AND run_id=? AND status='running' "
            "ON CONFLICT(tenant_id,run_id) DO UPDATE SET updated_at=excluded.updated_at",
            (time.time(), tenant_id, scan_id),
        )


def _heartbeat_worker(database: Path, tenant_id: str, scan_id: str, stop: threading.Event) -> None:
    interval = min(10.0, _orphan_grace_seconds() / 3)
    while not stop.wait(interval):
        try:
            _refresh_scan_heartbeat(database, tenant_id, scan_id)
        except Exception:
            logging.exception("Unable to refresh heartbeat for scan %s", scan_id)


def _expire_orphaned_running_scan(database: Path, tenant_id: str, scan_id: str) -> bool:
    # Registration protects local workers; the persisted heartbeat also protects
    # workers owned by another API process. Serialize the check with registration.
    with _ACTIVE_SCANS_LOCK:
        if scan_id in _ACTIVE_SCANS:
            return False
        now = time.time()
        with contextlib.closing(sqlite3.connect(database, timeout=10)) as connection, connection:
            # Old databases have no heartbeat. Give those rows a full grace period
            # starting at first observation, rather than failing them immediately.
            connection.execute(
                "INSERT OR IGNORE INTO qrypton_run_heartbeats(tenant_id,run_id,updated_at) "
                "SELECT tenant_id,run_id,? FROM qrypton_runs "
                "WHERE tenant_id=? AND run_id=? AND status='running'",
                (now, tenant_id, scan_id),
            )
            changed = connection.execute(
                "UPDATE qrypton_runs SET status='failed' "
                "WHERE tenant_id=? AND run_id=? AND status='running' "
                "AND EXISTS (SELECT 1 FROM qrypton_run_heartbeats h "
                "WHERE h.tenant_id=qrypton_runs.tenant_id AND h.run_id=qrypton_runs.run_id "
                "AND h.updated_at < ?)",
                (tenant_id, scan_id, now - _orphan_grace_seconds()),
            )
            return changed.rowcount == 1


def _run_scan_in_background(
    config: QryptonConfig, run_request: RunRequest, *, scan_id: str | None = None
) -> None:
    """Execute one isolated scan outside the HTTP request lifetime."""
    import logging
    import traceback

    if scan_id is None:
        scan_id = build_orchestrator(config).run_id_for(run_request)
    try:
        size_hint: int | None = None
        try:
            declared = getattr(run_request.target, "declared_size_bytes", None)
            if declared is not None and getattr(declared, "state", None) is not None:
                from qrypton.contracts.enums import ObservationState as _Obs

                if declared.state == _Obs.OBSERVED and declared.value is not None:
                    size_hint = int(declared.value)
        except (ValueError, TypeError, AttributeError):
            size_hint = None
        wall_time = min(
            run_request.limits.max_wall_time_seconds,
            _size_scaled_timeout_seconds(size_hint, run_request.target.kind.value),
        )
        asyncio.run(
            asyncio.wait_for(
                build_orchestrator(config).run(run_request, explicit_run_id=scan_id),
                timeout=wall_time,
            )
        )
    except TimeoutError:
        error_trace = traceback.format_exc()
        logging.error(f"Scan {scan_id} timed out after {wall_time} seconds: {error_trace}")
        try:
            from datetime import UTC, datetime

            from qrypton.application.schemas import PolicyOutcome, RunResult
            from qrypton.contracts.enums import RunStatus
            from qrypton.storage.sqlite import SqliteRunStore

            result = RunResult(
                run_id=scan_id,
                tenant_id=run_request.tenant_id,
                status=RunStatus.FAILED,
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
                asset=run_request.asset,
                target=run_request.target,
                business_context=run_request.business_context,
                failures=(
                    RunFailure(
                        stage="store",
                        error_code="scan_timeout",
                        message="failed: exceeded maximum execution time",
                    ),
                ),
                policy_outcome=PolicyOutcome(passed=False, violations=("scan_timeout",)),
            )
            store = SqliteRunStore(config.database_path)
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception as db_error:
            logging.error(f"Failed to mark scan {scan_id} as failed in database: {db_error}")
            raise
        return
    except Exception as error:
        error_trace = traceback.format_exc()
        logging.error(f"Scan {scan_id} failed with unexpected error: {error}\n{error_trace}")
        try:
            from datetime import UTC, datetime

            from qrypton.application.schemas import PolicyOutcome, RunResult
            from qrypton.contracts.enums import RunStatus
            from qrypton.storage.sqlite import SqliteRunStore

            store = SqliteRunStore(config.database_path)
            result = RunResult(
                run_id=scan_id,
                tenant_id=run_request.tenant_id,
                status=RunStatus.FAILED,
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
                asset=run_request.asset,
                target=run_request.target,
                business_context=run_request.business_context,
                failures=(
                    RunFailure(
                        stage="store",
                        error_code="unexpected_worker_error",
                        message=(
                            "Unexpected scan worker failure; "
                            "inspect server logs with the run ID."
                        ),
                    ),
                ),
                policy_outcome=PolicyOutcome(passed=False, violations=("unexpected_error",)),
            )
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception as db_error:
            logging.error(f"Failed to mark scan {scan_id} as failed in database: {db_error}")
            raise
        # The orchestrator persists structured failures for expected scan-stage errors.
        # Unexpected worker errors must not tear down Uvicorn or affect another scan.
        return
    finally:
        _clear_scan_state(scan_id)


def _run_full_scan_in_background(scan_request: ScanRequest, provisional_scan_id: str) -> None:
    """Own resolution, configuration, execution, and cleanup for one queued scan."""
    import logging

    tenant_id = os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    database_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    started_at = datetime.now(UTC)
    run_request: RunRequest | None = None
    stage: Literal["resolve", "configuration", "orchestration"] = "resolve"

    def progress_event(index: int, state: StageState, count: int | None) -> None:
        try:
            scan_progress.record(database_path, tenant_id, provisional_scan_id, index, state, count)
        except sqlite3.Error:
            logging.exception("Unable to record scan telemetry")

    progress_token = observer.set(progress_event)
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    try:
        _set_scan_state(provisional_scan_id, "resolving repository")
        _persist_scan_status(provisional_scan_id, tenant_id=tenant_id, status="running")
        heartbeat_thread = threading.Thread(
            target=_heartbeat_worker,
            args=(database_path, tenant_id, provisional_scan_id, heartbeat_stop),
            name="qrypton-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
        report(0, "running")
        run_request, _ = _build_request(scan_request)
        stage = "configuration"
        config = QryptonConfig(
            workspace_root=Path(run_request.target.locator).parent
            if Path(run_request.target.locator).is_file()
            else Path(run_request.target.locator),
            database_path=database_path,
            id_secret=_API_SECRET,
            mosca_parameters=MoscaParameters(
                data_shelf_life_years=(
                    scan_request.data_lifetime if scan_request.data_lifetime is not None else 7
                ),
                migration_time_years=scan_request.migration_time,
                quantum_threat_horizon_years=scan_request.crqc_horizon,
            ),
        )
        report(1, "completed")
        stage = "orchestration"
        _set_scan_state(provisional_scan_id, "scanning cryptographic evidence")
        _run_scan_in_background(config, run_request, scan_id=provisional_scan_id)
    except Exception as error:
        logging.exception("Scan %s failed during %s", provisional_scan_id, stage)
        if stage == "resolve" and isinstance(error, ValidationError):
            stage = "configuration"
        error_code = {
            "resolve": "target_resolution_failed",
            "configuration": "scan_configuration_failed",
            "orchestration": "unexpected_worker_error",
        }[stage]
        if stage == "resolve":
            error_code = resolution_failure_code(error)
        message = public_failure_message(error_code, stage)
        try:
            result = RunResult(
                run_id=provisional_scan_id,
                tenant_id=tenant_id,
                status=RunStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                asset=run_request.asset if run_request is not None else None,
                target=run_request.target if run_request is not None else None,
                business_context=run_request.business_context if run_request is not None else None,
                failures=(RunFailure(stage=stage, error_code=error_code, message=message),),
                policy_outcome=PolicyOutcome(passed=False, violations=(error_code,)),
            )
            store = SqliteRunStore(database_path)
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception:
            logging.exception("Unable to persist terminal failure for scan %s", provisional_scan_id)
    finally:
        observer.reset(progress_token)
        heartbeat_stop.set()
        if heartbeat_thread is not None and heartbeat_thread.ident is not None:
            heartbeat_thread.join(timeout=2)
        _clear_scan_state(provisional_scan_id)


@app.post("/api/v1/scans")
def create_scan(request: ScanRequest) -> dict[str, Any]:
    """Accept a scan request and return immediately with a provisional scan_id.

    The blocking work (tarball download, AST parsing, risk scoring) is off-loaded
    to a background thread via _run_full_scan_in_background so the browser's
    AbortSignal.timeout on the POST never fires.  The client polls GET
    /api/v1/scans/{scan_id} until the run settles.
    """
    # ── Fast pre-queue validation (resolve + shape only, no content hash) ───
    # Full RunRequest construction (file read + sha256 + HMAC) runs in the
    # background worker so POST latency is flat and the accept is immediate
    # for every target type. Any failure here is a 422 with a real message —
    # never a silent hang or empty 500.
    if not SCANNER_ROUTING.get(request.target_type):
        raise HTTPException(status_code=422, detail="unsupported target type")

    try:
        _validate_scan_locator(request)
    except (ValueError, OSError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:  # fail-closed with a message, never a bare 500
        import logging as _logging

        _logging.exception("scan validation failed unexpectedly")
        raise HTTPException(status_code=422, detail=f"target validation failed: {error}") from error

    # ── Provisional scan_id — stable for the lifetime of this request ────────
    # Derived from user-supplied fields + wall-clock so identical requests in
    # quick succession still get distinct IDs.  The background worker uses this
    # same ID throughout (passes it to the orchestrator as explicit_run_id).
    import time as _time

    tenant_id = os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    raw = f"{tenant_id}:{request.target_type}:{request.repository or ''}:{_time.time()}"
    deriver = HmacIdDeriver(_API_SECRET)
    scan_id = deriver.derive(
        namespace="run",
        tenant_id=tenant_id,
        canonical_payload=canonical_json_bytes({"raw": raw}),
    )

    # ── Derive canonical source/artifact descriptors (no I/O) ───────────────
    upload_meta = _upload_meta_for_request(request)
    canonical_source = _canonical_target_source(request, upload_meta)
    canonical_artifact = _canonical_artifact_metadata(request, canonical_source, upload_meta)

    # ── Persist a lightweight QUEUED row so polling works immediately ────────
    db_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    try:
        store = SqliteRunStore(db_path)
        store.close()
        context_fields = (
            "system_name",
            "owner",
            "environment",
            "business_criticality",
            "data_sensitivity",
            "data_lifetime",
            "internet_exposure",
            "regulatory_relevance",
            "migration_complexity",
            "migration_time",
            "crqc_horizon",
        )
        context = {key: getattr(request, key, None) for key in context_fields}
        if request.business_context is not None:
            context.update(request.business_context.model_dump())
        scan_progress.register(
            db_path,
            tenant_id,
            scan_id,
            json.dumps(
                [
                    request.target_type,
                    (request.repository or "").strip(),
                    request.branch or "main",
                ]
            ),
            context,
        )
        with contextlib.closing(sqlite3.connect(db_path, timeout=10)) as conn, conn:
            conn.execute(
                "INSERT OR IGNORE INTO qrypton_runs(tenant_id,run_id,status) VALUES (?,?,?)",
                (tenant_id, scan_id, "queued"),
            )
    except Exception as db_err:
        raise HTTPException(status_code=503, detail="scan persistence is unavailable") from db_err

    # ── Submit the full scan (download + parse + score) to the thread pool ───
    _set_scan_state(scan_id, "queued")
    try:
        _SCAN_EXECUTOR.submit(_run_full_scan_in_background, request, scan_id)
    except Exception as error:
        logging.exception("Unable to submit scan %s", scan_id)
        try:
            now = datetime.now(UTC)
            result = RunResult(
                run_id=scan_id,
                tenant_id=tenant_id,
                status=RunStatus.FAILED,
                started_at=now,
                completed_at=now,
                failures=(
                    RunFailure(
                        stage="orchestration",
                        error_code="scan_submission_failed",
                        message="Scan could not be queued. Try again.",
                    ),
                ),
                policy_outcome=PolicyOutcome(passed=False, violations=("scan_submission_failed",)),
            )
            store = SqliteRunStore(db_path)
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception:
            logging.exception("Unable to persist submission failure for scan %s", scan_id)
        finally:
            _clear_scan_state(scan_id)
        raise HTTPException(
            status_code=503, detail="Scan could not be queued. Try again."
        ) from error

    return {
        "status": "QUEUED",
        "scan_id": scan_id,
        "run_id": scan_id,
        "current_stage": 0,
        "progress_percent": None,
        "exit_code": None,
        "message": "Static cryptographic scan queued for inspection",
        "total_findings": 0,
        "target_type": request.target_type,
        "target_source": canonical_source,
        "artifact_metadata": canonical_artifact,
        "asset_reference": getattr(request, "repository", None) or request.target_type,
        "scanner": [SCANNER_ROUTING[request.target_type][1]],
        "request": request.model_dump(),
    }


@app.get("/api/v1/scan-context")
def previous_scan_context(target_type: str, repository: str, branch: str = "") -> dict[str, Any]:
    tenant = os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    store = SqliteRunStore(path)
    try:
        context = scan_progress.previous(
            path, tenant, json.dumps([target_type, repository.strip(), branch or "main"])
        )
        if context is not None:
            return {"context": context}
        # Older persisted runs retain canonical context and original asset references.
        for _, run_id, _ in store.list_runs(tenant_id=tenant):
            run = store.get_run(tenant_id=tenant, run_id=run_id)
            if run is None or run.asset is None or run.business_context is None:
                continue
            tags = run.asset.tags
            if f"target:{target_type}" not in tags:
                continue
            reference = run.asset.external_reference
            expected = f"{repository.strip()} ({branch or 'main'})"
            references = {expected}
            if not branch or branch == "main":
                references.add(repository.strip())
                references.add(f"{run.asset.name} ({repository.strip()})")
            if reference not in references:
                continue
            ctx = run.business_context
            return {
                "context": {
                    "system_name": run.asset.name,
                    "owner": ctx.owner_reference.value or "",
                    "environment": ctx.environment or "unclassified",
                    "regulatory_relevance": (
                        ctx.regulatory_scopes[0] if ctx.regulatory_scopes else "unclassified"
                    ),
                    "migration_complexity": ctx.migration_complexity or "unclassified",
                    "migration_time": ctx.mosca_y_migration_years,
                    "business_criticality": ctx.criticality.value or "unclassified",
                    "data_sensitivity": ctx.data_classification.value or "unclassified",
                    "data_lifetime": ctx.mosca_x_data_lifetime_years,
                    "internet_exposure": ctx.internet_exposed.value,
                }
            }
        return {"context": None}
    finally:
        store.close()


@app.get("/api/v1/scans/{scan_id}")
def get_scan(
    scan_id: str,
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
) -> dict[str, Any]:
    result = _get_scan_status(scan_id, tenant_id)
    tenant = tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    result.update(scan_progress.snapshot(path, tenant, scan_id, result["status"]))
    stages = result.get("stages")
    if stages:
        active = [i for i, state in enumerate(stages) if state in {"running", "failed"}]
        visited = [i for i, state in enumerate(stages) if state != "pending"]
        result["current_stage"] = active[0] if active else visited[-1] if visited else 0
    elif result["status"] != "QUEUED":
        result["current_stage"] = None
    return result


def _get_scan_status(
    scan_id: str,
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
) -> dict[str, Any]:
    """Return scan/run status for dashboard polling after submission."""
    database_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    queued_tenant = tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    failure = None
    store = SqliteRunStore(database_path)
    try:
        stored_status = next(
            (
                status
                for _, stored_id, status in store.list_runs(tenant_id=queued_tenant)
                if stored_id == scan_id
            ),
            None,
        )
        if stored_status in {"failed", "failure", "error"}:
            failed_run = store.get_run(tenant_id=queued_tenant, run_id=scan_id)
            if failed_run is not None and failed_run.failures:
                failure = failed_run.failures[0]
    finally:
        store.close()
    if stored_status in {"pending", "queued", "running"}:
        stage = _scan_stage(scan_id)
        if stored_status == "running" and _expire_orphaned_running_scan(
            database_path, queued_tenant, scan_id
        ):
            return {
                "scan_id": scan_id,
                "run_id": scan_id,
                "status": "FAILED",
                "run_status": "FAILED",
                "current_stage": 0,
                "progress_percent": None,
                "exit_code": 2,
                "total_findings": 0,
                "message": "Scan worker was interrupted before completion. Start the scan again.",
            }
        is_queued = stored_status in {"pending", "queued"}
        return {
            "scan_id": scan_id,
            "run_id": scan_id,
            "status": "QUEUED" if is_queued else "RUNNING",
            "run_status": "QUEUED" if is_queued else "RUNNING",
            "current_stage": 0 if is_queued else (1 if stage == "resolving repository" else 3),
            "progress_percent": None,
            "exit_code": None,
            "total_findings": 0,
            "message": "Waiting for an available scan worker"
            if is_queued
            else (stage or "Scan running"),
        }
    if stored_status in {"failed", "failure", "error"}:
        return {
            "scan_id": scan_id,
            "run_id": scan_id,
            "status": "FAILED",
            "run_status": "FAILED",
            "current_stage": 0,
            "progress_percent": None,
            "exit_code": 2,
            "total_findings": 0,
            "message": public_failure_message(
                failure.error_code if failure else "unknown",
                failure.stage if failure else None,
            )
            + f" Run ID: {scan_id}",
            "failure_stage": failure.stage if failure else None,
            "error_code": failure.error_code if failure else None,
        }
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=scan_id)
    status = _status_label(view.posture.run_status)
    is_completed = status in {"COMPLETED", "PARTIAL", "SUCCESS"}
    is_failed = status in {"FAILED", "FAILURE", "ERROR"}
    current_stage = 7 if is_completed else (3 if is_failed else 0)
    return {
        "scan_id": view.summary.run_id,
        "run_id": view.summary.run_id,
        "status": status,
        "run_status": status,
        "current_stage": current_stage,
        "progress_percent": None,
        "exit_code": _exit_code_for_status(status),
        "total_findings": view.posture.total_findings,
    }


@app.get("/api/v1/scans")
def list_scans(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 5,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> JSONResponse:
    """Historical scan summaries derived exclusively from persisted run records."""
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        rows, total = scan_history_page(store._connection, tenant_id, limit, offset)
        for row in rows:
            row["status"] = _status_label(row["status"])
    finally:
        store.close()
    return JSONResponse(content=jsonable_encoder(rows), headers={"X-Total-Count": str(total)})


def _sample_runs(store: SqliteRunStore, tenant_id: str) -> list[RunResult]:
    runs = (
        store.get_run(tenant_id=tenant_id, run_id=run_id)
        for run_id in store.list_runs_with_asset_tag(tenant_id=tenant_id, tag=_SAMPLE_TAG)
    )
    return [
        run
        for run in runs
        if run is not None and run.asset is not None and _SAMPLE_TAG in run.asset.tags
    ]


@app.post("/api/v1/sample-workspace")
def load_sample_workspace() -> dict[str, Any]:
    """Persist two genuine scans of bundled synthetic source, with scoped context."""
    sample_root = Path(__file__).resolve().parents[1] / "sample_payment_app"
    if not sample_root.is_dir():
        raise HTTPException(status_code=503, detail="sample source is unavailable")
    tenant_id = _scan_tenant(None)
    database_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    with _SAMPLE_WORKSPACE_LOCK:
        store = SqliteRunStore(database_path)
        try:
            existing = _sample_runs(store, tenant_id)
            if len(existing) >= 2 and all(
                run.status is RunStatus.COMPLETED and run.cbom and "comparison-v2" in run.asset.tags
                for run in existing[:2]
            ):
                return {
                    "run_id": existing[0].run_id,
                    "earlier_run_id": existing[1].run_id,
                    "sample_data": True,
                }
        finally:
            store.close()

        common = dict(
            target_type="source_repo",
            repository=str(sample_root),
            system_name="Sample payment app",
            owner="Sample payments team",
            data_lifetime=12,
            migration_time=4,
            crqc_horizon=8,
        )
        earlier_request, _ = _build_request(
            ScanRequest(
                **common,
                environment="test",
                business_criticality="low",
                data_sensitivity="internal",
                internet_exposure=False,
            )
        )
        current_request, _ = _build_request(
            ScanRequest(
                **common,
                environment="production",
                business_criticality="critical",
                data_sensitivity="restricted",
                internet_exposure=True,
                regulatory_relevance="payment-card",
                migration_complexity="high",
            )
        )

        def mark_sample(request: RunRequest) -> RunRequest:
            asset = request.asset.model_copy(
                update={
                    "external_reference": "Sample payment app (synthetic)",
                    "tags": (*request.asset.tags, _SAMPLE_TAG, "comparison-v2"),
                }
            )
            return request.model_copy(update={"asset": asset})

        earlier_request = mark_sample(earlier_request)
        current_request = mark_sample(current_request)
        config = QryptonConfig(
            workspace_root=sample_root,
            database_path=database_path,
            id_secret=_API_SECRET,
            mosca_parameters=MoscaParameters(
                data_shelf_life_years=12, migration_time_years=4, quantum_threat_horizon_years=8
            ),
        )
        sample_copy = tempfile.TemporaryDirectory(prefix="qrypton-sample-")
        working = Path(sample_copy.name)
        shutil.copytree(sample_root, working, dirs_exist_ok=True)
        legacy = working / "retired_tls.py"
        legacy.write_text(
            "from Crypto.PublicKey import RSA\ndef legacy_key():\n    return RSA.generate(1024)\n"
        )
        config = config.model_copy(update={"workspace_root": working})
        earlier_request = earlier_request.model_copy(
            update={"target": earlier_request.target.model_copy(update={"locator": str(working)})}
        )
        current_request = current_request.model_copy(
            update={"target": current_request.target.model_copy(update={"locator": str(working)})}
        )
        created: list[str] = []
        try:
            earlier = asyncio.run(build_orchestrator(config).run(earlier_request))
            created.append(earlier.run_id)
            if earlier.status is not RunStatus.COMPLETED or not earlier.findings:
                raise RuntimeError("sample source did not produce a complete earlier scan")
            evidence_paths = {
                item.id: Path(str(item.location.relative_path or "")).name
                for item in earlier.evidence
            }
            case_contexts = {
                "retired_tls.py": dict(
                    environment="test",
                    business_criticality="low",
                    data_sensitivity="internal",
                    internet_exposure=False,
                ),
                "checkout.py": dict(
                    environment="production",
                    business_criticality="critical",
                    data_sensitivity="restricted",
                    internet_exposure=True,
                    regulatory_relevance="payment-card",
                    data_lifetime=12,
                    migration_time=4,
                ),
                "internal_test_tool.py": dict(
                    environment="test",
                    business_criticality="low",
                    data_sensitivity="internal",
                    internet_exposure=False,
                    data_lifetime=1,
                    migration_time=1,
                ),
                "settlement.py": dict(
                    environment="production",
                    business_criticality="medium",
                    data_sensitivity="internal",
                    internet_exposure=False,
                    data_lifetime=7,
                    migration_time=3,
                ),
                "hybrid_gateway.py": dict(
                    environment="production",
                    business_criticality="low",
                    data_sensitivity="public",
                    internet_exposure=False,
                    data_lifetime=8,
                    migration_time=2,
                ),
                "unowned_callback.py": dict(
                    environment=None,
                    business_criticality=None,
                    data_sensitivity=None,
                    internet_exposure=None,
                    data_lifetime=0,
                    migration_time=0,
                ),
            }
            contexts = {
                name: _build_request(
                    ScanRequest(
                        **(common | fields),
                        business_context=BusinessContextPayload(**fields),
                    )
                )[0].business_context
                for name, fields in case_contexts.items()
            }
            finding_contexts = {}
            for finding in earlier.findings:
                names = {evidence_paths.get(evidence_id) for evidence_id in finding.evidence_ids}
                if len(names) != 1 or next(iter(names)) not in contexts:
                    raise RuntimeError("sample finding could not be mapped to one business context")
                if names != {"retired_tls.py"}:
                    finding_contexts[finding.id] = contexts[next(iter(names))]
            current_request = current_request.model_copy(
                update={"finding_business_contexts": finding_contexts}
            )
            # These are source changes before the second scan, never edits to scan history.
            legacy.unlink()
            (working / "new_signer.py").write_text(
                "from pqcrypto.sign import ml_dsa_65\n"
                "def signing_key():\n"
                "    return ml_dsa_65.generate_keypair()\n"
            )
            current = asyncio.run(build_orchestrator(config).run(current_request))
            created.append(current.run_id)
            if current.status is not RunStatus.COMPLETED or not current.cbom:
                raise RuntimeError("sample scan or CBOM export was incomplete")
        except Exception as error:
            cleanup = SqliteRunStore(database_path)
            try:
                for run_id in created:
                    cleanup.delete_run(tenant_id=tenant_id, run_id=run_id)
            finally:
                cleanup.close()
            logging.exception("Unable to load sample workspace")
            raise HTTPException(
                status_code=503, detail="sample workspace could not be loaded"
            ) from error
        finally:
            sample_copy.cleanup()
        return {"run_id": current.run_id, "earlier_run_id": earlier.run_id, "sample_data": True}


@app.delete("/api/v1/sample-workspace")
def remove_sample_workspace() -> dict[str, int]:
    """Remove only tenant-owned runs bearing the persisted synthetic-data tag."""
    with _SAMPLE_WORKSPACE_LOCK:
        store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
        try:
            tenant_id = _scan_tenant(None)
            runs = _sample_runs(store, tenant_id)
            for run in runs:
                store.delete_run(tenant_id=tenant_id, run_id=run.run_id)
        finally:
            store.close()
    return {"removed": len(runs)}


def _scan_tenant(tenant_id: str | None) -> str:
    return tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)


def _persisted_cbom(scan_id: str, tenant_id: str | None) -> bytes:
    tenant = _scan_tenant(tenant_id)
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        cbom = store.get_cbom(tenant_id=tenant, run_id=scan_id)
    finally:
        store.close()
    if cbom is None:
        raise HTTPException(status_code=404, detail="CBOM not found")
    try:
        return sanitize_persisted_cbom(cbom)
    except (ValueError, TypeError) as error:
        raise HTTPException(status_code=500, detail="persisted CBOM is invalid") from error


@app.get("/api/v1/scans/{scan_id}/cbom")
def get_scan_cbom(scan_id: str, tenant_id: Annotated[str | None, Query()] = None) -> Any:
    """Return the exact persisted CycloneDX CBOM generated by the scan."""
    return Response(
        content=_persisted_cbom(scan_id, tenant_id), media_type="application/vnd.cyclonedx+json"
    )


@app.get("/api/v1/scans/{scan_id}/cbom/export")
def export_scan_cbom(
    scan_id: str,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
    tenant_id: Annotated[str | None, Query()] = None,
) -> Response:
    """Download a persisted CycloneDX 1.6 CBOM or analyst-friendly CSV inventory."""
    cbom = _persisted_cbom(scan_id, tenant_id)
    if format == "json":
        return Response(
            content=cbom,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="qrypton-cbom-{scan_id}.cdx.json"'
            },
        )
    try:
        document = json.loads(cbom)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=500, detail="persisted CBOM is invalid") from error
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "Data origin",
            "Finding ID",
            "Asset ID",
            "Finding Category",
            "Asset Name",
            "CBOM Asset Type",
            "Algorithm Identity",
            "Identity Status",
            "Algorithm Family",
            "Variant / Parameters",
            "Crypto Role",
            "Library Metadata",
            "Protocol Metadata",
            "Lifecycle / Context",
            "Evidence / Provenance",
            "Final Severity",
            "Mosca Urgency",
            "Risk Dimensions",
            "NIST PQC Plan",
            "Business Criticality",
            "Confidence",
            "Canonical Finding (JSON)",
        ]
    )

    def property_value(properties: dict[str, Any], name: str) -> Any:
        value = properties.get(name, "")
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    def known_fields(values: dict[str, Any]) -> dict[str, Any]:
        return {name: value for name, value in values.items() if value not in (None, "", [], {})}

    for component in document.get("components", []):
        properties = {
            item.get("name"): item.get("value")
            for item in component.get("properties", [])
            if isinstance(item, dict)
        }
        crypto = component.get("cryptoProperties", {})
        assessment = property_value(properties, "org.qrypton.risk.assessment")
        csv_row = [
            "Sample data"
            if any(
                item.get("name") == "org.qrypton.asset.tag" and item.get("value") == _SAMPLE_TAG
                for item in document.get("metadata", {}).get("component", {}).get("properties", [])
                if isinstance(item, dict)
            )
            else "",
            property_value(properties, "org.qrypton.finding.id"),
            property_value(properties, "org.qrypton.asset.id"),
            property_value(properties, "org.qrypton.finding.category"),
            component.get("name", ""),
            crypto.get("assetType", "") if isinstance(crypto, dict) else "",
            property_value(properties, "org.qrypton.identity.label"),
            property_value(properties, "org.qrypton.identity.status"),
            property_value(properties, "org.qrypton.algorithm.family"),
            property_value(properties, "org.qrypton.algorithm.variant"),
            property_value(properties, "org.qrypton.crypto.role"),
            known_fields(
                {
                    "name": property_value(properties, "org.qrypton.library.name"),
                    "ecosystem": property_value(properties, "org.qrypton.library.ecosystem"),
                }
            ),
            crypto.get("protocolProperties", {}) if isinstance(crypto, dict) else "",
            known_fields(
                {
                    "lifecycle": property_value(properties, "org.qrypton.algorithm.lifecycle"),
                    "parameters": property_value(properties, "org.qrypton.algorithm.parameters"),
                    "observation_state": property_value(
                        properties, "org.qrypton.observation-state"
                    ),
                }
            ),
            {
                "provenance": property_value(properties, "org.qrypton.provenance"),
                "evidence": property_value(properties, "org.qrypton.evidence"),
            },
            assessment.get("level", "unknown") if isinstance(assessment, dict) else "unknown",
            property_value(properties, "org.qrypton.mosca"),
            {
                key: assessment.get(key)
                for key in ("factors", "crypto_risk", "quantum_risk", "business_impact_risk")
                if key in assessment
            }
            if isinstance(assessment, dict)
            else "unknown",
            property_value(properties, "org.qrypton.pqc.plan"),
            property_value(properties, "org.qrypton.business.criticality"),
            property_value(properties, "org.qrypton.finding.confidence"),
            property_value(properties, "org.qrypton.finding.canonical"),
        ]
        writer.writerow(
            [
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                if isinstance(value, (dict, list))
                else value
                for value in csv_row
            ]
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="qrypton-cbom-{scan_id}.csv"'},
    )


class PdfReportRequest(BaseModel):
    run_id: str | None = None
    scan_id: str | None = None
    tenant_id: str | None = None


def _build_pdf_report(scan_id: str, tenant_id: str | None) -> tuple[bytes, str]:
    """Assemble the dynamic PQC PDF from persisted run data (shared by GET/POST)."""
    store = _open_run_store()
    try:
        selected_tenant = tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
        if tenant_id is None:
            # Locate tenant ownership using lightweight metadata, never by
            # deserializing historical runs while searching for this one ID.
            owners = [tid for tid, rid, _ in store.list_runs() if rid == scan_id]
            if owners and selected_tenant not in owners:
                selected_tenant = owners[0]
        run = store.get_run(tenant_id=selected_tenant, run_id=scan_id)
    finally:
        store.close()
    if run is None:
        raise HTTPException(status_code=404, detail="scan record not found")
    view = SqliteDashboardDataProvider.run_view_from_result(run)
    finding_details = SqliteDashboardDataProvider.finding_details_from_result(run)
    content = executive_pdf(
        scan_id=scan_id,
        run=run,
        posture=view.posture,
        inventory=list(view.inventory),
        mosca=list(view.mosca_points),
        roadmap=list(view.roadmap),
        finding_details=finding_details,
    )
    return content, view.summary.run_id


@app.post("/api/v1/reports/pdf")
def create_scan_report_pdf(request: PdfReportRequest) -> Response:
    """Generate the dynamic PQC security report PDF for a completed scan."""
    scan_id = (request.run_id or request.scan_id or "").strip()
    if not scan_id:
        raise HTTPException(status_code=422, detail="run_id (or scan_id) is required")
    content, resolved_id = _build_pdf_report(scan_id, request.tenant_id)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="qrypton-pqc-report-{resolved_id}.pdf"'
        },
    )


@app.get("/api/v1/scans/{scan_id}/report/pdf")
def download_scan_report(
    scan_id: str, tenant_id: Annotated[str | None, Query()] = None
) -> Response:
    """Download a branded, self-contained executive post-quantum report."""
    content, resolved_id = _build_pdf_report(scan_id, tenant_id)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="qrypton-executive-report-{resolved_id}.pdf"'
            )
        },
    )


@app.delete("/api/v1/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, tenant_id: Annotated[str | None, Query()] = None) -> Response:
    """Remove exactly one tenant-scoped scan from history."""
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        deleted = store.delete_run(tenant_id=_scan_tenant(tenant_id), run_id=scan_id)
    finally:
        store.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="scan not found")
    return Response(status_code=204)


@app.get("/api/v1/findings/{finding_id}")
def get_finding(
    finding_id: str,
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> FindingDetail:
    """Returns finding evidence details."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    detail = provider.get_finding_detail(
        tenant_id=view.summary.tenant_id, run_id=view.summary.run_id, finding_id=finding_id
    )
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    row = next(
        (row for row in _investigation_view(view).inventory if row.finding_id == finding_id), None
    )
    return detail.model_copy(
        update={
            "assigned_owner": row.assigned_owner if row else None,
            "migration_status": row.migration_status if row else "untriaged",
            "in_roadmap": row.in_roadmap if row else False,
        }
    )


@app.get("/api/v1/mosca/eval")
def get_mosca_eval(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[MoscaPoint]:
    """Calculates Mosca timeline exposure."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.mosca_points)


@app.get("/api/v1/heatmap")
def get_heatmap(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[RiskHeatmapCell]:
    """Returns finding counts categorized into a matrix."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.heatmap_cells)


def _risk_matrix(
    provider: DashboardDataProvider, *, tenant_id: str | None, run_id: str | None
) -> dict[str, Any]:
    """Serialize the provider's canonical per-finding Mosca × criticality aggregation."""
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    cells = [cell.model_dump(mode="json") for cell in view.heatmap_cells]
    return {"scan_id": view.summary.run_id, "cells": cells}


@app.get("/api/v1/risk")
def get_risk_matrix(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> dict[str, Any]:
    """Return the latest/requested 30-cell Mosca urgency × business criticality grid."""
    return _risk_matrix(get_provider(tenant_id=tenant_id), tenant_id=tenant_id, run_id=run_id)


@app.get("/api/v1/scans/{scan_id}/risk")
def get_scan_risk_matrix(
    scan_id: str, tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None
) -> dict[str, Any]:
    """Return 30 urgency × business-criticality buckets for the selected scan."""
    return _risk_matrix(get_provider(tenant_id=tenant_id), tenant_id=tenant_id, run_id=scan_id)


@app.get("/api/v1/roadmap")
def get_roadmap(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[RoadmapRow]:
    """Returns an ordered PQC Migration Roadmap."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(_investigation_view(view).roadmap)
