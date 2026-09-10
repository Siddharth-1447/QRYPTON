# type: ignore
"""FastAPI backend application for QRYPTON cryptographic posture and inventory."""

from __future__ import annotations

import asyncio
import csv
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel

from qrypton.api.reporting import executive_pdf
from qrypton.application.config import (
    QryptonConfig,
    build_orchestrator,
    default_recommendation_policy,
    default_risk_policy,
)
from qrypton.application.schemas import PolicyGate, RunRequest, RunFailure
from qrypton.contracts.enums import (
    AssetKind,
    Criticality,
    ObservationState,
    RiskLevel,
    ScanTargetKind,
)
from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, BusinessContext, Observation, Provenance, ScanTarget
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
from qrypton.ui.mock_provider import MockDashboardDataProvider
from qrypton.ui.provider import DashboardDataProvider
from qrypton.ui.sqlite_provider import SqliteDashboardDataProvider

app = FastAPI(title="QRYPTON Cryptographic Inventory API")
_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="qrypton-scan")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_provider(tenant_id: str | None = None) -> DashboardDataProvider:
    """Return the authoritative persisted-data provider.

    Mock dashboard records are intentionally never used by HTTP handlers: an
    unavailable or empty database must remain visibly empty, not look healthy.
    """
    candidates: list[Path] = []
    env_db = os.environ.get("QRYPTON_DB")
    if env_db:
        candidates.append(Path(env_db))
    else:
        candidates.extend([Path("qrypton.db"), Path("qrypton.sqlite3"), Path("qrypton_demo.db")])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                sqlite_provider = SqliteDashboardDataProvider(candidate)
                return sqlite_provider
            except Exception:
                continue
    raise HTTPException(status_code=503, detail="scan persistence is unavailable")


def _resolve_view(
    provider: DashboardDataProvider,
    tenant_id: str | None = None,
    run_id: str | None = None,
) -> DashboardRunView:
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
    return list(view.inventory)


@app.get("/api/v1/posture")
def get_posture(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> ExecutivePosture:
    """Retrieve executive cryptographic posture metrics for the active or requested run."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return view.posture


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
    environment: str = "production"
    business_criticality: str = "critical"
    data_sensitivity: str = "internal"
    internet_exposure: bool = False
    regulatory_relevance: str = "none"
    migration_complexity: str = "medium"
    data_lifetime: float = 0
    migration_time: float = 0
    crqc_horizon: float = 0


class ScanRequest(BaseModel):
    target_type: str
    repository: str = ""
    artifact_id: str | None = None
    branch: str = "main"
    environment: str
    business_criticality: str
    system_name: str = ""
    owner: str = ""
    data_sensitivity: str = "internal"
    internet_exposure: bool = False
    regulatory_relevance: str = "none"
    migration_complexity: str = "medium"
    data_lifetime: float
    migration_time: float
    crqc_horizon: float
    # Structured original-artifact preservation (preferred; legacy
    # repository/artifact_id fields above remain accepted for compat).
    target_source: TargetSource | None = None
    artifact_metadata: ArtifactMetadata | None = None
    business_context: BusinessContextPayload | None = None


_API_SECRET = os.environ.get("QRYPTON_ID_SECRET", "").encode() or os.urandom(32)


def _limits() -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=64 * 1024 * 1024,
        max_expanded_bytes=512 * 1024 * 1024,
        max_file_count=100_000,
        max_nesting_depth=8,
        max_layer_count=128,
        max_ast_nodes=1_000_000,
        max_evidence_count=100_000,
        max_wall_time_seconds=300,
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
def _resolve_upload(reference: str) -> Path:
    token = reference.strip().removeprefix("upload://").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{16,64}", token):
        raise ValueError("unknown artifact reference")
    matches = sorted(
        p for p in _uploads_dir().glob(f"{token}__*")
        if not p.name.endswith(".meta.json")
    )
    if not matches or not matches[0].is_file() or matches[0].is_symlink():
        raise ValueError("uploaded artifact not found or expired")
    return matches[0].resolve(strict=True)


def _fetch_tarball_to_source_dir(url: str, prefix: str) -> Path:
    """Download a bounded remote tarball and extract it without executing targets."""
    workspace = Path(tempfile.mkdtemp(prefix=prefix))
    archive_path = workspace / "repository.tar.gz"
    try:
        with urllib.request.urlopen(url, timeout=10) as response, archive_path.open("wb") as output:
            socket.setdefaulttimeout(10)
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 64 * 1024 * 1024:
                    raise ValueError("repository archive exceeds download limit")
                output.write(chunk)
        extracted = workspace / "source"
        extracted.mkdir()
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive.getmembers():
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
    except (OSError, tarfile.TarError, urllib.error.URLError) as error:
        shutil.rmtree(workspace, ignore_errors=True)
        raise ValueError(f"repository acquisition failed: {error}") from error


def _materialize_kms_descriptor(value: str) -> Path:
    """Persist a KMS key identifier as a static JSON descriptor for inspection.

    Key material is never fetched; only the identifier the user supplied is recorded
    so the scan pipeline has a concrete local artifact to attribute findings to.
    """
    work = Path(tempfile.mkdtemp(prefix="qrypton-kms-"))
    descriptor = {
        "kms_key_id": value.strip(),
        "note": "KMS key descriptor; static metadata only, no key material accessed.",
    }
    path = work / "kms-key.json"
    path.write_text(json.dumps(descriptor, indent=2), encoding="utf-8")
    return path


def _materialize_container_descriptor(value: str) -> Path:
    """Persist a container image reference as a static JSON descriptor.

    Registries are never pulled and containers are never started; only the
    image reference the user supplied is recorded so the scan pipeline has a
    concrete local artifact to associate CBOM findings with. Uploaded
    `docker save` archives still take the deep-inspection path (layers, files,
    packages, libraries, configuration).
    """
    work = Path(tempfile.mkdtemp(prefix="qrypton-container-"))
    descriptor = {
        "container_image_reference": value.strip(),
        "note": "Container image reference descriptor; static metadata only, "
        "registry not pulled, container never started.",
    }
    path = work / "container-image.json"
    path.write_text(json.dumps(descriptor, indent=2), encoding="utf-8")
    return path


_HOSTED_GIT_ERROR = (
    "only HTTPS GitHub, GitLab, or Bitbucket source repositories are supported"
)


def _resolve_repository_locator(request: ScanRequest) -> Path:
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
        return _materialize_kms_descriptor(str(explicit["identifier"]))
    if explicit.get("type") == "container_reference" and explicit.get("reference"):
        ref = str(explicit["reference"]).strip()
        if _is_docker_hub_reference(ref):
            return _materialize_container_descriptor(ref)
    if explicit.get("type") == "git_repository" and explicit.get("url"):
        legacy = request.model_copy(
            update={
                "repository": str(explicit["url"]),
                "branch": str(explicit.get("branch") or request.branch or "main"),
                "target_source": None,
            }
        )
        return _resolve_repository_locator(legacy)
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
            return _materialize_kms_descriptor(raw)
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
            return _fetch_tarball_to_source_dir(url, prefix="qrypton-github-")
        if host in {"gitlab.com", "www.gitlab.com"}:
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) < 2:
                raise ValueError("GitLab repository URL must identify a group and repository")
            parts[-1] = parts[-1].removesuffix(".git")
            full_path = "/".join(parts)
            repo_name = parts[-1]
            url = f"https://gitlab.com/{full_path}/-/archive/{branch}/{repo_name}-{branch}.tar.gz"
            return _fetch_tarball_to_source_dir(url, prefix="qrypton-gitlab-")
        if host in {"bitbucket.org", "www.bitbucket.org"}:
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) != 2:
                raise ValueError("Bitbucket repository URL must identify an owner and repository")
            owner, repository = parts
            repository = repository.removesuffix(".git")
            url = f"https://bitbucket.org/{owner}/{repository}/get/{branch}.tar.gz"
            return _fetch_tarball_to_source_dir(url, prefix="qrypton-bitbucket-")
        raise ValueError(_HOSTED_GIT_ERROR)
    if request.target_type == "container_image" and raw and "://" not in raw:
        try:
            exists = Path(raw).expanduser().exists()
        except OSError:
            exists = False
        if not exists:
            if _is_docker_hub_reference(raw):
                return _materialize_container_descriptor(raw)
            if "/" in raw or ":" in raw:
                raise ValueError(
                    "container registries cannot be pulled; upload a docker archive "
                    "(`docker save -o image.tar <image>`) or provide a server-local path"
                )
    return Path(raw).expanduser().resolve(strict=True)


@app.post("/api/v1/uploads")
def upload_artifact(file: UploadFile = File(...)) -> dict[str, Any]:
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
        candidates.append(raw.removeprefix("upload://").removeprefix("Upload://").strip())
    for key in ("artifact_id", "artifactId", "id", "locator", "location"):
        value = explicit.get(key)
        if isinstance(value, str) and value.strip():
            token = value.strip().removeprefix("upload://").strip()
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
        explicit_meta = (
            explicit.model_dump(exclude_none=True) if explicit is not None else {}
        )
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


def _build_request(request: ScanRequest) -> tuple[RunRequest, Path]:
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
    locator = _resolve_repository_locator(request)
    if locator.is_symlink() or not locator.is_file() and not locator.is_dir():
        raise ValueError("target must be an existing local file or directory")
    # Preserve the ORIGINAL artifact (never a fake repo): the filesystem
    # `locator` above feeds the scanner, while `original_reference`,
    # `target_source`, and `artifact_metadata` below preserve what the user
    # actually supplied (upload name/format, KMS identifier+provider,
    # container reference, git URL+provider).
    upload_meta = _upload_meta_for_request(request)
    target_source = _canonical_target_source(request, upload_meta)
    artifact_metadata = _canonical_artifact_metadata(
        request, target_source, upload_meta, locator
    )
    original_reference = _original_reference(request, target_source, artifact_metadata)
    # TARGET-SPECIFIC SCANNER selection from the routing table (fail-closed on
    # unknown target types). Locator-shape validation stays target-specific so
    # each error message names the actual target the user selected.
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
    }:
        if not locator.is_file():
            if request.target_type == "source_archive":
                raise ValueError(
                    "source archive must be an uploaded archive or a server-local file"
                )
            if request.target_type == "binary":
                raise ValueError(
                    "binary must be an uploaded binary or a server-local file"
                )
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
        or artifact_metadata.get("name")
        or target_source.get("identifier")
        or target_source.get("reference")
        or locator.name
    )[:512]
    owner = str(getattr(request, "owner", "") or "unassigned")
    data_sensitivity = str(getattr(request, "data_sensitivity", "internal") or "internal")
    regulatory_relevance = str(getattr(request, "regulatory_relevance", "none") or "none")
    asset_tags: list[str] = []
    asset_tags.append(f"target:{request.target_type}"[:128])
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
    context_id = deriver.derive(
        namespace="business_context",
        tenant_id=tenant_id,
        canonical_payload=canonical_json_bytes(
            {"asset": asset_id, "system": system_name, "owner": owner}
        ),
    )
    # Explicit business_context block wins per-field over legacy flat fields,
    # so business context is preserved as its own object, never folded into
    # the locator.
    explicit_ctx = getattr(request, "business_context", None)
    def _ctx_field(name: str, default: Any) -> Any:
        try:
            value = getattr(explicit_ctx, name, None) if explicit_ctx is not None else None
        except (ValueError, AttributeError):
            value = None
        if value is None or (isinstance(value, str) and not value.strip()):
            return default
        return value

    ctx_criticality = str(_ctx_field("business_criticality", request.business_criticality))
    ctx_sensitivity = str(_ctx_field("data_sensitivity", data_sensitivity))
    ctx_exposure = bool(_ctx_field("internet_exposure", bool(getattr(request, "internet_exposure", False))))
    ctx_regulatory = str(_ctx_field("regulatory_relevance", regulatory_relevance))
    ctx_owner = str(_ctx_field("owner", owner))
    context = BusinessContext(
        id=context_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        criticality=_observed(Criticality(ctx_criticality), context_id),
        data_classification=_observed(ctx_sensitivity, context_id),
        internet_exposed=_observed(ctx_exposure, context_id),
        regulatory_scopes=(ctx_regulatory,)
        if ctx_regulatory not in {"", "none"}
        else (),
        owner_reference=_observed(ctx_owner, context_id),
        provenance=provenance,
    )
    run_request = RunRequest(
        tenant_id=tenant_id,
        asset=asset,
        target=target,
        limits=_limits(),
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


def _run_scan_in_background(config: QryptonConfig, run_request: RunRequest) -> None:
    """Execute one isolated scan outside the HTTP request lifetime."""
    import logging
    import traceback
    scan_id = build_orchestrator(config).run_id_for(run_request)
    try:
        asyncio.run(asyncio.wait_for(build_orchestrator(config).run(run_request), timeout=300))
    except asyncio.TimeoutError:
        error_trace = traceback.format_exc()
        logging.error(f"Scan {scan_id} timed out after 300 seconds: {error_trace}")
        try:
            from datetime import UTC, datetime
            from qrypton.application.schemas import RunResult, PolicyOutcome
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
                failures=(RunFailure(stage="store", error_code="scan_timeout", message="Scan exceeded the configured execution limit."),),
                policy_outcome=PolicyOutcome(passed=False, violations=("scan_timeout",)),
            )
            store = SqliteRunStore(config.database_path)
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception as db_error:
            logging.error(f"Failed to mark scan {scan_id} as failed in database: {db_error}")
        return
    except Exception as error:
        error_trace = traceback.format_exc()
        logging.error(f"Scan {scan_id} failed with unexpected error: {error}\n{error_trace}")
        try:
            from datetime import UTC, datetime
            from qrypton.application.schemas import RunResult, PolicyOutcome
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
                failures=(RunFailure(
                    stage="store",
                    error_code="unexpected_worker_error",
                    message="Unexpected scan worker failure; inspect server logs with the run ID."
                ),),
                policy_outcome=PolicyOutcome(passed=False, violations=("unexpected_error",)),
            )
            try:
                store.finalize_run(result)
            finally:
                store.close()
        except Exception as db_error:
            logging.error(f"Failed to mark scan {scan_id} as failed in database: {db_error}")
        # The orchestrator persists structured failures for expected scan-stage errors.
        # Unexpected worker errors must not tear down Uvicorn or affect another scan.
        return


@app.post("/api/v1/scans")
def create_scan(request: ScanRequest) -> dict[str, Any]:
    try:
        run_request, _ = _build_request(request)
        upload_meta = _upload_meta_for_request(request)
        canonical_source = _canonical_target_source(request, upload_meta)
        canonical_artifact = _canonical_artifact_metadata(
            request, canonical_source, upload_meta
        )
        config = QryptonConfig(
            workspace_root=Path(run_request.target.locator).parent
            if Path(run_request.target.locator).is_file()
            else Path(run_request.target.locator),
            database_path=Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")),
            id_secret=_API_SECRET,
            mosca_parameters=MoscaParameters(
                data_shelf_life_years=request.data_lifetime,
                migration_time_years=request.migration_time,
                quantum_threat_horizon_years=request.crqc_horizon,
            ),
        )
        orchestrator = build_orchestrator(config)
        scan_id = orchestrator.run_id_for(run_request)
        store = SqliteRunStore(config.database_path)
        try:
            store.begin_run(run_request, run_id=scan_id)
        finally:
            store.close()
        _SCAN_EXECUTOR.submit(_run_scan_in_background, config, run_request)
        status = "QUEUED"
    except sqlite3.DatabaseError as error:
        raise HTTPException(status_code=503, detail="scan persistence is unavailable") from error
    except (ValueError, OSError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "status": status,
        "scan_id": scan_id,
        "run_id": scan_id,
        "exit_code": None,
        "message": "Static cryptographic scan queued for inspection",
        "total_findings": 0,
        "target_type": request.target_type,
        "target_source": canonical_source,
        "artifact_metadata": canonical_artifact,
        "asset_reference": run_request.asset.external_reference,
        "scanner": list(run_request.selected_scanners),
        "request": request.model_dump(),
    }


@app.get("/api/v1/scans/{scan_id}")
def get_scan(
    scan_id: str,
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
) -> dict[str, Any]:
    """Return scan/run status for dashboard polling after submission."""
    database_path = Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    queued_tenant = tenant_id or os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)
    if any(
        stored_id == scan_id and status in {"pending", "queued", "running"}
        for stored_tenant, stored_id, status in SqliteRunStore(database_path).list_runs(
            tenant_id=queued_tenant
        )
    ):
        return {
            "scan_id": scan_id,
            "run_id": scan_id,
            "status": "QUEUED",
            "run_status": "QUEUED",
            "exit_code": None,
            "total_findings": 0,
        }
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=scan_id)
    status = _status_label(view.posture.run_status)
    return {
        "scan_id": view.summary.run_id,
        "run_id": view.summary.run_id,
        "status": status,
        "run_status": status,
        "exit_code": _exit_code_for_status(status),
        "total_findings": view.posture.total_findings,
    }


@app.get("/api/v1/scans")
def list_scans(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
) -> list[dict[str, Any]]:
    """Historical scan summaries derived exclusively from persisted run records."""
    provider = get_provider(tenant_id=tenant_id)
    rows: list[dict[str, Any]] = []
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        for summary in provider.list_runs(tenant_id=tenant_id):
            view = provider.get_run_view(tenant_id=summary.tenant_id, run_id=summary.run_id)
            run = store.get_run(tenant_id=summary.tenant_id, run_id=summary.run_id)
            target = run.asset.external_reference if run and run.asset else "unavailable"
            tags = run.asset.tags if run and run.asset else ()
            target_type = next((tag.removeprefix("target:") for tag in tags if tag.startswith("target:")), "unknown")
            environment = next((tag.removeprefix("environment:") for tag in tags if tag.startswith("environment:")), "unknown")
            posture = view.posture if view else None
            rows.append({
                "scan_id": summary.run_id, "run_id": summary.run_id,
                "tenant_id": summary.tenant_id, "status": _status_label(summary.status),
                "started_at": summary.started_at, "completed_at": summary.completed_at,
                "artifact": target, "target_type": target_type, "environment": environment,
                "total_findings": summary.total_findings or 0,
                "highest_risk": next((level for level, count in (("critical", posture.critical_findings_count if posture else 0), ("high", posture.high_findings_count if posture else 0), ("medium", posture.medium_findings_count if posture else 0), ("low", posture.low_findings_count if posture else 0)) if count), "unknown"),
                "critical_findings_count": posture.critical_findings_count if posture else 0,
                "high_findings_count": posture.high_findings_count if posture else 0,
                "medium_findings_count": posture.medium_findings_count if posture else 0,
            })
    finally:
        store.close()
    return rows


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
    return cbom


@app.get("/api/v1/scans/{scan_id}/cbom")
def get_scan_cbom(scan_id: str, tenant_id: Annotated[str | None, Query()] = None) -> Any:
    """Return the exact persisted CycloneDX CBOM generated by the scan."""
    return Response(content=_persisted_cbom(scan_id, tenant_id), media_type="application/vnd.cyclonedx+json")


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
            headers={"Content-Disposition": f'attachment; filename="qrypton-cbom-{scan_id}.cdx.json"'},
        )
    try:
        document = json.loads(cbom)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=500, detail="persisted CBOM is invalid") from error
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Asset Name", "Asset Type", "Primitive", "Location/Path", "Classical Risk", "Quantum Risk (Mosca)", "NIST PQC Target", "Business Criticality"])
    for component in document.get("components", []):
        properties = {item.get("name"): item.get("value") for item in component.get("properties", []) if isinstance(item, dict)}
        crypto = component.get("cryptoProperties", {})
        algorithm = crypto.get("algorithmProperties", {}) if isinstance(crypto, dict) else {}
        assessment = properties.get("org.qrypton.risk.assessment", "")
        mosca = properties.get("org.qrypton.mosca", "")
        plan = properties.get("org.qrypton.pqc.plan", "")
        evidence = properties.get("org.qrypton.evidence", "")
        writer.writerow([component.get("name", ""), crypto.get("assetType", "") if isinstance(crypto, dict) else "", algorithm.get("primitive", ""), evidence, assessment, mosca, plan, properties.get("org.qrypton.business.criticality", "")])
    return Response(
        content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="qrypton-cbom-{scan_id}.csv"'},
    )


@app.get("/api/v1/scans/{scan_id}/report/pdf")
def download_scan_report(scan_id: str, tenant_id: Annotated[str | None, Query()] = None) -> Response:
    """Download a branded, self-contained executive post-quantum report."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=scan_id)
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        run = store.get_run(tenant_id=view.summary.tenant_id, run_id=scan_id)
    finally:
        store.close()
    if run is None:
        raise HTTPException(status_code=404, detail="scan record not found")
    content = executive_pdf(scan_id=scan_id, run=run, posture=view.posture, inventory=list(view.inventory), mosca=list(view.mosca_points), roadmap=list(view.roadmap))
    return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="qrypton-executive-report-{scan_id}.pdf"'})


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
    return detail


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


_MATRIX_URGENCIES = (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW)
_MATRIX_CRITICALITIES = ("low", "medium", "high", "critical")


def _risk_matrix(provider: DashboardDataProvider, *, tenant_id: str | None, run_id: str | None) -> dict[str, Any]:
    """Build the canonical 4×4 UI matrix directly from persisted findings."""
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    store = SqliteRunStore(Path(os.environ.get("QRYPTON_DB", "qrypton.sqlite3")))
    try:
        run = store.get_run(tenant_id=view.summary.tenant_id, run_id=view.summary.run_id)
    finally:
        store.close()
    business_criticality = "low"
    if run is not None and run.business_context is not None:
        observed = run.business_context.criticality
        if observed.state == ObservationState.OBSERVED and observed.value in {
            Criticality.LOW, Criticality.MEDIUM, Criticality.HIGH, Criticality.CRITICAL,
        }:
            business_criticality = observed.value.value
    urgency_by_id = {point.finding_id: point.urgency for point in view.mosca_points}
    risk_by_id = {item.finding_id: item.risk_level for item in view.inventory}
    buckets: dict[tuple[RiskLevel, str], list[str]] = {
        (urgency, criticality): []
        for urgency in _MATRIX_URGENCIES
        for criticality in _MATRIX_CRITICALITIES
    }
    for finding in view.inventory:
        urgency = urgency_by_id.get(
            finding.finding_id, risk_by_id.get(finding.finding_id, RiskLevel.MEDIUM)
        )
        if urgency not in _MATRIX_URGENCIES:
            urgency = RiskLevel.MEDIUM
        buckets[(urgency, business_criticality)].append(finding.finding_id)
    cells = [
        {
            "mosca_urgency": urgency.value,
            "business_criticality": criticality,
            "finding_count": len(ids),
            "finding_ids": ids,
        }
        for urgency in _MATRIX_URGENCIES
        for criticality in _MATRIX_CRITICALITIES
        for ids in (buckets[(urgency, criticality)],)
    ]
    return {"scan_id": view.summary.run_id, "cells": cells}


@app.get("/api/v1/risk")
def get_risk_matrix(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> dict[str, Any]:
    """Return the latest/requested 16-cell Mosca urgency × business criticality grid."""
    return _risk_matrix(get_provider(tenant_id=tenant_id), tenant_id=tenant_id, run_id=run_id)


@app.get("/api/v1/scans/{scan_id}/risk")
def get_scan_risk_matrix(
    scan_id: str, tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None
) -> dict[str, Any]:
    """Return exactly 16 density buckets for the selected persisted scan."""
    return _risk_matrix(get_provider(tenant_id=tenant_id), tenant_id=tenant_id, run_id=scan_id)


@app.get("/api/v1/roadmap")
def get_roadmap(
    tenant_id: Annotated[str | None, Query(description="Filter by tenant ID")] = None,
    run_id: Annotated[str | None, Query(description="Filter by run ID")] = None,
) -> list[RoadmapRow]:
    """Returns an ordered PQC Migration Roadmap."""
    provider = get_provider(tenant_id=tenant_id)
    view = _resolve_view(provider, tenant_id=tenant_id, run_id=run_id)
    return list(view.roadmap)
