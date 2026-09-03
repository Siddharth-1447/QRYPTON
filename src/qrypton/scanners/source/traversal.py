"""Safe, deterministic local source-tree traversal."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pathspec
from pathspec.pattern import Pattern

from qrypton.contracts.models import ScanTarget
from qrypton.contracts.primitives import RelativePath, Sha256Digest
from qrypton.ports.scanners import ScanLimits
from qrypton.scanners.source.policy import SourceScanPolicy

HARD_IGNORES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "site-packages",
    }
)


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: Path
    relative_path: RelativePath
    raw_bytes: bytes
    digest: Sha256Digest
    language: str
    text: str
    encoding_degraded: bool = False


@dataclass(frozen=True, slots=True)
class TraversalResult:
    files: tuple[SourceFile, ...]
    warnings: tuple[str, ...]
    partial: bool


def resolve_source_root(target: ScanTarget, *, policy: SourceScanPolicy) -> Path:
    """Resolve a target locator and require it to stay under the approved local root."""
    if target.kind.value != "source_tree":
        raise ValueError("source scanner only supports source_tree targets")
    locator = target.locator
    if "\x00" in locator:
        raise ValueError("target locator contains NUL")
    root = Path(locator).resolve(strict=True)
    approved = policy.allowed_root.resolve(strict=True)
    try:
        root.relative_to(approved)
    except ValueError as error:
        raise ValueError("target locator lies outside allowed_root") from error
    if not root.is_dir():
        raise ValueError("source target must be an existing directory")
    return root


def _gitignore(root: Path, policy: SourceScanPolicy) -> pathspec.PathSpec[Pattern] | None:
    ignore_file = root / ".gitignore"
    if not policy.honor_root_gitignore or not ignore_file.is_file() or ignore_file.is_symlink():
        return None
    try:
        lines = ignore_file.read_text("utf-8").splitlines()
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    except UnicodeDecodeError:
        return None


def _language(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in {".c", ".h"}:
        return "c"
    return "cpp"


def iter_source_files(
    root: Path, *, policy: SourceScanPolicy, limits: ScanLimits
) -> TraversalResult:
    """Read selected files with hard limits and stable path ordering; never follow symlinks."""
    spec = _gitignore(root, policy)
    files: list[SourceFile] = []
    warnings: list[str] = []
    total_bytes = 0
    partial = False
    candidates = sorted(root.rglob("*"), key=lambda item: item.as_posix().encode("utf-8"))
    for path in candidates:
        if len(files) >= limits.max_file_count:
            warnings.append("source file-count limit reached")
            partial = True
            break
        if path.is_symlink():
            warnings.append(f"skipped symlink: {path.relative_to(root).as_posix()}")
            partial = True
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            warnings.append("skipped path outside root")
            partial = True
            continue
        parts = relative.split("/")
        if any(part in HARD_IGNORES for part in parts):
            continue
        if path.is_dir() or path.suffix not in policy.include_extensions:
            continue
        if relative in policy.extra_excludes or (spec is not None and spec.match_file(relative)):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            warnings.append(f"unreadable file metadata: {relative}")
            partial = True
            continue
        if size > policy.max_source_file_bytes:
            warnings.append(f"skipped oversized file: {relative}")
            partial = True
            continue
        if total_bytes + size > policy.max_total_source_bytes:
            warnings.append("source byte limit reached")
            partial = True
            break
        try:
            raw = path.read_bytes()
        except OSError:
            warnings.append(f"unreadable file: {relative}")
            partial = True
            continue
        total_bytes += len(raw)
        try:
            text = raw.decode("utf-8-sig")
            degraded = False
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            degraded = True
            warnings.append(f"encoding degraded: {relative}")
            partial = True
        files.append(
            SourceFile(
                path=path,
                relative_path=relative,
                raw_bytes=raw,
                digest=f"sha256:{hashlib.sha256(raw).hexdigest()}",
                language=_language(path),
                text=text,
                encoding_degraded=degraded,
            )
        )
    return TraversalResult(tuple(files), tuple(warnings[:100]), partial)
