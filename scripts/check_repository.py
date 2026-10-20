"""Reject local state and generated outputs from the Git index.

This path-only guard complements secret scanning. PEM certificates and public
keys are allowed because their filenames do not establish whether they are
private; run a content-aware secret scanner before publishing changes.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_DIRECTORIES = frozenset(
    {
        ".agents",
        ".codex",
        ".cursor",
        ".kiro",
        ".vscode",
        ".idea",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".hypothesis",
        ".cache",
        "node_modules",
        ".next",
        "dist",
        "build",
        "htmlcov",
        "coverage",
        "qa_audit",
        "scratch",
        "tmp",
        "temp",
        "artifacts",
    }
)
FORBIDDEN_FILENAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        ".ds_store",
        "next-env.d.ts",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)
GENERATED_PATTERNS = (
    ".coverage*",
    "*.visual-check.*",
    "backend-audit-index.json",
    "backend-diagnostic-audit-*.md",
    "demo_cbom*.json",
    "demo_ci_report.json",
)
PRIVATE_KEY_SUFFIXES = (".key", ".p12", ".pfx", ".ppk", ".jks", ".keystore", ".priv")
BUILD_SUFFIXES = (".pyc", ".pyo", ".class", ".o", ".obj", ".so", ".dll", ".exe", ".whl")
DATABASE_SUFFIXES = (".db", ".sqlite", ".sqlite3")
DATABASE_SIDECARS = ("-wal", "-shm", "-journal")


class RepositoryCheckError(RuntimeError):
    """The tracked file inventory could not be obtained reliably."""


def blocked_reason(path: str) -> str | None:
    """Explain a forbidden repository-relative path, independent of host case rules."""
    normalized = path.replace("\\", "/").casefold()
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or (len(normalized) > 1 and normalized[1] == ":")
    ):
        return "invalid repository-relative path"
    if any(part in FORBIDDEN_DIRECTORIES or part.endswith(".egg-info") for part in parts[:-1]):
        return "local tooling, cache, build, or generated-output directory"
    filename = parts[-1]
    if filename in FORBIDDEN_FILENAMES:
        return "local instruction, credential, or generated file"
    if filename == ".env" or (filename.startswith(".env.") and filename != ".env.example"):
        return "environment file (only .env.example is publishable)"
    if filename.endswith(PRIVATE_KEY_SUFFIXES):
        return "private-key or credential-store file extension"
    if any(
        filename.endswith(suffix)
        or any(filename.endswith(suffix + sidecar) for sidecar in DATABASE_SIDECARS)
        for suffix in DATABASE_SUFFIXES
    ):
        return "database or database sidecar"
    if filename.endswith(BUILD_SUFFIXES + (".tsbuildinfo", ".log")):
        return "compiled, generated, or runtime output"
    if any(fnmatch.fnmatchcase(filename, pattern) for pattern in GENERATED_PATTERNS):
        return "generated audit, coverage, or demo output"
    return None


def tracked_paths(repository: Path) -> list[str]:
    """Read the index using NUL delimiters; Git failure must never mean a clean tree."""
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "ls-files", "-z"],
            cwd=repository,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RepositoryCheckError(
            "git ls-files failed; repository hygiene was not verified"
        ) from error
    if result.stdout and not result.stdout.endswith(b"\0"):
        raise RepositoryCheckError("git returned an incomplete NUL-delimited file inventory")
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def main() -> int:
    """Print actionable index violations and return a CI-friendly exit status."""
    try:
        paths = tracked_paths(REPOSITORY_ROOT)
    except RepositoryCheckError as error:
        print(f"Repository hygiene check failed: {error}", file=sys.stderr)
        return 2
    violations = [(path, reason) for path in paths if (reason := blocked_reason(path))]
    if violations:
        print("Remove these local/generated files from the Git index:", file=sys.stderr)
        for path, reason in sorted(violations):
            # repr prevents control characters in filenames from altering terminal output.
            print(f"  {path!r}: {reason}", file=sys.stderr)
        return 1
    print(f"Repository hygiene passed ({len(paths)} tracked files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
