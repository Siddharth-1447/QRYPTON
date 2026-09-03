"""Validated limits and selection policy for local source scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator

from qrypton.contracts.models import DomainModel
from qrypton.contracts.primitives import RelativePath

SourceExtension = Literal[".py", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"]


class SourceScanPolicy(DomainModel):
    allowed_root: Path
    include_extensions: frozenset[SourceExtension] = frozenset(
        {".py", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
    )
    extra_excludes: tuple[RelativePath, ...] = ()
    honor_root_gitignore: bool = True
    follow_symlinks: Literal[False] = False
    enable_gcc_syntax_gate: bool = False
    max_source_file_bytes: Annotated[int, Field(gt=0)] = 5 * 1024 * 1024
    max_total_source_bytes: Annotated[int, Field(gt=0)] = 512 * 1024 * 1024
    max_snippet_bytes: Annotated[int, Field(gt=0, le=4096)] = 1024

    @field_validator("allowed_root")
    @classmethod
    def require_absolute_root(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("allowed_root must be absolute")
        return value
