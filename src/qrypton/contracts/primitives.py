"""Constrained primitive types and validation helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, TypeAlias

from pydantic import AfterValidator, Field


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _relative_path(value: str) -> str:
    if "\x00" in value:
        raise ValueError("relative path must not contain NUL")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ValueError("path must be relative")
    if any(segment in {"", ".", ".."} for segment in normalized.split("/")):
        raise ValueError("path must be normalized and must not traverse")
    return normalized


EntityId: TypeAlias = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,31}_[a-z2-7]{52}$")]
TenantId: TypeAlias = Annotated[str, Field(pattern=r"^tenant_[a-z2-7]{52}$")]
Sha256Digest: TypeAlias = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
ScannerVersion: TypeAlias = Annotated[str, Field(min_length=1, max_length=128)]
NonEmptyText: TypeAlias = Annotated[str, Field(min_length=1, max_length=512)]
RelativePath: TypeAlias = Annotated[
    str, Field(min_length=1, max_length=4096), AfterValidator(_relative_path)
]
Confidence: TypeAlias = Annotated[float, Field(ge=0.0, le=1.0)]
RiskScore: TypeAlias = Annotated[float, Field(ge=0.0, le=100.0)]
Excerpt: TypeAlias = Annotated[str, Field(max_length=4096)]
UtcDateTime: TypeAlias = Annotated[datetime, AfterValidator(_utc_datetime)]
JsonScalar: TypeAlias = str | int | float | bool | None
