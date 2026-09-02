"""Canonical serialization and tenant-scoped deterministic identifiers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel

from qrypton.contracts.errors import IdDerivationError
from qrypton.contracts.primitives import EntityId, TenantId

_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise IdDerivationError("canonical timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise IdDerivationError("canonical payload cannot contain non-finite float")
    return value


def canonical_json_bytes(payload: Mapping[str, Any], *, version: int = 1) -> bytes:
    """Return versioned canonical UTF-8 JSON suitable for HMAC input."""
    if version < 1:
        raise IdDerivationError("canonicalization version must be positive")
    document = {"payload": _canonical_value(payload), "version": version}
    try:
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise IdDerivationError("payload is not canonical JSON serializable") from error


class IdDeriver(Protocol):
    def derive(self, *, namespace: str, tenant_id: TenantId, canonical_payload: bytes) -> EntityId:
        """Derive a stable identifier without exposing the tenant secret."""


class HmacIdDeriver:
    """HMAC-SHA-256 ID derivation with a caller-provided tenant-scoped secret."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise IdDerivationError("HMAC secret must contain at least 256 bits")
        self._secret = secret

    def derive(self, *, namespace: str, tenant_id: TenantId, canonical_payload: bytes) -> EntityId:
        if not _NAMESPACE_RE.fullmatch(namespace):
            raise IdDerivationError("namespace must match the entity-ID prefix format")
        if not canonical_payload:
            raise IdDerivationError("canonical payload must not be empty")
        message = b"qrypton-id-v1\x00" + tenant_id.encode("ascii") + b"\x00" + canonical_payload
        digest = hmac.new(self._secret, message, hashlib.sha256).digest()
        encoded = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
        return f"{namespace}_{encoded}"

    def derive_tenant_id(self, *, canonical_payload: bytes) -> TenantId:
        """Create an opaque tenant ID from a stable tenant identity payload."""
        seed_tenant = f"tenant_{'a' * 52}"
        derived = self.derive(
            namespace="tenant", tenant_id=seed_tenant, canonical_payload=canonical_payload
        )
        return derived
