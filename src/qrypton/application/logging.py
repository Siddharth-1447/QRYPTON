"""Structured logging that deliberately accepts metadata only."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol


class SafeLogger(Protocol):
    def event(self, name: str, *, fields: Mapping[str, object]) -> None: ...


class JsonSafeLogger:
    _ALLOWED = frozenset(
        {"run_id", "tenant_id", "scanner", "stage", "count", "duration_ms", "error_code", "status"}
    )

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("qrypton")

    def event(self, name: str, *, fields: Mapping[str, object]) -> None:
        safe = {key: value for key, value in fields.items() if key in self._ALLOWED}
        payload = {
            "event": name,
            "timestamp": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            **safe,
        }
        self._logger.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))
