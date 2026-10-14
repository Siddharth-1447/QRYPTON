"""Persistence boundary for sanitized QRYPTON run records."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, TypeAlias

from qrypton.contracts.primitives import EntityId, TenantId

if TYPE_CHECKING:
    from qrypton.application.schemas import RunRequest, RunResult, ScannerExecutionResult

    # Read adapters consume the persisted data contract through this port.
    PersistedRun: TypeAlias = RunResult


class RunStore(Protocol):
    def begin_run(self, request: RunRequest, *, run_id: EntityId) -> None: ...
    def persist_scanner_result(self, result: ScannerExecutionResult) -> None: ...
    def persist_artifacts(self, result: RunResult) -> None: ...
    def finalize_run(self, result: RunResult) -> None: ...
    def get_run(self, *, tenant_id: TenantId, run_id: EntityId) -> RunResult | None: ...
    def get_cbom(self, *, tenant_id: TenantId, run_id: EntityId) -> bytes | None: ...
    def list_runs(
        self, *, tenant_id: TenantId | None = None
    ) -> Sequence[tuple[TenantId, EntityId, str]]: ...
