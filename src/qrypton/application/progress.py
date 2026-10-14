"""Execution-scoped progress events; no timers or inferred percentages."""

from collections.abc import Callable
from contextvars import ContextVar
from typing import Literal

StageState = Literal["pending", "running", "completed", "warning", "failed"]
ProgressObserver = Callable[[int, StageState, int | None], None]
observer: ContextVar[ProgressObserver | None] = ContextVar("scan_progress", default=None)


def report(stage: int, state: StageState, findings: int | None = None) -> None:
    callback = observer.get()
    if callback is not None:
        callback(stage, state, findings)
