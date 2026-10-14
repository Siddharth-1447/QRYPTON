"""Streaming entropy calculation for executable sections."""

from __future__ import annotations

import math
from collections import Counter
from threading import Event
from typing import BinaryIO


def shannon_entropy(
    stream: BinaryIO,
    *,
    offset: int,
    size: int,
    chunk_size: int = 64 * 1024,
    cancelled: Event | None = None,
) -> float:
    """Return Shannon entropy in bits per byte without materializing a section."""
    if offset < 0 or size < 0 or chunk_size <= 0:
        raise ValueError("invalid entropy range")
    stream.seek(offset)
    counts: Counter[int] = Counter()
    remaining = size
    total = 0
    while remaining:
        if cancelled is not None and cancelled.is_set():
            raise InterruptedError("entropy calculation cancelled")
        chunk = stream.read(min(remaining, chunk_size))
        if not chunk:
            break
        counts.update(chunk)
        total += len(chunk)
        remaining -= len(chunk)
    if total == 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
