"""Read-only local source scanner implementation."""

from __future__ import annotations

import asyncio
import time
import tokenize
from collections.abc import AsyncIterator
from itertools import islice
from threading import Event

from qrypton.ports.scanners import ScanRequest, SourceObservation
from qrypton.scanners.source.cpp_lexical import analyze_cpp_lexical
from qrypton.scanners.source.gcc_gate import gcc_syntax_status
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.python_lexical import analyze_python_lexical
from qrypton.scanners.source.traversal import iter_source_files, resolve_source_root


class LocalSourceScanner:
    """Read-only source scanner with offloaded discovery and bounded per-file analysis."""

    name = "qrypton-source"
    version = "0.2.0"
    supported_targets = frozenset({"source_tree"})

    def __init__(self, policy: SourceScanPolicy) -> None:
        self.policy = policy
        self.warnings: tuple[str, ...] = ()
        self.partial = False

    async def scan(self, request: ScanRequest) -> AsyncIterator[SourceObservation]:
        cancelled = Event()
        try:
            async for observation in self._scan(request, cancelled):
                yield observation
        finally:
            # to_thread cancellation does not stop a running filesystem walk.
            cancelled.set()

    async def _scan(
        self, request: ScanRequest, cancelled: Event
    ) -> AsyncIterator[SourceObservation]:
        deadline = time.monotonic() + request.limits.max_wall_time_seconds
        root = await asyncio.to_thread(resolve_source_root, request.target, policy=self.policy)
        traversal = await asyncio.to_thread(
            iter_source_files,
            root,
            policy=self.policy,
            limits=request.limits,
            deadline=deadline,
            cancelled=cancelled,
        )
        warnings = list(traversal.warnings)
        partial = traversal.partial
        emitted = 0
        for file_index, source in enumerate(traversal.files):
            if file_index % 64 == 0:
                await asyncio.sleep(0)
            if time.monotonic() > deadline:
                warnings.append("source scan wall-time limit reached")
                partial = True
                break
            try:
                if source.language == "python":
                    try:
                        observations = await asyncio.to_thread(
                            tuple,
                            islice(
                                analyze_python_ast(
                                    source, policy=self.policy, limits=request.limits
                                ),
                                request.limits.max_evidence_count - emitted + 1,
                            ),
                        )
                        for observation in observations:
                            if emitted % 64 == 0:
                                await asyncio.sleep(0)
                            if emitted >= request.limits.max_evidence_count:
                                raise StopIteration
                            emitted += 1
                            yield observation
                    except SyntaxError:
                        warnings.append(f"AST fallback: {source.relative_path}")
                        try:
                            observations = await asyncio.to_thread(
                                tuple,
                                islice(
                                    analyze_python_lexical(
                                        source, policy=self.policy, limits=request.limits
                                    ),
                                    request.limits.max_evidence_count - emitted + 1,
                                ),
                            )
                            for observation in observations:
                                if emitted % 64 == 0:
                                    await asyncio.sleep(0)
                                if emitted >= request.limits.max_evidence_count:
                                    raise StopIteration
                                emitted += 1
                                yield observation
                        except (tokenize.TokenError, IndentationError):
                            warnings.append(f"tokenization failed: {source.relative_path}")
                            partial = True
                else:
                    status = await asyncio.to_thread(
                        gcc_syntax_status, source, policy=self.policy, limits=request.limits
                    )
                    if status.attempted and status.valid is False:
                        warnings.append(f"compiler syntax gate failed: {source.relative_path}")
                        partial = True
                    observations = await asyncio.to_thread(
                        tuple,
                        islice(
                            analyze_cpp_lexical(source, policy=self.policy, limits=request.limits),
                            request.limits.max_evidence_count - emitted + 1,
                        ),
                    )
                    for observation in observations:
                        if emitted % 64 == 0:
                            await asyncio.sleep(0)
                        if emitted >= request.limits.max_evidence_count:
                            raise StopIteration
                        emitted += 1
                        yield observation
            except StopIteration:
                warnings.append("source evidence limit reached")
                partial = True
                break
            except ValueError as error:
                warnings.append(f"analysis skipped for {source.relative_path}: {error}")
                partial = True
        self.warnings = tuple(warnings[:100])
        self.partial = partial
