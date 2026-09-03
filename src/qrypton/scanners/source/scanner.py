"""Read-only local source scanner implementation."""

from __future__ import annotations

import time
import tokenize
from collections.abc import AsyncIterator

from qrypton.ports.scanners import ScanRequest, SourceObservation
from qrypton.scanners.source.cpp_lexical import analyze_cpp_lexical
from qrypton.scanners.source.gcc_gate import gcc_syntax_status
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.python_lexical import analyze_python_lexical
from qrypton.scanners.source.traversal import iter_source_files, resolve_source_root


class LocalSourceScanner:
    """Single-threaded source scanner that never executes scanned source code."""

    name = "qrypton-source"
    version = "0.2.0"
    supported_targets = frozenset({"source_tree"})

    def __init__(self, policy: SourceScanPolicy) -> None:
        self.policy = policy
        self.warnings: tuple[str, ...] = ()
        self.partial = False

    async def scan(self, request: ScanRequest) -> AsyncIterator[SourceObservation]:
        root = resolve_source_root(request.target, policy=self.policy)
        traversal = iter_source_files(root, policy=self.policy, limits=request.limits)
        warnings = list(traversal.warnings)
        partial = traversal.partial
        emitted = 0
        deadline = time.monotonic() + request.limits.max_wall_time_seconds
        for source in traversal.files:
            if time.monotonic() > deadline:
                warnings.append("source scan wall-time limit reached")
                partial = True
                break
            try:
                if source.language == "python":
                    try:
                        observations = analyze_python_ast(
                            source, policy=self.policy, limits=request.limits
                        )
                        for observation in observations:
                            if emitted >= request.limits.max_evidence_count:
                                raise StopIteration
                            emitted += 1
                            yield observation
                    except SyntaxError:
                        warnings.append(f"AST fallback: {source.relative_path}")
                        partial = True
                        try:
                            for observation in analyze_python_lexical(
                                source, policy=self.policy, limits=request.limits
                            ):
                                if emitted >= request.limits.max_evidence_count:
                                    raise StopIteration
                                emitted += 1
                                yield observation
                        except (tokenize.TokenError, IndentationError):
                            warnings.append(f"tokenization failed: {source.relative_path}")
                            partial = True
                else:
                    status = gcc_syntax_status(source, policy=self.policy, limits=request.limits)
                    if status.attempted and status.valid is False:
                        warnings.append(f"compiler syntax gate failed: {source.relative_path}")
                        partial = True
                    observations = analyze_cpp_lexical(
                        source, policy=self.policy, limits=request.limits
                    )
                    for observation in observations:
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
