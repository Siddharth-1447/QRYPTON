"""Optional, non-evidentiary GCC syntax gate for C/C++ files."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from qrypton.ports.scanners import ScanLimits
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.traversal import SourceFile


@dataclass(frozen=True, slots=True)
class SourceSyntaxStatus:
    attempted: bool
    valid: bool | None
    reason: str | None = None


def gcc_syntax_status(
    source: SourceFile, *, policy: SourceScanPolicy, limits: ScanLimits
) -> SourceSyntaxStatus:
    """Run an optional fixed-argument syntax check; it never executes source code."""
    if not policy.enable_gcc_syntax_gate or source.language == "python":
        return SourceSyntaxStatus(attempted=False, valid=None)
    executable = shutil.which("gcc" if source.language == "c" else "g++")
    if executable is None:
        return SourceSyntaxStatus(attempted=False, valid=None, reason="compiler unavailable")
    language = "c" if source.language == "c" else "c++"
    environment = {
        "PATH": os.path.dirname(executable),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
    }
    try:
        completed = subprocess.run(
            [
                executable,
                "-fsyntax-only",
                "-fno-diagnostics-color",
                "-w",
                "-x",
                language,
                str(source.path),
            ],
            check=False,
            shell=False,
            cwd=str(source.path.parent),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=min(limits.max_wall_time_seconds, 10),
        )
    except (OSError, subprocess.TimeoutExpired):
        return SourceSyntaxStatus(attempted=True, valid=False, reason="compiler gate failed")
    return SourceSyntaxStatus(attempted=True, valid=completed.returncode == 0)
