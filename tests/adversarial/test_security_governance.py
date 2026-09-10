"""Security governance, subprocess execution safety, and log leakage audits.

Verifies that scanned artifacts are NEVER executed via dynamic code evaluation,
and that logging contains zero secrets or raw source code excerpts.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from qrypton.application.logging import JsonSafeLogger


def test_no_dynamic_code_execution_or_dangerous_subprocesses() -> None:
    """AST static audit: src/qrypton must not contain eval(), exec(), os.system(), or shell=True."""
    src_dir = Path(__file__).parents[2] / "src" / "qrypton"
    assert src_dir.exists(), f"Source directory {src_dir} not found"

    forbidden_calls = {"eval", "exec", "system", "popen"}

    class SecurityVisitor(ast.NodeVisitor):
        def __init__(self, filepath: Path) -> None:
            self.filepath = filepath
            self.violations: list[str] = []

        def visit_Call(self, node: ast.Call) -> None:
            # Check for direct calls to eval(), exec(), os.system()
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                self.violations.append(f"{self.filepath}:{node.lineno} dangerous call to {node.func.id}()")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                self.violations.append(f"{self.filepath}:{node.lineno} dangerous call to .{node.func.attr}()")

            # Check for subprocess calls with shell=True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"run", "Popen", "call"}:
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.violations.append(f"{self.filepath}:{node.lineno} subprocess with shell=True")

            self.generic_visit(node)

    violations: list[str] = []
    for py_file in src_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        visitor = SecurityVisitor(py_file)
        visitor.visit(tree)
        violations.extend(visitor.violations)

    assert not violations, f"Security audit violations detected:\n" + "\n".join(violations)


def test_logger_sanitizes_unauthorized_fields() -> None:
    """JsonSafeLogger strictly drops fields not in its explicitly approved allowlist."""
    records: list[dict[str, Any]] = []

    class MockHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.__dict__)

    raw_logger = logging.getLogger("qrypton_test_audit")
    raw_logger.setLevel(logging.INFO)
    handler = MockHandler()
    raw_logger.addHandler(handler)

    logger = JsonSafeLogger(raw_logger)
    logger.event(
        "scan_completed",
        fields={
            "run_id": "run_123",
            "tenant_id": "tenant_456",
            "status": "success",
            "count": 42,
            "secret_key": "SUPER_SECRET_API_KEY_LEAK",
            "source_code": "def secret_function(): pass",
            "relative_path": "src/secret.py",
        },
    )

    assert len(records) == 1
    msg = records[0]["msg"]
    assert "run_123" in msg
    assert "tenant_456" in msg
    assert "success" in msg
    assert "SUPER_SECRET_API_KEY_LEAK" not in msg
    assert "secret_function" not in msg
    assert "relative_path" not in msg
