"""Architectural linting: UI must not import prohibited business-logic modules."""

from __future__ import annotations

import ast
from pathlib import Path

# Entire UI package, including the SQLite adapter.
PROHIBITED_MODULE_PREFIXES = (
    "qrypton.scanners",
    "qrypton.normalizers",
    "qrypton.correlation",
    "qrypton.risk",
    "qrypton.recommendations",
    "qrypton.policies",
    "qrypton.application",
    "qrypton.contracts.ids",
    "qrypton.exporters",
)

# Presentation modules may not talk to persistence internals either.
PRESENTATION_FORBIDDEN_PREFIXES = ("qrypton.storage",)

ADAPTER_FILENAMES = {"sqlite_provider.py"}


def _extract_imported_modules(file_path: Path) -> list[str]:
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_ui_modules_do_not_import_prohibited_business_logic() -> None:
    ui_dir = Path(__file__).resolve().parents[2] / "src" / "qrypton" / "ui"
    python_files = list(ui_dir.rglob("*.py"))
    assert len(python_files) >= 8
    violations: list[str] = []
    for py_file in python_files:
        imported = _extract_imported_modules(py_file)
        for mod in imported:
            for prohibited in PROHIBITED_MODULE_PREFIXES:
                if mod == prohibited or mod.startswith(prohibited + "."):
                    violations.append(f"{py_file.name} imports {mod}")
            if py_file.name not in ADAPTER_FILENAMES:
                for prohibited in PRESENTATION_FORBIDDEN_PREFIXES:
                    if mod == prohibited or mod.startswith(prohibited + "."):
                        violations.append(f"presentation {py_file.name} imports {mod}")
    assert not violations, "Architectural boundary violated:\n" + "\n".join(violations)


def test_sqlite_provider_source_does_not_reference_mosca_calculator() -> None:
    path = Path(__file__).resolve().parents[2] / "src" / "qrypton" / "ui" / "sqlite_provider.py"
    source = path.read_text(encoding="utf-8")
    assert "MoscaRiskCalculator" not in source
    assert "evaluate_qrypton_risk" not in source
    assert "factors.rationale" not in source
