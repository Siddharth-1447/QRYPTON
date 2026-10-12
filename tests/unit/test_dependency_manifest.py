"""Keep clean development installs complete without executing scanned artifacts."""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# These are input artifacts, not executable QRYPTON modules.
SAMPLE_ARTIFACTS = ROOT / "src/qrypton/sample_payment_app"


def _names(requirements: list[str]) -> set[str]:
    return {re.split(r"[\[<>=!~; ]", requirement, maxsplit=1)[0] for requirement in requirements}


def test_third_party_imports_are_declared() -> None:
    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = manifest["project"]
    declared = _names(project["dependencies"])
    for requirements in project["optional-dependencies"].values():
        declared.update(_names(requirements))
    for requirements in manifest["dependency-groups"].values():
        declared.update(_names(requirements))
    imports: set[str] = set()
    for directory in (ROOT / "src", ROOT / "tests"):
        for path in sorted(directory.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
            if path.is_relative_to(SAMPLE_ARTIFACTS):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imports.add(node.module.split(".")[0])
    third_party = imports - sys.stdlib_module_names - {"qrypton", "tests"}
    assert not (missing := sorted(third_party - declared)), f"Undeclared imports: {missing}"


def test_dev_extra_includes_api_ui_and_test_dependencies() -> None:
    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = manifest["project"]["optional-dependencies"]
    assert "dev" in extras, "pip install .[dev] does not install dependency-groups.dev"
    assert "qrypton[api,ui]" in extras["dev"]
    assert {"fastapi", "python-multipart", "uvicorn"} <= _names(extras["api"])
    assert {"pytest", "hypothesis", "httpx", "mypy", "ruff"} <= _names(extras["dev"])
    assert manifest["dependency-groups"]["dev"] == ["qrypton[dev]"]
