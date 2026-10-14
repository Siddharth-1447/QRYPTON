"""The demo database command only scans a caller-approved local input."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "regenerate_demo_db.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("regenerate_demo_db", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_regenerator_uses_local_source_and_selected_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    source = tmp_path / "demo.py"
    source.write_text("import hashlib\nhashlib.sha256(b'demo')\n")
    database = tmp_path / "demo.db"
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "cli_main", lambda args: commands.append(args) or 0)
    monkeypatch.setattr(
        sys, "argv", [str(SCRIPT), "--db", str(database), "--source", str(source)]
    )
    monkeypatch.setenv("QRYPTON_DEMO_ID_SECRET", "x" * 32)

    assert module.main() == 0
    assert len(commands) == 1
    assert commands[0][0] == "scan"
    assert commands[0][1] == str(source)
    assert commands[0][commands[0].index("--scanner") + 1] == "qrypton-source"
    assert commands[0][commands[0].index("--db") + 1] == str(database)


def test_demo_regenerator_refuses_existing_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script()
    database = tmp_path / "demo.db"
    database.write_bytes(b"already here")
    source = tmp_path / "demo.py"
    source.write_text("pass\n")
    monkeypatch.setattr(
        sys, "argv", [str(SCRIPT), "--db", str(database), "--source", str(source)]
    )

    with pytest.raises(SystemExit, match="2"):
        module.main()
    assert database.read_bytes() == b"already here"
