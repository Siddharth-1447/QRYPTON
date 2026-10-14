"""The demo must prove the pipeline worked and propagate failures."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_demo.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_demo", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_proves_source_evidence_and_ci_policy_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_script()
    monkeypatch.delenv("QRYPTON_ID_SECRET", raising=False)
    assert module.run_enterprise_demo(tmp_path) == 0
    output = capsys.readouterr().out
    assert "Enterprise demo: PASS" in output
    assert "expected" in output
    assert (tmp_path / "scan.ci.json").is_file()
    assert (tmp_path / "ci.cbom.json").is_file()
    assert (tmp_path / "demo.sqlite3").is_file()
    assert len(module.os.environ["QRYPTON_ID_SECRET"]) == 64
    assert module.os.environ["QRYPTON_ID_SECRET"] not in output


@pytest.mark.parametrize("code", [2, 4, 6, 7])
def test_demo_propagates_scan_failure(
    code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setenv("QRYPTON_ID_SECRET", "x" * 32)
    calls: list[list[str]] = []
    monkeypatch.setattr(module, "cli_main", lambda args: calls.append(args) or code)
    assert module.run_enterprise_demo(tmp_path) == 1
    assert len(calls) == 1
    assert not (tmp_path / "scan.ci.json").exists()


@pytest.mark.parametrize("code", [0, 2, 4, 5, 6, 7])
def test_demo_rejects_unexpected_ci_result(
    code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setenv("QRYPTON_ID_SECRET", "x" * 32)
    outcomes = iter([0, code])
    monkeypatch.setattr(module, "cli_main", lambda args: next(outcomes))
    assert module.run_enterprise_demo(tmp_path) == 1


def test_demo_rejects_missing_artifacts_despite_success_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setenv("QRYPTON_ID_SECRET", "x" * 32)
    outcomes = iter([0, 3])
    monkeypatch.setattr(module, "cli_main", lambda args: next(outcomes))
    assert module.run_enterprise_demo(tmp_path) == 1


def test_demo_preserves_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setenv("QRYPTON_ID_SECRET", "x" * 32)
    previous = tmp_path / "previous.txt"
    previous.write_text("keep this", encoding="utf-8")
    assert module.run_enterprise_demo(tmp_path) == 1
    assert previous.read_text(encoding="utf-8") == "keep this"


def test_demo_rejects_weak_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script()
    monkeypatch.setenv("QRYPTON_ID_SECRET", "short")
    assert module.preflight_health_check() is False


def test_demo_rejects_unsupported_python(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script()
    monkeypatch.setattr(sys, "version_info", (3, 14, 0))
    assert module.preflight_health_check() is False
