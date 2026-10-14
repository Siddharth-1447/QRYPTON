from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from qrypton.ci.exit_codes import ExitCode
from qrypton.cli import main
from qrypton.storage.sqlite import SqliteRunStore


def _args(tmp_path: Path, source: Path, *, ci: bool = False) -> list[str]:
    command = ["ci", "scan"] if ci else ["scan"]
    return [
        *command, str(source), "--tenant-id", f"tenant_{'c' * 52}",
        "--asset-kind", "application", "--asset-reference", "qa-cli-contract",
        "--asset-name", "QA CLI", "--id-secret-env", "QRYPTON_CLI_CONTRACT_SECRET",
        "--db", str(tmp_path / "runs.sqlite3"), "--max-risk", "critical",
    ]


def _source(tmp_path: Path, monkeypatch: MonkeyPatch) -> Path:
    monkeypatch.setenv("QRYPTON_CLI_CONTRACT_SECRET", "s" * 32)
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("import hashlib\nhashlib.sha256(b'x')\n", encoding="utf-8")
    return source


def test_fixed_time_repeat_reuses_immutable_result_and_cbom(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    source = _source(tmp_path, monkeypatch)
    first_cbom = tmp_path / "first.cdx.json"
    args = _args(tmp_path, source) + [
        "--reference-time", "2026-10-13T00:00:00+00:00", "--output", str(first_cbom),
    ]
    assert main(args) == ExitCode.SUCCESS
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    second_cbom = tmp_path / "second.cdx.json"
    args[-1] = str(second_cbom)
    assert main(args) == ExitCode.SUCCESS
    assert capsys.readouterr().out.strip() == f"reused existing immutable result {run_id}"
    assert first_cbom.read_bytes() == second_cbom.read_bytes()
    store = SqliteRunStore(tmp_path / "runs.sqlite3")
    assert len(store.list_runs(tenant_id=f"tenant_{'c' * 52}")) == 1
    store.close()


def test_fixed_time_changed_content_is_distinct_conflict(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    source = _source(tmp_path, monkeypatch)
    output = tmp_path / "first.cdx.json"
    args = _args(tmp_path, source) + [
        "--reference-time", "2026-10-13T00:00:00+00:00", "--output", str(output),
    ]
    assert main(args) == ExitCode.SUCCESS
    original = output.read_bytes()
    capsys.readouterr()
    (source / "main.py").write_text("import hashlib\nhashlib.sha512(b'x')\n", encoding="utf-8")
    assert main(args) == ExitCode.RUN_CONFLICT
    captured = capsys.readouterr()
    assert "run_conflict" in captured.err
    assert "different target content" in captured.err
    assert output.read_bytes() == original
    assert captured.out == ""


def test_fixed_time_changed_request_cannot_reuse_result(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    source = _source(tmp_path, monkeypatch)
    args = _args(tmp_path, source) + ["--reference-time", "2026-10-13T00:00:00+00:00"]
    assert main(args) == ExitCode.SUCCESS
    capsys.readouterr()
    changed = args.copy()
    changed[changed.index("--asset-name") + 1] = "Another name"
    assert main(changed) == ExitCode.RUN_CONFLICT
    assert "run_conflict" in capsys.readouterr().err


@pytest.mark.parametrize(
    "baseline",
    [
        {"schema_version": "1.0", "inventory": "not-an-object"},
        {"schema_version": "1.0", "inventory": []},
        {"schema_version": "1.0", "inventory": None},
        {"schema_version": "1.0"},
        {"inventory": {}},
        {"schema_version": "wrong", "inventory": {}},
        {
            "schema_version": "1.0",
            "inventory": {"bad": {"risk_level": "high", "category": "library"}},
        },
    ],
)
def test_invalid_ci_baseline_fails_before_scan_with_artifact(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str],
    baseline: object,
) -> None:
    source = _source(tmp_path, monkeypatch)
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline), encoding="utf-8")
    artifact = tmp_path / "ci.json"
    args = _args(tmp_path, source, ci=True) + [
        "--baseline", str(baseline_file), "--cbom-output", str(tmp_path / "cbom.json"),
        "--ci-output", str(artifact),
    ]
    assert main(args) == ExitCode.BASELINE_ERROR
    assert "invalid_baseline:" in capsys.readouterr().err
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["exit_code"] == ExitCode.BASELINE_ERROR
    assert document["error_code"] == "invalid_baseline"
    assert document["reason"]
    assert "source" not in artifact.read_text(encoding="utf-8")
    assert not (tmp_path / "runs.sqlite3").exists()


@pytest.mark.parametrize(
    "selection", [["does-not-exist"], ["qrypton-source", "does-not-exist"]],
)
def test_unknown_scanner_is_configuration_error_and_ci_records_name(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str],
    selection: list[str],
) -> None:
    source = _source(tmp_path, monkeypatch)
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version":"1.0","inventory":{}}', encoding="utf-8")
    artifact = tmp_path / "ci.json"
    args = _args(tmp_path, source, ci=True) + [
        "--baseline", str(baseline), "--cbom-output", str(tmp_path / "cbom.json"),
        "--ci-output", str(artifact),
        *(item for name in selection for item in ("--scanner", name)),
    ]
    code = main(args)
    assert code == ExitCode.INVOCATION_ERROR
    assert code != ExitCode.POLICY_VIOLATION
    captured = capsys.readouterr()
    assert "does-not-exist" in captured.err
    assert "valid scanners" in captured.err
    document = json.loads(artifact.read_text(encoding="utf-8"))
    assert document["error_code"] == "unknown_scanner"
    assert document["unavailable_scanners"] == ["does-not-exist"]
    assert "qrypton-source" in document["valid_scanners"]
    store = SqliteRunStore(tmp_path / "runs.sqlite3")
    assert not store.list_runs(tenant_id=f"tenant_{'c' * 52}")
    store.close()


def test_all_registered_scanners_remain_selectable(
    tmp_path: Path, monkeypatch: MonkeyPatch,
) -> None:
    source = _source(tmp_path, monkeypatch)
    names = (
        "qrypton-source", "qrypton-binary", "qrypton-library", "qrypton-container",
        "qrypton-kms",
    )
    args = _args(tmp_path, source) + [
        *(item for name in names for item in ("--scanner", name))
    ]
    assert main(args) == ExitCode.SUCCESS


def test_unknown_scanner_code_differs_from_real_policy_failure(
    tmp_path: Path, monkeypatch: MonkeyPatch,
) -> None:
    source = _source(tmp_path, monkeypatch)
    (source / "main.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    valid = _args(tmp_path, source) + ["--max-risk", "medium", "--scanner", "qrypton-source"]
    assert main(valid) == ExitCode.POLICY_VIOLATION
    invalid = _args(tmp_path, source) + ["--max-risk", "medium", "--scanner", "missing"]
    assert main(invalid) == ExitCode.INVOCATION_ERROR
