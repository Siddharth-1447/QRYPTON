from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from qrypton.ci.exit_codes import ExitCode
from qrypton.cli import main


def test_scan_persists_and_reports_a_deterministic_cbom(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    database = tmp_path / "runs.sqlite3"
    output = tmp_path / "first.cdx.json"
    secret_name = "QRYPTON_TEST_ID_SECRET"
    monkeypatch.setenv(secret_name, "a" * 32)  # type: ignore[attr-defined]
    arguments = [
        "scan",
        str(source),
        "--tenant-id",
        f"tenant_{'a' * 52}",
        "--asset-kind",
        "application",
        "--asset-reference",
        "integration",
        "--asset-name",
        "Integration",
        "--id-secret-env",
        secret_name,
        "--db",
        str(database),
        "--output",
        str(output),
    ]
    # SHA-1 is High crypto risk under taxonomy 1.0.0, so the default risk gate
    # reports a policy violation while still completing and persisting the scan.
    assert main(arguments) == ExitCode.POLICY_VIOLATION
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    report = tmp_path / "second.cdx.json"
    assert (
        main(
            [
                "report",
                "--run-id",
                run_id,
                "--tenant-id",
                f"tenant_{'a' * 52}",
                "--db",
                str(database),
                "--output",
                str(report),
            ]
        )
        == 0
    )
    assert report.read_bytes() == output.read_bytes()
    from qrypton.storage.sqlite import SqliteRunStore

    stored = SqliteRunStore(database).get_run(tenant_id=f"tenant_{'a' * 52}", run_id=run_id)
    assert stored is not None
    assert len(stored.mosca_evaluations) == len(stored.findings)
    for evaluation in stored.mosca_evaluations:
        if evaluation.mosca_applicable == "yes":
            assert evaluation.required_security_years == (
                evaluation.x_data_lifetime_years + evaluation.y_migration_years
            )
        else:
            assert evaluation.required_security_years is None
            assert evaluation.exposure_score is None


def test_ci_scan_emits_sanitized_delta_and_artifacts(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    secret_name = "QRYPTON_TEST_CI_ID_SECRET"
    monkeypatch.setenv(secret_name, "b" * 32)  # type: ignore[attr-defined]
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version":"1.0","inventory":{}}', encoding="utf-8")
    cbom = tmp_path / "scan.cdx.json"
    output = tmp_path / "ci.json"
    result = main(
        [
            "ci", "scan", str(source), "--tenant-id", f"tenant_{'b' * 52}",
            "--asset-kind", "application", "--asset-reference", "ci-integration",
            "--asset-name", "CI integration", "--id-secret-env", secret_name,
            "--baseline", str(baseline), "--db", str(tmp_path / "runs.sqlite3"),
            "--cbom-output", str(cbom), "--ci-output", str(output), "--max-risk", "critical",
        ]
    )
    assert result == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.0"
    assert document["delta"]
    assert "evidence" not in output.read_text(encoding="utf-8")
    assert cbom.exists()
