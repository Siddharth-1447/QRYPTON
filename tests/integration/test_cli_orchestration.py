from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

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
    assert main(arguments) == 0
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
        assert evaluation.required_security_years == (
            evaluation.x_data_lifetime_years + evaluation.y_migration_years
        )
