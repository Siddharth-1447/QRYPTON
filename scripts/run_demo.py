"""Verify a local source scan, persisted evidence, and the CI policy gate."""

from __future__ import annotations

import argparse
import os
import secrets
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from qrypton.ci.exit_codes import ExitCode
from qrypton.ci.schema import CiResult
from qrypton.cli import main as cli_main
from qrypton.storage.sqlite import SqliteRunStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TENANT_ID = "tenant_" + "d" * 52


def preflight_health_check() -> bool:
    """Use a process-local random demo secret unless the caller supplied one."""
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        print("FAILED: Python 3.11-3.13 is required", file=sys.stderr)
        return False
    secret = os.environ.setdefault("QRYPTON_ID_SECRET", secrets.token_hex(32))
    if len(secret.encode("utf-8")) < 32:
        print("FAILED: QRYPTON_ID_SECRET must contain at least 32 UTF-8 bytes", file=sys.stderr)
        return False
    return True


def run_enterprise_demo(output_dir: Path | None = None) -> int:
    """Return success only after verifying artifacts and the expected policy violation."""
    if not preflight_health_check():
        return 1
    if output_dir is None:
        artifacts = PROJECT_ROOT / "artifacts"
        artifacts.mkdir(exist_ok=True)
        output_dir = Path(tempfile.mkdtemp(prefix="demo-", dir=artifacts))
    else:
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        if any(output_dir.iterdir()):
            print("FAILED: output directory must be empty", file=sys.stderr)
            return 1

    database = output_dir / "demo.sqlite3"
    cbom = output_dir / "scan.cbom.json"
    ci_cbom = output_dir / "ci.cbom.json"
    ci_output = output_dir / "scan.ci.json"
    shared = [
        str(PROJECT_ROOT / "demo" / "enterprise"),
        "--tenant-id", TENANT_ID,
        "--asset-kind", "repository",
        "--asset-reference", "repo:enterprise/crypto-service",
        "--asset-name", "Enterprise Crypto Service",
        "--id-secret-env", "QRYPTON_ID_SECRET",
        "--db", str(database),
        "--scanner", "qrypton-source",
        "--quiet",
    ]
    scan_code = cli_main(["scan", *shared, "--max-risk", "critical", "--output", str(cbom)])
    if scan_code != ExitCode.SUCCESS:
        print(f"FAILED: source scan exited with {scan_code}", file=sys.stderr)
        return 1
    ci_code = cli_main([
        "ci", "scan", *shared,
        "--baseline", str(PROJECT_ROOT / "demo_corpus" / "ci_baseline.json"),
        "--ci-output", str(ci_output), "--cbom-output", str(ci_cbom),
        "--max-risk", "medium",
    ])
    if ci_code != ExitCode.POLICY_VIOLATION:
        print(f"FAILED: expected CI policy violation (3), got {ci_code}", file=sys.stderr)
        return 1
    try:
        result = CiResult.model_validate_json(ci_output.read_bytes())
        if (
            result.exit_code != ci_code or not result.introduced
            or result.scanner.failed or result.scanner.partial
            or not cbom.read_bytes() or not ci_cbom.read_bytes()
        ):
            raise ValueError("scan artifacts do not prove a complete policy gate")
        store = SqliteRunStore(database)
        try:
            run = store.get_run(tenant_id=TENANT_ID, run_id=result.run_id)
            if (
                run is None or run.status.value != "completed" or not run.findings
                or len(run.findings) != len(run.assessments)
                or len(run.findings) != len(run.mosca_evaluations)
                or not run.recommendations
                or any(not finding.evidence_ids for finding in run.findings)
                or store.get_cbom(tenant_id=TENANT_ID, run_id=result.run_id) != ci_cbom.read_bytes()
            ):
                raise ValueError("persisted scan evidence or analysis is incomplete")
            print(f"Verified {len(run.findings)} findings and {len(run.evidence)} evidence records")
        finally:
            store.close()
    except (OSError, ValueError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    print("Enterprise demo: PASS; CI rejected introduced risk as expected.")
    print(f"Artifacts: {output_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="empty artifact output directory")
    args = parser.parse_args()
    try:
        return run_enterprise_demo(args.output_dir)
    except (OSError, sqlite3.Error) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
