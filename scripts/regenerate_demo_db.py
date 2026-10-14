"""Create a local demo database from the checked-in source corpus."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from qrypton.cli import main as cli_main


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", type=Path, default=project_root / "qrypton_demo.db", help="new SQLite output path"
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=project_root / "demo_corpus" / "source" / "crypto_service.py",
    )
    parser.add_argument("--id-secret-env", default="QRYPTON_DEMO_ID_SECRET")
    args = parser.parse_args()

    database = args.db.resolve()
    source = args.source.resolve()
    if database.exists():
        parser.error("database already exists; choose a new --db path")
    if not source.is_file():
        parser.error("demo source file is unavailable")
    secret = os.environ.get(args.id_secret_env, "")
    if len(secret.encode("utf-8")) < 32:
        parser.error("ID secret environment variable must contain at least 32 UTF-8 bytes")
    if not database.parent.is_dir():
        parser.error("database parent directory does not exist")

    return int(
        cli_main(
            [
                "scan",
                str(source),
                "--tenant-id",
                "tenant_" + "d" * 52,
                "--asset-kind",
                "application",
                "--asset-reference",
                "repo:enterprise/crypto-service",
                "--asset-name",
                "Enterprise Crypto Service",
                "--id-secret-env",
                args.id_secret_env,
                "--db",
                str(database),
                "--reference-time",
                "2026-01-15T10:00:00+00:00",
                "--max-risk",
                "critical",
                "--scanner",
                "qrypton-source",
            ]
        )
    )


if __name__ == "__main__":
    sys.exit(main())
