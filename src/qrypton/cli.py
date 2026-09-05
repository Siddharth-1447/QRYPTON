"""CI-oriented QRYPTON command line interface."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tomllib
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from qrypton.application.config import (
    QryptonConfig,
    build_orchestrator,
    default_recommendation_policy,
    default_risk_policy,
)
from qrypton.application.schemas import PolicyGate, RunRequest
from qrypton.contracts.enums import AssetKind, ObservationState, RiskLevel, ScanTargetKind
from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, Observation, Provenance, ScanTarget
from qrypton.ports.scanners import ScanLimits
from qrypton.storage.sqlite import SqliteRunStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrypton")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument("--tenant-id", required=True)
    scan.add_argument("--asset-kind", required=True, choices=[item.value for item in AssetKind])
    scan.add_argument("--asset-reference", required=True)
    scan.add_argument("--asset-name", required=True)
    scan.add_argument("--id-secret-env", required=True)
    scan.add_argument("--config")
    scan.add_argument("--db")
    scan.add_argument("--output")
    scan.add_argument("--scanner", action="append", default=[])
    scan.add_argument(
        "--max-risk",
        choices=[item.value for item in RiskLevel],
        default=None,
    )
    scan.add_argument("--allow-partial", action="store_true")
    scan.add_argument("--allow-scanner-failure", action="store_true")
    scan.add_argument("--max-concurrency", type=int, default=None)
    scan.add_argument("--format", choices=("json", "text"), default="json")
    scan.add_argument("--quiet", action="store_true")
    report = commands.add_parser("report")
    report.add_argument("--run-id", required=True)
    report.add_argument("--tenant-id", required=True)
    report.add_argument("--db", default=os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    report.add_argument("--output", required=True)
    return parser


def _limits() -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=64 * 1024 * 1024,
        max_expanded_bytes=512 * 1024 * 1024,
        max_file_count=100_000,
        max_nesting_depth=8,
        max_layer_count=128,
        max_ast_nodes=1_000_000,
        max_evidence_count=100_000,
        max_wall_time_seconds=300,
        max_memory_bytes=512 * 1024 * 1024,
    )


def _file_config(path: str | None) -> dict[str, object]:
    if path is None:
        return {}
    with Path(path).open("rb") as stream:
        document = tomllib.load(stream)
    allowed = {"db", "max_concurrency", "max_risk"}
    if set(document) - allowed:
        raise ValueError("unknown configuration key")
    return document


def _setting(
    args: argparse.Namespace, name: str, config: dict[str, object], default: object
) -> object:
    cli_value = getattr(args, name, None)
    if cli_value is not None:
        return cli_value
    environment = os.environ.get(f"QRYPTON_{name.upper()}")
    if environment is not None:
        return environment
    return config.get(name, default)


def _scan(args: argparse.Namespace) -> int:
    secret = os.environ.get(args.id_secret_env)
    if secret is None or len(secret.encode()) < 32:
        return 2
    target_path = Path(args.target).resolve(strict=True)
    file_config = _file_config(args.config)
    database_path = Path(str(_setting(args, "db", file_config, "qrypton.sqlite3")))
    max_concurrency = int(str(_setting(args, "max_concurrency", file_config, 1)))
    max_risk = RiskLevel(str(_setting(args, "max_risk", file_config, "medium")))
    now = datetime.now(UTC)
    deriver = HmacIdDeriver(secret.encode())
    config_bytes = canonical_json_bytes({"root": str(target_path.parent)})
    digest = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
    provenance = Provenance(
        scanner_name="qrypton-cli",
        scanner_version="1.0.0",
        scanner_config_digest=digest,
        observed_at=now,
    )
    asset_id = deriver.derive(
        namespace="asset",
        tenant_id=args.tenant_id,
        canonical_payload=canonical_json_bytes(
            {"reference": args.asset_reference, "kind": args.asset_kind}
        ),
    )
    asset = Asset(
        id=asset_id,
        tenant_id=args.tenant_id,
        kind=args.asset_kind,
        external_reference=args.asset_reference,
        name=args.asset_name,
        created_at=now,
        updated_at=now,
        provenance=provenance,
    )
    kind = ScanTargetKind.SOURCE_TREE if target_path.is_dir() else ScanTargetKind.FILE
    target_id = deriver.derive(
        namespace="target",
        tenant_id=args.tenant_id,
        canonical_payload=canonical_json_bytes(
            {"asset": asset_id, "kind": kind, "locator": str(target_path)}
        ),
    )
    target = ScanTarget(
        id=target_id,
        tenant_id=args.tenant_id,
        asset_id=asset_id,
        kind=kind,
        locator=str(target_path),
        content_digest=Observation(state=ObservationState.UNKNOWN),
        declared_size_bytes=Observation(state=ObservationState.UNKNOWN),
        requested_at=now,
        provenance=provenance,
    )
    config = QryptonConfig(
        workspace_root=target_path if target_path.is_dir() else target_path.parent,
        database_path=database_path,
        id_secret=secret.encode(),
        max_concurrency=max_concurrency,
    )
    request = RunRequest(
        tenant_id=args.tenant_id,
        asset=asset,
        target=target,
        limits=_limits(),
        selected_scanners=tuple(args.scanner),
        risk_policy=default_risk_policy(now),
        recommendation_policy=default_recommendation_policy(now),
        config_digest=digest,
        policy_gate=PolicyGate(
            max_allowed_risk=max_risk,
            fail_on_partial=not args.allow_partial,
            fail_on_scanner_failure=not args.allow_scanner_failure,
        ),
        reference_time=now,
    )
    result = asyncio.run(build_orchestrator(config).run(request))
    if args.output and result.cbom is not None:
        Path(args.output).write_bytes(result.cbom)
    if not args.quiet:
        payload = {
            "run_id": result.run_id,
            "status": result.status,
            "policy_passed": result.policy_outcome.passed,
            "findings": len(result.findings),
        }
        print(
            json.dumps(payload, sort_keys=True)
            if args.format == "json"
            else "{status}: {findings} findings".format(**payload)
        )
    if result.status.value == "failed":
        return 4
    return 0 if result.policy_outcome.passed else 3


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "scan":
            return _scan(args)
        cbom = SqliteRunStore(Path(args.db)).get_cbom(tenant_id=args.tenant_id, run_id=args.run_id)
        if cbom is None:
            return 5
        Path(args.output).write_bytes(cbom)
        return 0
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError):
        return 2


if __name__ == "__main__":
    sys.exit(main())
