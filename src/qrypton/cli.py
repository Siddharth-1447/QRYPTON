"""CI-oriented QRYPTON command line interface."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import tomllib
from collections.abc import Sequence
from datetime import UTC, datetime
from importlib.metadata import version as package_version
from pathlib import Path

from qrypton.application.config import (
    QryptonConfig,
    build_services,
    default_recommendation_policy,
    default_risk_policy,
)
from qrypton.application.orchestration import QryptonOrchestrator, UnknownScannerError
from qrypton.application.schemas import PolicyGate, RunRequest
from qrypton.ci import CI_SCHEMA_VERSION, build_ci_result, dump_ci_result
from qrypton.ci.exit_codes import ExitCode
from qrypton.contracts.enums import AssetKind, ObservationState, RiskLevel, ScanTargetKind
from qrypton.contracts.ids import HmacIdDeriver, canonical_json_bytes
from qrypton.contracts.models import Asset, Observation, Provenance, ScanTarget
from qrypton.exporters.cyclonedx_1_6 import CycloneDx16CbomExporter
from qrypton.ports.scanners import ScanLimits
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from qrypton.scanners.extended import (
    CloudKmsScanner,
    ContainerImageScanner,
    ExtendedStaticScanner,
    LibraryDependencyScanner,
)
from qrypton.scanners.source.scanner import LocalSourceScanner
from qrypton.storage.sqlite import SqliteRunStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrypton", formatter_class=argparse.RawTextHelpFormatter)
    components = (
        ("source scanner", LocalSourceScanner),
        ("binary scanner", LocalBinaryScanner),
        ("extended static adapter", ExtendedStaticScanner),
        ("library dependency adapter", LibraryDependencyScanner),
        ("container image adapter", ContainerImageScanner),
        ("cloud KMS adapter", CloudKmsScanner),
        ("CBOM exporter", CycloneDx16CbomExporter),
    )
    version_text = "\n".join(
        (f"qrypton {package_version('qrypton')}",)
        + tuple(
            f"{label} ({component.name}) {component.version}"
            for label, component in components
        )
    )
    parser.add_argument("--version", action="version", version=version_text)
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
    scan.add_argument(
        "--reference-time",
        help="UTC ISO-8601 timestamp used for deterministic policy and CBOM timestamps",
    )
    scan.add_argument("--format", choices=("json", "text"), default="json")
    scan.add_argument("--quiet", action="store_true")
    report = commands.add_parser("report")
    report.add_argument("--run-id", required=True)
    report.add_argument("--tenant-id", required=True)
    report.add_argument("--db", default=os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    report.add_argument("--output", required=True)
    ci = commands.add_parser("ci")
    ci_scan = ci.add_subparsers(dest="ci_command", required=True).add_parser("scan")
    ci_scan.add_argument("target")
    ci_scan.add_argument("--tenant-id", required=True)
    ci_scan.add_argument(
        "--asset-kind", required=True, choices=[item.value for item in AssetKind]
    )
    ci_scan.add_argument("--asset-reference", required=True)
    ci_scan.add_argument("--asset-name", required=True)
    ci_scan.add_argument("--id-secret-env", required=True)
    ci_scan.add_argument("--config")
    ci_scan.add_argument("--db")
    ci_scan.add_argument("--scanner", action="append", default=[])
    ci_scan.add_argument("--max-risk", choices=[item.value for item in RiskLevel], default="high")
    ci_scan.add_argument("--allow-partial", action="store_true")
    ci_scan.add_argument("--allow-scanner-failure", action="store_true")
    ci_scan.add_argument("--max-concurrency", type=int, default=None)
    ci_scan.add_argument("--quiet", action="store_true")
    ci_scan.add_argument("--baseline", required=True)
    ci_scan.add_argument("--changed-from")
    ci_scan.add_argument("--cbom-output", required=True)
    ci_scan.add_argument("--ci-output", required=True)
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


def _target_content_hash(path: Path) -> str:
    """Hash path names, file bytes, and symlink identities without following links."""
    digest = hashlib.sha256()

    def record(entry: Path) -> None:
        name = "." if entry == path else entry.relative_to(path).as_posix()
        digest.update(name.encode("utf-8", errors="surrogateescape") + b"\0")
        if entry.is_symlink():
            digest.update(b"L\0" + os.readlink(entry).encode("utf-8", errors="surrogateescape"))
        elif entry.is_file():
            digest.update(b"F\0")
            with entry.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif entry.is_dir():
            digest.update(b"D\0")
        else:
            raise ValueError("unsupported target entry")
        digest.update(b"\0")

    record(path)
    if path.is_dir():
        for current, directories, files in os.walk(path, followlinks=False):
            base = Path(current)
            for name in sorted((*directories, *files)):
                record(base / name)
            directories[:] = sorted(
                name for name in directories if not (base / name).is_symlink()
            )
    return f"sha256:{digest.hexdigest()}"


def _scan_input_hash(path: Path, request: RunRequest) -> str:
    payload = canonical_json_bytes(
        {"target_content": _target_content_hash(path), "request": request}
    )
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _validated_baseline(document: object) -> dict[str, object]:
    if not isinstance(document, dict) or document.get("schema_version") != CI_SCHEMA_VERSION:
        raise ValueError("baseline schema_version must be 1.0")
    inventory = document.get("inventory")
    if not isinstance(inventory, dict):
        raise ValueError("baseline inventory must be an object")
    categories = {"algorithm_use", "key_material", "certificate", "protocol", "library"}
    for fingerprint, entry in inventory.items():
        if (
            not isinstance(fingerprint, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint) is None
        ):
            raise ValueError("baseline inventory contains an invalid fingerprint")
        if not isinstance(entry, dict):
            raise ValueError("baseline inventory entries must be objects")
        risk_level = entry.get("risk_level")
        category = entry.get("category")
        if not isinstance(risk_level, str) or risk_level not in {
            level.value for level in RiskLevel
        }:
            raise ValueError("baseline inventory entry has an invalid risk_level")
        if not isinstance(category, str) or category not in categories:
            raise ValueError("baseline inventory entry has an invalid category")
    return document


def _ci_failure(
    args: argparse.Namespace,
    exit_code: ExitCode,
    error_code: str,
    reason: str,
    **details: object,
) -> int:
    document: dict[str, object] = {
        "schema_version": CI_SCHEMA_VERSION,
        "exit_code": int(exit_code),
        "exit_reason": exit_code.name.casefold(),
        "error_code": error_code,
        "reason": reason,
        **details,
    }
    print(f"{error_code}: {reason}", file=sys.stderr)
    try:
        Path(args.ci_output).write_bytes(dump_ci_result(document))
    except OSError:
        print("artifact_error: cannot write CI failure artifact", file=sys.stderr)
        return ExitCode.ARTIFACT_ERROR
    return exit_code


def _scan(args: argparse.Namespace) -> int:
    secret = os.environ.get(args.id_secret_env)
    if secret is None or len(secret.encode()) < 32:
        return ExitCode.INVOCATION_ERROR
    target_path = Path(args.target).resolve(strict=True)
    file_config = _file_config(args.config)
    database_path = Path(str(_setting(args, "db", file_config, "qrypton.sqlite3")))
    max_concurrency = int(str(_setting(args, "max_concurrency", file_config, 1)))
    max_risk = RiskLevel(str(_setting(args, "max_risk", file_config, "medium")))
    # `ci scan` shares this runner but its parser defines no --reference-time.
    if getattr(args, "reference_time", None):
        parsed_time = datetime.fromisoformat(args.reference_time)
        if parsed_time.tzinfo is None:
            raise ValueError("reference time must include a timezone")
        now = parsed_time.astimezone(UTC)
    else:
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
    services = build_services(config)
    store = services.store
    if not isinstance(store, SqliteRunStore):
        raise RuntimeError("CLI requires SQLite run storage")
    orchestrator = QryptonOrchestrator(services, max_concurrency=config.max_concurrency)
    try:
        valid = tuple(sorted({scanner.name for scanner in services.scanners}))
        unknown = tuple(sorted(set(request.selected_scanners) - set(valid)))
        if unknown:
            error = UnknownScannerError(unknown, valid)
            args._scan_error = {
                "error_code": "unknown_scanner",
                "reason": str(error),
                "unavailable_scanners": list(unknown),
                "valid_scanners": list(valid),
            }
            print(f"scanner_configuration_error: {error}", file=sys.stderr)
            return ExitCode.INVOCATION_ERROR
        run_id = orchestrator.run_id_for(request)
        args._run_id = run_id
        content_hash = _scan_input_hash(target_path, request)
        existing = store.get_run(tenant_id=args.tenant_id, run_id=run_id)
        if existing is not None:
            if store.get_content_hash(tenant_id=args.tenant_id, run_id=run_id) != content_hash:
                print(
                    f"run_conflict: immutable result {run_id} has different target content",
                    file=sys.stderr,
                )
                return ExitCode.RUN_CONFLICT
            if existing.cbom is not None and existing.cbom_digest != (
                f"sha256:{hashlib.sha256(existing.cbom).hexdigest()}"
            ):
                print(
                    f"run_conflict: immutable result {run_id} has an invalid CBOM digest",
                    file=sys.stderr,
                )
                return ExitCode.RUN_CONFLICT
            if args.output:
                if existing.cbom is None:
                    print("artifact_error: stored result has no CBOM", file=sys.stderr)
                    return ExitCode.ARTIFACT_ERROR
                try:
                    Path(args.output).write_bytes(existing.cbom)
                except OSError:
                    print("artifact_error: cannot write CBOM output", file=sys.stderr)
                    return ExitCode.ARTIFACT_ERROR
            print(f"reused existing immutable result {run_id}")
            return ExitCode.SUCCESS
        result = asyncio.run(orchestrator.run(request))
        if _scan_input_hash(target_path, request) != content_hash:
            print("run_conflict: target content changed during scan", file=sys.stderr)
            return ExitCode.RUN_CONFLICT
        store.bind_content_hash(tenant_id=args.tenant_id, run_id=run_id, digest=content_hash)
    finally:
        store.close()
    if args.output:
        if result.cbom is None:
            print("artifact_error: scan produced no CBOM", file=sys.stderr)
            return ExitCode.ARTIFACT_ERROR
        try:
            Path(args.output).write_bytes(result.cbom)
        except OSError:
            print("artifact_error: cannot write CBOM output", file=sys.stderr)
            return ExitCode.ARTIFACT_ERROR
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
        return ExitCode.SCANNER_FAILURE
    return ExitCode.SUCCESS if result.policy_outcome.passed else ExitCode.POLICY_VIOLATION


def _ci_scan(args: argparse.Namespace) -> int:
    """Run a scan, then gate only introduced/worsened findings against a trusted baseline."""
    try:
        baseline_path = Path(args.baseline).resolve(strict=True)
        if baseline_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("baseline exceeds 8 MiB limit")
        baseline = _validated_baseline(json.loads(baseline_path.read_bytes()))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        reason = str(error) if isinstance(error, ValueError) else "cannot read baseline JSON"
        return _ci_failure(args, ExitCode.BASELINE_ERROR, "invalid_baseline", reason)
    # CI owns artifact persistence so export failures are distinguishable from invocation errors.
    args.output = None
    args.format = "json"
    scan_code = _scan(args)
    if scan_code == ExitCode.INVOCATION_ERROR and hasattr(args, "_scan_error"):
        detail = args._scan_error
        return _ci_failure(
            args, ExitCode.INVOCATION_ERROR, detail["error_code"], detail["reason"],
            unavailable_scanners=detail["unavailable_scanners"],
            valid_scanners=detail["valid_scanners"],
        )
    if scan_code == ExitCode.RUN_CONFLICT:
        return _ci_failure(
            args, ExitCode.RUN_CONFLICT, "run_conflict",
            "immutable run ID already has different target content",
        )
    if scan_code == ExitCode.INVOCATION_ERROR:
        return scan_code
    database_path = Path(args.db or os.environ.get("QRYPTON_DB", "qrypton.sqlite3"))
    store = SqliteRunStore(database_path)
    result = store.get_run(tenant_id=args.tenant_id, run_id=args._run_id)
    if result is None:
        store.close()
        return ExitCode.SCANNER_FAILURE

    # Determine exit code before building the result document.
    scanner_failed = result.status.value == "failed" or any(
        item.status == "failed" for item in result.scanner_results
    )
    if scanner_failed and not args.allow_scanner_failure:
        exit_code = ExitCode.SCANNER_FAILURE
    else:
        exit_code = ExitCode.SUCCESS  # may be upgraded to POLICY_VIOLATION below

    document = build_ci_result(
        result, baseline, changed_from=args.changed_from, exit_code=exit_code,
    )

    # Check policy threshold against introduced findings.
    if exit_code == ExitCode.SUCCESS:
        threshold = {
            RiskLevel.INFORMATIONAL: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
            RiskLevel.UNKNOWN: -1,
        }
        allowed = threshold[RiskLevel(args.max_risk)]
        introduced = document["introduced"]
        assert isinstance(introduced, list)
        if any(
            threshold.get(RiskLevel(str(item["risk_level"])), 5) > allowed
            for item in introduced
            if isinstance(item, dict)
        ):
            exit_code = ExitCode.POLICY_VIOLATION
            document["exit_code"] = int(exit_code)
            document["exit_reason"] = "policy_violation"

    try:
        Path(args.ci_output).write_bytes(dump_ci_result(document))
        cbom = store.get_cbom(tenant_id=args.tenant_id, run_id=result.run_id)
        if cbom is not None:
            Path(args.cbom_output).write_bytes(cbom)
    except OSError:
        store.close()
        return ExitCode.ARTIFACT_ERROR
    store.close()
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "scan":
            return _scan(args)
        if args.command == "ci" and args.ci_command == "scan":
            return _ci_scan(args)
        cbom = SqliteRunStore(Path(args.db)).get_cbom(tenant_id=args.tenant_id, run_id=args.run_id)
        if cbom is None:
            return ExitCode.BASELINE_ERROR
        Path(args.output).write_bytes(cbom)
        return ExitCode.SUCCESS
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError):
        return ExitCode.INVOCATION_ERROR


if __name__ == "__main__":
    sys.exit(main())
