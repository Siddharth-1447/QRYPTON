"""Verify the reproducible enterprise demo evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from qrypton.storage.sqlite import SqliteRunStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--cbom", type=Path, required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    store = SqliteRunStore(args.db)
    runs = store.list_runs(tenant_id=args.tenant_id)
    if len(runs) != 1:
        raise SystemExit(f"expected exactly one persisted run, found {len(runs)}")
    run = store.get_run(tenant_id=args.tenant_id, run_id=runs[0][1])
    if run is None:
        raise SystemExit("persisted run summary has no result payload")
    if run.status.value != "completed" or not run.policy_outcome.passed:
        raise SystemExit(f"run is not a passing completed run: {run.status.value}")
    persisted_cbom = store.get_cbom(tenant_id=args.tenant_id, run_id=runs[0][1])
    if not persisted_cbom or persisted_cbom != args.cbom.read_bytes():
        raise SystemExit("CBOM file does not match the persisted run")
    if not run.findings or len(run.findings) != len(run.assessments):
        raise SystemExit("findings and assessments are not one-to-one")
    if len(run.findings) != len(run.mosca_evaluations):
        raise SystemExit("Mosca evaluations are incomplete")
    if any(not finding.evidence_ids for finding in run.findings):
        raise SystemExit("finding without evidence")
    expected_paths = {"payment_service.py", "edge_gateway.cpp", "modern_service.py"}
    corpus_root = Path(__file__).resolve().parents[1] / "demo" / "enterprise"
    if any(not (corpus_root / path).is_file() for path in expected_paths):
        raise SystemExit("enterprise corpus is incomplete")
    corpus_digests = {
        path: hashlib.sha256((corpus_root / path).read_bytes()).hexdigest()
        for path in sorted(expected_paths)
    }
    scanner_names = {item.scanner_name for item in run.scanner_results}
    if "qrypton-source" not in scanner_names:
        raise SystemExit("source scanner did not complete")
    algorithms = {
        finding.algorithm.value.canonical_name
        for finding in run.findings
        if finding.algorithm.value is not None
    }
    required = {"sha-1", "rsa", "ec"}
    if not required.issubset(algorithms):
        raise SystemExit(f"missing required algorithm findings: {sorted(required - algorithms)}")
    cbom_digest = f"sha256:{hashlib.sha256(persisted_cbom).hexdigest()}"
    evidence = {
        "status": "PASS",
        "run_id": run.run_id,
        "tenant_id": run.tenant_id,
        "findings": len(run.findings),
        "evidence": len(run.evidence),
        "assessments": len(run.assessments),
        "mosca_evaluations": len(run.mosca_evaluations),
        "recommendations": len(run.recommendations),
        "corpus_sha256": corpus_digests,
        "scanner_names": sorted(scanner_names),
        "cbom_sha256": cbom_digest,
        "policy_passed": run.policy_outcome.passed,
    }
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("enterprise_demo: PASS")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
