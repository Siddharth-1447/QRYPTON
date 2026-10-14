# Pipeline QA and regression evidence

The regression suite now covers source trees and archives, binary symbols,
dependency wheels, container archives and references, and KMS identifiers and
metadata. These workflows pass through scanner dispatch, canonical evidence and
finding normalization, correlation, risk and recommendation phases, SQLite
persistence, CBOM export, and the existing API/dashboard read models. Network
acquisition remains explicitly opt-in.

## Coverage map

| Invariant | Regression coverage |
| --- | --- |
| Source, binary, dependency, container, KMS/API dispatch and persisted traces | `tests/workflows/test_workflow_backend.py`, `tests/workflows/test_workflow_scanners.py` |
| Canonical finding IDs, evidence references, confidence, business context, risk tiers, Mosca urgency and CBOM/API preservation | `tests/workflows/test_workflow_backend.py::test_persisted_source_trace_preserves_canonical_risk_across_surfaces` |
| X/Y/Z boundary and invalid/missing timeline inputs | `tests/risk/test_mosca.py`, `tests/risk/test_corrective_phase.py`, `tests/property/test_risk_properties.py` |
| Identified, partially identified and unknown algorithms; unknown protocol; RSA/ECC, AES/SHA, weak hashes and PQC | `tests/risk/test_taxonomy.py`, `tests/risk/test_corrective_phase.py` |
| Deterministic IDs and serialized reports | `tests/integration/test_cli_orchestration.py`, `tests/adversarial/test_determinism.py` |
| API inventory, CBOM, CSV, PDF, posture, heatmap, risk matrix and selected finding IDs reconcile | `tests/api/test_report_pdf.py` |
| Historical persisted scan survives SQLite deserialization with matching finding, evidence, assessment, Mosca and CBOM identities | `tests/workflows/test_historical_613_trace.py` |

The workflow tests create actual SQLite runs from deterministic local fixture
bytes and reopen them through a fresh store instance. The historical trace test
uses a read-only SQLite connection; it skips with a stated reason when the
runtime database is absent.

## Historical 613-finding trace

The exact historical 613-finding artifact is available in this workspace at
`qrypton.sqlite3`, run
`run_rijjek6ih47m3hwenq7spc5erwiiynciq4cwvcicrnvwsk5pcpjq`. It contains 613
findings, 10,776 evidence records, 613 assessments, 613 Mosca evaluations, and
a CBOM containing the same 613 finding IDs. Finding evidence links, assessment
confidence and business-context links, final-priority/level equality, and
assessment/Mosca urgency reconcile when both assessment fields are present.

This database is runtime state and is not a checked-in fixture, so clean clones
cannot reproduce that historical run unless the artifact is separately
provided. Its assessment records predate independent crypto-risk and
quantum-risk dimensions and structured assessment-level Mosca fields. The risk
dimensions and assessment Mosca applicability/urgency deserialize as `unknown`
and must stay that way; separate persisted timeline records are checked against
their own X+Y and Z values. The historical trace therefore validates persistence
and identity continuity, while the current fixture-driven suite validates the
newer risk dimensions. It cannot be used to retroactively claim those
dimensions or assessment-level urgency for the old scan.

## Latest validation

Run with the repository's Python 3.13 environment:

```powershell
.venv\Scripts\python.exe -m pytest -q
```

The remote GitHub acquisition workflow is opt-in via
`QRYPTON_RUN_NETWORK_TESTS=1`. The symlink adversarial case is skipped on
Windows when the process lacks symlink creation privileges. Latest full-suite
run: **266 passed, 2 skipped**. The skips are the opt-in remote acquisition
test and the platform-restricted symlink case; one Starlette deprecation
warning remains.
