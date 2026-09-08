# QRYPTON enterprise demo corpus

This directory is the complete, deterministic input for the release demo. It is
intentionally small enough to audit by hand and contains no network dependency,
secret, generated identifier, database, or pre-built binary.

## Corpus map

| Surface | File | Intent |
| --- | --- | --- |
| Python AST | `payment_service.py` | Import-bound SHA-1, RSA, ECDH, AES, and TLS uses |
| C++ lexical | `edge_gateway.cpp` | OpenSSL RSA/AES APIs and an ECDHE cipher-suite literal |
| Unsupported-control | `modern_service.py` | ML-KEM and AES-GCM are present to prove modern primitives are not reported as legacy findings |

The expected source-scan invariants are:

* exactly 3 source files are traversed;
* at least one Python AST and one C++ lexical observation are emitted;
* the run is completed, not partial;
* all findings have evidence and the evidence bundle includes SHA-256 digests for
  every corpus file;
* the CBOM is valid CycloneDX 1.6 JSON and its digest is stable across reruns;
* `sha-1`, `rsa`, and `ec`/`ecdh` are mapped to migration recommendations;
* `ml-kem` and `aes` are not treated as legacy migration findings.

Counts are not hard-coded here because scanner versions are part of the
reproducibility contract. The release command below prints the machine-readable
run summary; `tools/verify_enterprise_demo.py` validates the invariants and
records the observed counts in the evidence bundle.

## Deterministic run

From the repository root:

```powershell
python -m pip install -e ".[ui]"
$env:QRYPTON_DEMO_SECRET = "01234567890123456789012345678901"
New-Item -ItemType Directory -Force artifacts\enterprise-demo | Out-Null
qrypton scan demo\enterprise `
  --tenant-id tenant_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee `
  --asset-kind application `
  --asset-reference enterprise-demo `
  --asset-name "QRYPTON Enterprise Demo" `
  --id-secret-env QRYPTON_DEMO_SECRET `
  --reference-time 2026-01-15T10:00:00+00:00 `
  --db artifacts\enterprise-demo\demo.sqlite3 `
  --output artifacts\enterprise-demo\demo.cdx.json `
  --format json
python tools\verify_enterprise_demo.py `
  --db artifacts\enterprise-demo\demo.sqlite3 `
  --cbom artifacts\enterprise-demo\demo.cdx.json `
  --tenant-id tenant_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee `
  --output artifacts\enterprise-demo\evidence.json
```

The scan command must exit `0`. The verifier must exit `0` and print
`enterprise_demo: PASS`. Run the same commands a second time after deleting only
the two output files; `run_id` and the CBOM SHA-256 digest must be unchanged.
The expected scan summary is `status=completed`, `policy_passed=true`, and
`findings=11`. The verifier evidence must report `evidence=14`,
`assessments=11`, `mosca_evaluations=11`, `recommendations=22`, and the
`cbom_sha256` recorded in that bundle.

## Dashboard

```powershell
$env:QRYPTON_DB = "$PWD\artifacts\enterprise-demo\demo.sqlite3"
$env:QRYPTON_TENANT_ID = "tenant_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
streamlit run src\qrypton\ui\app.py --server.headless true
```

The selected run must show the persisted run ID, findings, evidence-backed
inventory, Mosca view, CBOM export, and PQC roadmap. The dashboard must not be
run without `QRYPTON_DB`; otherwise its sample provider can display synthetic
data and is not acceptable as release evidence.
