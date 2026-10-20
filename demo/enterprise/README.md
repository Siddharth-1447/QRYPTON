# Enterprise source demo corpus

These intentionally insecure examples are controlled scanner inputs. They are
not a production application and must not be deployed. The corpus is small
enough to inspect by hand and has no network dependency or prebuilt binary.

For installation and the supported first scan, follow
[getting started](../../docs/getting-started.md). For an automated scan and CI-gate
demonstration, use `python scripts/run_demo.py` from the repository root.

## Corpus map

| File | Purpose |
| --- | --- |
| `payment_service.py` | Python AST observations of SHA-1, RSA, ECDH, AES, and TLS-related usage. |
| `edge_gateway.cpp` | C++ lexical observations of OpenSSL APIs and a cipher-suite literal. |
| `modern_service.py` | Modern primitive names for checking classification behavior alongside legacy examples. |

Static findings describe observed source evidence. They do not prove that a
particular call executes or that a whole application is quantum ready.

## Inspect this corpus

Run these PowerShell commands from the repository root after installing the
project and activating its virtual environment. Use a fresh output directory.

```powershell
$env:QRYPTON_DEMO_ID_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
$env:QRYPTON_DEMO_TENANT = "tenant_" + ("e" * 52)
New-Item -ItemType Directory -Force artifacts/enterprise-demo | Out-Null
qrypton scan demo/enterprise `
  --tenant-id $env:QRYPTON_DEMO_TENANT `
  --asset-kind application `
  --asset-reference enterprise-demo `
  --asset-name "Enterprise Source Demo" `
  --id-secret-env QRYPTON_DEMO_ID_SECRET `
  --reference-time 2026-01-15T10:00:00+00:00 `
  --scanner qrypton-source `
  --max-risk critical `
  --db artifacts/enterprise-demo/demo.sqlite3 `
  --output artifacts/enterprise-demo/demo.cdx.json
python tools/verify_enterprise_demo.py `
  --db artifacts/enterprise-demo/demo.sqlite3 `
  --cbom artifacts/enterprise-demo/demo.cdx.json `
  --tenant-id $env:QRYPTON_DEMO_TENANT `
  --output artifacts/enterprise-demo/evidence.json
```

The fixed reference time makes this an assessment scenario with repeatable
inputs. The permissive `critical` policy threshold lets this insecure corpus
complete for demonstration; choose an approved threshold for real policy gates.
The verifier checks persisted/exported CBOM equality, evidence-backed findings,
assessment and Mosca records, required source identities, and corpus digests.
It prints observed counts and the CBOM digest. Use those results instead of
assuming fixed totals across scanner versions.

Keep the generated ID secret private and unchanged while comparing reruns.
Changing the secret changes derived identifiers. A fresh process also needs the
same secret, tenant, reference time, target content, and policies for a meaningful
comparison. Databases, secrets, CBOMs, and evidence bundles belong in ignored
local output directories.

To display the result, follow the [dashboard instructions](../../docs/getting-started.md)
with `QRYPTON_DB` pointing to this database, `QRYPTON_TENANT_ID` set to the demo
tenant, and `QRYPTON_ID_SECRET` set to the same demo ID secret. Confirm that the
selected scan ID and counts match the persisted result; synthetic sample data
is labeled separately in the application.
