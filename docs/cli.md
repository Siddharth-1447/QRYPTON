# CLI and CI policy guide

[Project overview](../README.md) · [Install first](getting-started.md)

These PowerShell commands scan the checked-in demo source and write results to
the Git-ignored `artifacts/quickstart/` directory. Run them in the installation
[installation terminal](getting-started.md#requirements-and-installation):

```powershell
New-Item -ItemType Directory -Force artifacts/quickstart | Out-Null
$env:QRYPTON_ID_SECRET = & $python -c "import secrets; print(secrets.token_hex(32))"
$env:QRYPTON_TENANT_ID = "tenant_" + ("d" * 52)
$scan = & $qrypton scan demo_corpus/source/crypto_service.py `
  --tenant-id $env:QRYPTON_TENANT_ID --asset-kind application `
  --asset-reference demo/source --asset-name "Demo Source" `
  --id-secret-env QRYPTON_ID_SECRET --scanner qrypton-source --max-risk critical `
  --db artifacts/quickstart/runs.sqlite3 `
  --output artifacts/quickstart/scan.cdx.json | ConvertFrom-Json
$scan
& $qrypton report --run-id $scan.run_id --tenant-id $env:QRYPTON_TENANT_ID `
  --db artifacts/quickstart/runs.sqlite3 --output artifacts/quickstart/report.cdx.json
```

`qrypton report` re-exports the stored CBOM. The dashboard/API provides executive
PDF reports. Keep the same ID secret for a persistent workspace: rotating it
changes derived identifiers. This quick start uses an ephemeral secret; supply a
stable secret of at least 32 UTF-8 bytes through your secret manager for ongoing use.

To compare a scan against an empty CI baseline:

```powershell
& $python -c "import json,pathlib; pathlib.Path('artifacts/quickstart/empty-baseline.json').write_text(json.dumps({'schema_version':'1.0','inventory':{}}), encoding='utf-8')"
& $qrypton ci scan demo_corpus/source/crypto_service.py `
  --tenant-id $env:QRYPTON_TENANT_ID --asset-kind application `
  --asset-reference demo/source --asset-name "Demo Source" `
  --id-secret-env QRYPTON_ID_SECRET --scanner qrypton-source --max-risk critical `
  --db artifacts/quickstart/ci.sqlite3 `
  --baseline artifacts/quickstart/empty-baseline.json `
  --cbom-output artifacts/quickstart/ci.cdx.json `
  --ci-output artifacts/quickstart/ci-result.json
```

The permissive `critical` threshold is for this demonstration. Select your
organization's approved threshold when using the gate. `--changed-from` records
the comparison reference; the current scan scope remains the full repository.
Use `qrypton scan --help` and `qrypton ci scan --help` for the supported options.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including reuse of an identical immutable result. |
| 2 | Invalid invocation or scanner selection. |
| 3 | Policy threshold violation. |
| 4 | Runtime scanner failure. |
| 5 | Invalid CI baseline; the CI artifact contains a sanitized error. |
| 6 | Artifact write failure. |
| 7 | Run ID conflict with different target content. |
