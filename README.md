# QRYPTON

Cryptographic discovery, evidence-backed inventory, and quantum migration planning.
QRYPTON statically inspects supplied artifacts, correlates cryptographic usages,
evaluates deterministic risk and Mosca timelines, stores scan snapshots in SQLite,
and exports a CycloneDX 1.6 cryptographic bill of materials (CBOM).

The repository contains a Python CLI, a FastAPI service, a Next.js dashboard, and a
legacy read-only Streamlit dashboard. The current release is `0.1.0`; deployment
and scanner boundaries are documented below.

## Capabilities

| Area | Implemented behavior |
| --- | --- |
| Discovery | Python AST and C/C++ lexical inspection; ELF/PE/Mach-O inspection; supplied archives, dependency manifests, container artifacts, and KMS descriptors. Targets are inspected without executing their code. |
| Evidence | Scanner provenance, artifact digests, location anchors, confidence, explicit unknown states, and deterministic correlation of the same usage. |
| Assessment | Cryptographic and quantum risk, business context, Mosca urgency, PQC recommendations, and a ranked migration roadmap. |
| Workspace | Persisted scan history, inventory filters and saved views, finding investigation, ownership/status workflows, scan comparison, and explicitly labeled sample data. |
| Reporting | CycloneDX 1.6 JSON, CSV exports, executive PDF reports, and sanitized CI deltas against a trusted baseline. |
| Integrations | Provisioned access tokens, local password accounts, configured OAuth providers, CI result publishing, and optional GitHub Issue creation. |

## Requirements and installation

- Python **3.11–3.13**.
- Node.js **22.18 or newer** and npm for the web frontend and its TypeScript tests.
- Git for repository workflows. No Docker or cloud account is required for the local quick start.

From the repository root in PowerShell:

```powershell
python -m venv .venv
$python = ".\.venv\Scripts\python.exe"
$qrypton = ".\.venv\Scripts\qrypton.exe"
& $python -m pip install --upgrade "pip>=26.2"
& $python -m pip install -e ".[dev]"
& $qrypton --version
Push-Location web
npm ci
Pop-Location
```

On Linux or macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2'
python -m pip install -e '.[dev]'
qrypton --version
npm --prefix web ci
```

The base package installs the CLI. The `api` extra adds FastAPI and Uvicorn; `ui`
adds Streamlit and Plotly; `dev` includes both runtime extras plus pytest,
Hypothesis, Ruff, and mypy. For a runtime-only install use `pip install -e ".[api]"`
or `pip install -e ".[api,ui]"`. Frontend dependencies are locked in
[`web/package-lock.json`](web/package-lock.json).

## CLI quick start

These PowerShell commands scan the checked-in demo source and write results to
the Git-ignored `artifacts/quickstart/` directory. Run them in the installation
terminal above:

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

## Run the dashboards

Start the API from the same quick-start terminal so it inherits the ID secret,
tenant, and database settings:

```powershell
$env:QRYPTON_DB = (Resolve-Path artifacts/quickstart/runs.sqlite3).Path
& $python -m uvicorn qrypton.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal, from the repository root:

```powershell
Push-Location web
npm run dev -- --hostname 127.0.0.1
```

Open [the dashboard](http://localhost:3000/) or
[the API reference](http://127.0.0.1:8000/docs).
`GET /api/v1/health` checks service availability. The dashboard uses
`http://127.0.0.1:8000` by default; change `NEXT_PUBLIC_API_URL` in `web/.env.local`
when the backend origin differs, then restart or rebuild the frontend.

For later sessions, restore the same `QRYPTON_DB`, `QRYPTON_TENANT_ID`, and
`QRYPTON_ID_SECRET` before starting the API. [`scripts/start-dev.ps1`](scripts/start-dev.ps1)
can start both installed services in the background and writes logs to
`tmp/dev-servers/`; it inherits these environment settings.

The legacy Streamlit dashboard uses the same database:

```powershell
& .\.venv\Scripts\python.exe -m streamlit run src/qrypton/ui/app.py `
  --server.address 127.0.0.1 --server.port 8501
```

Set its database and tenant variables in that terminal first. Streamlit displays
mock data only when `QRYPTON_DEMO_MODE=1`. The Next.js **Try with sample payment
app** action loads an explicitly labeled synthetic workspace. To generate a
separate local demo database, set a 32-byte-or-longer `QRYPTON_DEMO_ID_SECRET` and
run `python scripts/regenerate_demo_db.py`; it refuses to overwrite an existing file.

For an automated source-scan and CI-gate demonstration, run
`python scripts/run_demo.py`. It writes a fresh `artifacts/demo-*` directory,
validates persisted evidence and exports, and checks an intentional policy
violation. Use `--output-dir artifacts/my-demo` to select an empty output directory.

## Configuration and security boundaries

Backend settings are environment variables; they are not automatically loaded
from `web/.env.local`. Keep secrets, uploaded targets, account databases, and
generated scan artifacts out of Git.

| Variable | Purpose |
| --- | --- |
| `QRYPTON_DB` | SQLite scan database; API writes default to `qrypton.sqlite3`. Set this explicitly so all readers and writers use the same file. |
| `QRYPTON_TENANT_ID` | Workspace tenant ID; API defaults to `tenant_` followed by 52 `a` characters. Match the tenant used by CLI scans. |
| `QRYPTON_ID_SECRET` | Stable ID derivation secret, at least 32 UTF-8 bytes. Without it, the API generates a process-local random secret. |
| `QRYPTON_UPLOADS` | Upload storage directory; defaults to `artifacts/uploads`. HTTP uploads are capped at 64 MiB. |
| `QRYPTON_AUTH_DB` | Local account database; defaults to `qrypton-accounts.sqlite3`. |
| `QRYPTON_ALLOW_SIGNUP` | Set to `false` to disable password-account registration. Registration creates Viewer accounts. |
| `QRYPTON_ACCESS_TOKENS` | Server-managed JSON mapping of SHA-256 token digests to subjects and roles. See the [access workflow](docs/scan-progress-and-status.md). |
| `QRYPTON_OAUTH_<PROVIDER>_*` | Provider client ID, client secret, and redirect URI for configured OAuth sign-in. `QRYPTON_AUTH_ORIGINS` controls allowed sign-in origins. |
| `QRYPTON_GITHUB_ISSUES_REPO`, `QRYPTON_GITHUB_ISSUES_TOKEN` | Optional fixed destination and server-only token for Issue creation; see [finding actions](docs/finding-actions-and-exports.md). |
| `QRYPTON_PUBLIC_URL` | Public UI origin used in generated finding links. |
| `NEXT_PUBLIC_API_URL` | Browser-visible backend origin. Never put credentials in `NEXT_PUBLIC_*` variables. |

The supplied service configuration is intended for trusted local use. Selected
analyst actions enforce roles, but authentication and tenant authorization do not
cover every scan, upload, read, or deletion endpoint. Tenant query parameters are
not an authorization boundary. Keep the API bound to loopback; deploying it to a
shared or public network requires complete authentication, tenant isolation,
transport protection, upload controls, and network policy. Current CORS defaults
allow local HTTP origins.

Scan snapshots retain their recorded assessments; analyst decisions live in
separate tables. Immutability prevents overwrites of finalized snapshots and does
not prevent explicit scan deletion. Export redaction removes source excerpts and
free-form evidence attributes; protect the underlying databases and uploaded files.

### Scanner limitations

- The CLI accepts local files or directories. The API additionally obtains source
  archives from supported GitHub, GitLab, and Bitbucket HTTPS repository URLs.
  It does not use the Codex GitHub connection to authenticate private targets.
- Container registries are not pulled. Supply an exported image archive; a bare
  reference is descriptor evidence. KMS discovery uses static identifiers or
  supplied descriptor documents, without authenticated cloud key metadata.
- Static evidence does not establish runtime cryptographic use, completeness, or
  compliance. Missing observations remain unknown. A partial scan is incomplete
  evidence; absent findings alone do not establish remediation.
- CLI requested bounds are 64 MiB compressed input, 512 MiB expanded content,
  100,000 files, nesting depth 8, 128 layers, 1,000,000 AST nodes, 100,000 evidence
  items, 300 seconds, and 512 MiB memory. Enforcement varies by adapter. Archive
  extraction lacks a separately enforced per-member limit and complete container
  whiteout handling.
- Scanner deadlines are cooperative, not hard process or memory isolation. The
  API executor and authentication sessions are process-local, and queued work is
  not recovered after a process restart. See the [worker lifecycle notes](docs/scan-worker-remediation.md).

## Development and verification

Run from the repository root after installing the `dev` extra:

```powershell
& .\.venv\Scripts\python.exe -m ruff check .
& .\.venv\Scripts\python.exe -m mypy src
& .\.venv\Scripts\python.exe -m pytest
& .\.venv\Scripts\python.exe -m pip wheel . --no-deps --wheel-dir artifacts/dist
Push-Location web
npm test
npm run lint
npm run typecheck
npm run build
Pop-Location
```

Python checks follow [`pyproject.toml`](pyproject.toml); mypy currently suppresses
API-module errors, so a successful type check does not establish full API typing.
Tests include contract, property, scanner, workflow, API, exporter, and adversarial
regressions. Web tests use Node's native test runner. Historical audit and
validation documents record their own scope and dates; they are not current CI results.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution checks and
[SECURITY.md](SECURITY.md) for vulnerability reporting and deployment boundaries.

[`ci.yml`](.github/workflows/ci.yml) runs the ordinary Python and frontend checks.
The cryptographic [PR gate](.github/workflows/qrypton-pr.yml) and
[baseline refresh](.github/workflows/qrypton-baseline.yml) additionally require the
repository secret `QRYPTON_ID_SECRET`, variable `QRYPTON_TENANT_ID`, and optionally
`QRYPTON_MAX_RISK` (default `high`). The baseline is held on the default branch in
`.qrypton/baseline.ci.json`. Fork pull requests do not receive these secrets.
The optional policy workflows report a setup warning and skip scanning when the
required secret or tenant variable is absent; the ordinary quality checks still run.

## Repository map

| Path | Contents |
| --- | --- |
| `src/qrypton/contracts/`, `ports/` | Validated domain models and adapter interfaces. |
| `src/qrypton/scanners/` | Source, binary, archive, library, container, and KMS static adapters. |
| `src/qrypton/application/`, `risk/`, `recommendations/`, `policies/` | Orchestration, correlation, assessment, and migration policy. |
| `src/qrypton/storage/`, `exporters/`, `ci/` | SQLite persistence, CBOM serialization/schema validation, and CI deltas. |
| `src/qrypton/api/`, `ui/` | FastAPI service and legacy Streamlit dashboard. |
| [`web/`](web/README.md) | Next.js dashboard, reusable components, and frontend tests. |
| `tests/` | Backend automated checks. |
| `scripts/`, `tools/` | Local development launchers, demo generation, and verification tools. |
| `demo/`, `demo_corpus/`, `src/qrypton/sample_payment_app/` | Controlled scanner fixtures and deliberately insecure examples; do not deploy them. |
| `docs/` | Risk, evidence, workflow, design, and historical audit documentation. |
| `.github/workflows/` | Quality checks and optional cryptographic policy automation. |
| `artifacts/`, `tmp/`, `scratch/` | Local generated output and working files, excluded from version control. |

Browse the [documentation index](docs/README.md), or start with the [risk model](docs/risk-model-v1.0.md),
[normalization and correlation contract](docs/normalization-correlation-v1.0.md),
[remediation ranking](docs/remediation-ranking-v1.0.md),
[finding status and progress](docs/scan-progress-and-status.md), and
[finding actions and exports](docs/finding-actions-and-exports.md).

## License

The package metadata declares a proprietary license. No open-source license grant
is included; dependency and bundled asset licenses remain applicable.
