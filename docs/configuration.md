# Configuration and security boundaries

[Project overview](../README.md) · [Getting started](getting-started.md) · [Security policy](../SECURITY.md)

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
| `QRYPTON_ACCESS_TOKENS` | Server-managed JSON mapping of SHA-256 token digests to subjects and roles. See the [access workflow](scan-progress-and-status.md). |
| `QRYPTON_OAUTH_<PROVIDER>_*` | Provider client ID, client secret, and redirect URI for configured OAuth sign-in. `QRYPTON_AUTH_ORIGINS` controls allowed sign-in origins. |
| `QRYPTON_GITHUB_ISSUES_REPO`, `QRYPTON_GITHUB_ISSUES_TOKEN` | Optional fixed destination and server-only token for Issue creation; see [finding actions](finding-actions-and-exports.md). |
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
  not recovered after a process restart. See the [worker lifecycle notes](scan-worker-remediation.md).

## CI policy workflows

The optional [PR gate](../.github/workflows/qrypton-pr.yml) and
[baseline refresh](../.github/workflows/qrypton-baseline.yml) require the repository
secret `QRYPTON_ID_SECRET` and variable `QRYPTON_TENANT_ID`.
`QRYPTON_MAX_RISK` is optional and defaults to `high`. The trusted baseline is
stored on the default branch at `.qrypton/baseline.ci.json`.

Fork pull requests do not receive these secrets. The policy workflows report a
setup warning and skip scanning when the required configuration is absent;
ordinary [repository checks](../.github/workflows/ci.yml) still run.
