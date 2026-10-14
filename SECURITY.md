# Security

QRYPTON is currently intended for local development and evaluation. Bind the API
and dashboard to loopback. Core scan, upload, inventory, and export endpoints do
not yet enforce authentication and authorization tied to a principal's tenant.
Finding actions enforce roles, but this does not protect the other endpoints.
Do not expose the service to untrusted networks without addressing these boundaries.

Use a randomly generated, stable `QRYPTON_ID_SECRET` with at least 32 UTF-8 bytes
for persistent workspaces. Store it outside version control. Keep SQLite databases,
account stores, uploads, reports, access tokens, and OAuth client secrets private.
Demo fixtures deliberately contain weak cryptography and are test inputs only.

Sessions and workers are process-local. Multi-worker operation and externally
accessible deployments require additional validation and access controls.

## Reporting

Report vulnerabilities privately to the repository owner, Siddharth-1447, through
your established private contact channel. Do not publish credentials, private scan
data, or exploit details in an issue. Include the affected commit, reproduction
conditions, impact, and a minimal sanitized example.

## Dependency checks

Run `npm audit --omit=dev` for the dashboard runtime dependency tree and `npm audit`
for its development tooling. The current ESLint chain includes the upstream
[braces advisory GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm),
which currently has no patched version. It concerns development tooling; avoid
passing untrusted glob patterns to that tooling. Recheck the advisory when updating dependencies.
