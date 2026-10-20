# QRYPTON documentation

Start with the [project overview](../README.md) and
[getting started](getting-started.md). The guides below describe the checked-in
implementation and its local evaluation boundaries.

## Run and configure

- [Getting started](getting-started.md): installation, a source scan, and dashboards.
- [CLI guide](cli.md): scan, report, and CI commands.
- [Configuration](configuration.md): environment variables and optional integrations.
- [Enterprise demo corpus](../demo/enterprise/README.md): controlled source fixtures.

## Understand the system

- [Architecture](architecture.md): components, scan data flow, and trust boundaries.
- [Risk model](risk-model-v1.0.md): cryptographic risk, quantum risk, and Mosca urgency.
- [Normalization and correlation](normalization-correlation-v1.0.md): evidence,
  observation states, usage identity, and merging rules.
- [Remediation ranking](remediation-ranking-v1.0.md): migration ordering and context.

## Work with results

- [Scan progress and finding status](scan-progress-and-status.md): persisted scans,
  comparisons, analyst roles, and finding lifecycle.
- [Finding actions and exports](finding-actions-and-exports.md): ticket drafts,
  optional GitHub Issues integration, and reporting.
- [Scan worker lifecycle](scan-worker-remediation.md): scheduling, timeouts,
  heartbeats, polling, and operational limits.

## Contribute

Read [CONTRIBUTING.md](../CONTRIBUTING.md) for development checks and
[SECURITY.md](../SECURITY.md) for reporting and deployment boundaries.
The [design foundation](design-foundation.md) identifies shared frontend and PDF
resources and the checks relevant to visual changes.
