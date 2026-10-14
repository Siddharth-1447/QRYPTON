# QRYPTON documentation

Use the [repository README](../README.md) for installation, local operation,
configuration, and current security boundaries. The documents below explain the
contracts and record implementation or audit evidence. Test counts, screenshots,
source line references, and release assumptions in historical records apply to
the revision inspected at that time; use current CI for the present checkout.

## Assessment and evidence contracts

- [Risk model 1.0](risk-model-v1.0.md): cryptographic and quantum classification,
  Mosca applicability, business impact, and final priority.
- [Normalization and correlation 1.0](normalization-correlation-v1.0.md): evidence
  provenance, observation states, usage anchors, and merging rules.
- [Remediation ranking 1.0](remediation-ranking-v1.0.md): observed protection
  context and deterministic migration ordering.

## Workspace and reporting

- [Scan progress and finding status](scan-progress-and-status.md): scan comparison,
  analyst lifecycle, provisioned roles, shortcuts, and CI result publishing.
- [Finding actions and exports](finding-actions-and-exports.md): GitHub Issue
  configuration, ticket drafts, report downloads, and CBOM redaction.
- [Scan worker remediation](scan-worker-remediation.md): lifecycle ownership,
  scanner scheduling, watchdogs, heartbeats, polling, and remaining boundaries.

## Implementation and validation records

- [Interactive architecture snapshot](architecture.html) and its
  [source model](architecture.json); code links identify the captured revision.
- [Pipeline QA matrix](qa-validation-matrix.md).
- [Dashboard availability and hydration](dashboard-hydration-fix.md).
- [Login and loading](login-and-loading-validation.md).
- [Design foundation](design-foundation.md).
- [Steel Teal theme validation](steel-teal-theme-validation.md).
- [Typography validation](typography-validation.md).
- [UI refinement](ui-refresh.md).
- [Enterprise demo release record](ENTERPRISE_DEMO_RELEASE.md) and
  [controlled demo corpus](../demo/enterprise/README.md).

Design and demo records can describe earlier palettes, counts, or setup choices.
Follow the root README and current code when these differ.

## Historical audits and proposals

- [Backend diagnostic audit, 6 October 2026](backend-diagnostic-audit-2026-10-06.md):
  pre-remediation findings; subsequent worker changes are linked above.
- [QA audit report](audits/QRYPTON_QA_REPORT.md).
- [QA re-audit report](audits/REAUDIT_REPORT.md).
- [QA-06 / QA-09 proposal](qa06-qa09-implementation-plan.md): a recorded proposal,
  not evidence that those changes were implemented.

The duplicate working source snapshot under local `qa_audit/` is excluded from
Git. Its substantive audit reports are preserved in `docs/audits/`.
