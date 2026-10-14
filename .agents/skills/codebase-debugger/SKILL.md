---
name: codebase-debugger
description: Diagnose and fix build errors, runtime crashes, logic bugs, type failures, and unexpected stack traces by tracing the failing behavior to its root cause before editing code.
---

# Codebase Debugger

Use this skill whenever a task involves a build failure, runtime crash, logic bug, type failure, or unexpected stack trace. Read the actual code and trace the failing data or control flow before proposing or applying a fix.

## Investigation

- Parse the reported failure and identify its precise location and conditions.
- Inspect the failing code, relevant imports and types, and its callers or upstream inputs. Follow asynchronous boundaries and environment dependencies when they affect the failure.
- Trace the invalid state or behavior to where it originates. Classify the cause when useful: state or concurrency, contract or type mismatch, or system/environment boundary.
- Do not edit files that have not been inspected, and do not guess from the error text alone.

## Resolution

Before editing, briefly state the root cause, why the current behavior fails, and the smallest set of changes that addresses it. Fix the underlying defect and its immediate dependencies while preserving the codebase's architecture and guarantees. Avoid unrelated refactoring and symptom-only guards unless the guard is itself the correct boundary fix.

Handle relevant boundary cases, then verify the change using checks appropriate to the repository and the failure. Report what was changed and the verification result, including any limitation that prevented verification.
