# QA-06 and QA-09 — implementation plan awaiting approval

QA-10 and QA-12 are independently authorized fixes. This document proposes QA-06
and QA-09 only; their implementation and acceptance tests require approval.

## QA-06: a single budget for the entire scan

Replace silent skips and permissive archive probing with a shared `ArchiveBudget`
passed through every nested archive and container layer. Never reset counters at
recursion boundaries. Classify archive intent before parsing (QA-10); malformed
archives cannot become text. Retain bounded asynchronous copying and cancellation
cleanup. Extraction finishes successfully before any effective observations are
emitted; a limit failure discards that target's staged observations and temporary
files. Zero findings on an incomplete target must never mean complete coverage.

The following proposed defaults preserve the CLI's current numeric defaults.
Equality passes; exceeding the limit fails. Actual bytes override declared sizes.

| Limit / ScanLimits field | Default | Enforcement |
| --- | --- | --- |
| Compressed bytes / `max_compressed_bytes` | 64 MiB | Stat the root before opening. Charge each nested compressed archive/layer before opening; cumulative root plus nested encoded bytes is the workload budget. Bound each actual read as well to catch replacement/growth; no unlimited recognition/decompression probes. |
| Expanded bytes / `max_expanded_bytes` | 512 MiB | Reject a member's advertised size before opening when it exceeds remaining budget; count actual decompressor output including archive framing/padding and trailing data, before writing. Outer and nested expansion both count. Do not trust gzip ISIZE or ZIP size declarations alone. |
| Members / `max_file_count` | 100,000 | Count every header, including directories and whiteouts, before opening its payload or creating an entry. Aggregate across nesting and layers. Stream TAR headers; cap ZIP central-directory bytes/records before materializing its index. |
| Per-member bytes / `max_file_bytes` | 64 MiB | Check advertised member size before reading and actual streaming bytes before writing; apply the same cap to each scanned leaf. Oversized files are errors, never skipped. |
| Archive nesting / `max_nesting_depth` | 8 | Root depth is 0. Check the next depth before opening a nested archive. Filesystem directory depth is separate and does not consume archive depth. |
| Container layers / `max_layer_count` | 128 | Parse bounded manifest/index metadata; reject an oversized ordered layer list before loading blobs. Count every applied layer in the selected image, including empty layers. Ordinary archives consume no container layer slots. |
| Wall time / `max_wall_time_seconds` | 300 seconds | One monotonic deadline from scan entry through parsing, copying, overlay work and scanning. Check before each blocking stage/chunk. Run hostile archive parsers in a terminable worker process; the supervisor enforces the deadline even if parsing does not yield. Kill/join workers before cleaning their temporary roots. |

Resource controls remain active too: cap evidence at 100,000, memory at 512 MiB
(including indexes and XML/JSON trees), and AST nodes at 1,000,000 where applicable.
Use process resource limits appropriate to the host (Windows Job Object/Linux
resource limits); failure to establish required worker isolation is an explicit
configuration failure. Metadata parsing consumes bytes, memory and time budgets.

### Configuration

Keep `ScanLimits` as the validated request contract. Add one canonical default
factory used by CLI and API; remove duplicated `_limits()` constants. Expose all
seven limits in the CLI TOML `[scan_limits]` table, matching `ScanLimits` names,
with equivalent CLI overrides and a typed API `scan_limits` object. CLI overrides
win over TOML; unset values use the factory. Reject unknown fields, nonpositive
byte/count/time bounds and negative depth. Server hard ceilings clamp permissible
user overrides by rejecting requests that exceed policy, with an explicit error.
Replace the API's implicit size-scaled deadline with this documented default and
explicit override. Include effective limits in scanner configuration digests and
coverage metadata so results can be reproduced.

### Failure and path contract

Introduce a typed `ArchiveLimitError(code, limit_name, reason, maximum, observed,
member, depth, layer)`; codes are `archive_compressed_bytes_limit`,
`archive_expanded_bytes_limit`, `archive_member_count_limit`,
`archive_member_size_limit`, `archive_nesting_depth_limit`,
`archive_layer_count_limit`, and `archive_time_limit`. Preserve QA-10's distinct
`invalid_archive` code. Propagate these as structured scanner-result fields,
`partial=true`/status `partial`, plus bounded sanitized diagnostics. Extend the
result schema and persistence rather than relying only on warning strings.
Unexpected worker failure is failed coverage, never a successful empty scan.

CLI output must include the code, limit name and reason, e.g.
`archive_member_count_limit: max_file_count=10 exceeded by member 11; partial scan`.
Existing default policy gates reject partial coverage; `--allow-partial` permits
report retrieval without erasing incompleteness. Add CBOM metadata properties for
coverage status, error code, limit name, effective limits and processed/expected
members/layers. Persist and expose the same structured coverage through API/run
results, including zero-finding exports. Partial metadata must survive storage
and export round trips.

Validate archive names as POSIX relative paths before writing: reject absolute,
drive/UNC, backslash, NUL, `.`/`..` components and host-invalid paths; ensure every
resolved destination stays under the one private temp root. Reject symlinks,
hardlinks, device entries, FIFOs and unsupported special entries with explicit
coverage errors. Prevent duplicate-path/type collisions from bypassing budgets.
Use exclusive creation/no-follow operations where supported; extracted inputs
cannot create links. All parsing failures, limits, exceptions and cancellation
remove staging output. Nothing may extract outside the temporary root.

### Acceptance checks after approval

For each of the seven limits, one parameterized boundary test covers exactly at
the limit (passes) and limit+1 (fails closed with its precise code and limit name).
Use a deterministic injected clock for deadline equality and a separate hostile
worker timeout test. Depth 0 allows a root archive and rejects its first nested
archive. Verify both TAR and ZIP paths, aggregate nested counters, misleading
sizes, oversized entries, unsafe paths, cleanup and corruption after valid entries.
Assert no limit case has zero findings with complete coverage. Keep the 256 KiB
gzip expansion fixture rejected under a 64 KiB budget, including padding-only
and concatenated gzip streams. Assert CLI, stored result, CBOM and coverage
metadata carry the same error. Hostile tests run in subprocesses with parent
timeouts; ensure timeout kills the worker and leaves no live child/temp output.

## QA-09: effective container filesystem and separate history

Implement after QA-06, QA-10 and QA-03. QA-03 is a prerequisite for suppressing
algorithm inference from manifest/config wording; do not expand that work here.

1. Detect Docker-save (`manifest.json`) and OCI layout (`oci-layout`, `index.json`)
   from bounded structural metadata. For Docker-save, select an unambiguous image
   or require an image selector; follow its `Layers` array order. For OCI, resolve
   selected manifest/index/platform descriptors, verify blob digest and size, and
   follow manifest `layers` order. Reject missing, corrupt or unsupported layer
   media types rather than silently skipping them. Multiple images/platforms need
   explicit selection or separately identified results.
2. Stage each layer under QA-06's shared budget and private temporary root. Build
   an overlay index for the effective filesystem, applying layers oldest to newest.
   Interpret whiteouts before ordinary additions in the same layer: `.wh.<name>`
   deletes the inherited named entry and its subtree; `.wh..wh..opq` deletes all
   inherited children of that directory. Same-layer additions survive opacity.
   A later layer may recreate any deleted file/directory. Whiteout marker files
   never become crypto content. Handle file/directory replacement explicitly.
3. Validate whiteout parents and derived names with the same POSIX path validator.
   Reject empty targets, `.`/`..`, separators, absolute or drive names. Deletion
   operates on the internal overlay index only; it cannot delete host paths.
   Reject links and special entries under QA-06's extraction contract.
4. Scan surviving regular files only for effective findings. Do not scan archive
   blobs, manifest/config prose, descriptor digests or whiteout marker names as
   crypto content. Structured package/config interpretation may emit separately
   supported metadata evidence under QA-03, never keyword-derived algorithms.
5. Retain layer identity/digest, ordinal, logical path and file digest on each
   evidence record. Independently record bounded historical evidence from removed
   or replaced content with `present_in_layer`, `deleted_in_layer`/`replaced_in_layer`
   and deletion reason. A whiteout record reads “present in layer N, deleted in
   layer M”. Expose history as a separate collection/view and CBOM extension,
   excluded from effective finding totals and risk assessment. Re-added identical
   bytes retain their new provenance; do not deduplicate away the deletion history.
6. Coverage is complete only after every selected layer validates and applies and
   the effective scan completes. Any layer error/limit makes coverage partial with
   layer identity, processed/expected counts and explicit reason. Fail closed for
   the affected image; never present a partly applied overlay as final content.

### Acceptance checks after approval

Run both Docker-save and OCI fixtures: RSA in layer 1 removed by
`.wh.crypto.conf` in layer 2 produces no effective RSA finding, while history
records layers 1 and 2. Test opaque-directory removal with same-layer additions,
file recreation in layer 3, replacement, directory subtree deletion, reordered
members within one layer, and whiteout traversal attempts. Manifest/config wording
must not fabricate AES. Include missing/truncated layers, OCI digest mismatch,
layer-count boundaries and worker timeout. `partial=false` is permitted only when
all selected layers and the effective scan finish successfully. Validate history
and effective provenance through persistence, API and CBOM export.
