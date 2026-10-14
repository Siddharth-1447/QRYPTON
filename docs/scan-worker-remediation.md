# Scan worker remediation — 7 October 2026

This records the implemented changes following the [backend audit](backend-diagnostic-audit-2026-10-06.md). The audit and its source index remain historical snapshots; their line numbers and defect descriptions are not a statement of the current implementation.

## Worker lifecycle: ORCH-01 and ORCH-05

- `api/app.py::ScanRequest` validates the three Mosca durations as finite values in `[0, 10000]`. Optional overrides in `BusinessContextPayload` have the same bounds. Invalid requests receive HTTP 422 before locator validation or executor submission.
- `_run_full_scan_in_background` owns early resolution, configuration, execution, sanitized failure persistence, and unconditional activity cleanup. Its outer exception handler writes a terminal `RunResult` with a completion timestamp; its `finally` clears the process-local activity entry. Failure of inner error persistence propagates to this outer guard for another attempt.
- `application/schemas.py::RunFailure` and `ui/contracts.py::SafeRunFailure` accept `resolve`, `configuration`, and `orchestration` in addition to existing stages.
- A database that remains unavailable cannot receive a terminal write. That path logs the persistence failure and still clears process-local activity; it does not claim a successful write.

## Scanner scheduling: ORCH-02

| Code path | Implemented behavior |
|---|---|
| `source/scanner.py::LocalSourceScanner.scan/_scan` | Offloads root resolution, discovery, Python AST/lexical analysis, C/C++ lexical analysis and compiler gate with `asyncio.to_thread`. Observation materialization is limited by remaining evidence capacity. File and observation loops yield every 64 iterations. The source deadline starts before discovery. |
| `source/traversal.py::iter_source_files` | Accepts a cancellation event and checks it while walking directories and files. The async wrapper sets the event on exit so cancellation does not leave the complete tree walking in the executor. Existing callers may omit it. |
| `extended.py::ExtendedStaticScanner._extract` | Async extraction yields between archive members and at each copy chunk of at most 1 MiB. TAR iteration is incremental. Exceptions and cancellation remove the partial temporary directory. Nested extraction uses the same cooperative path. |
| `extended.py::ExtendedStaticScanner.scan/_candidates/_matches` | Incremental deterministic directory walking replaces eager recursive sorting. File reads are bounded and offloaded. Regex results are fetched in batches of 64 in the executor, including searches that produce no matches. Match loops yield periodically; line counting advances from the prior match rather than repeatedly scanning the whole prefix. Cleanup runs in `finally`. All four adapters inheriting this implementation receive these changes. |
| `binary/scanner.py::LocalBinaryScanner._scan` | Offloads path resolution, metadata, hashing, binary parsing, section entropy, and fallback text reads. Symbol/library loops yield every 64 entries, including nonmatches. Section and string-token loops yield each iteration. Existing file-size limits apply before analysis. |
| `binary/scanner.py::_digest/_entropy`, `binary/entropy.py::shannon_entropy` | Hashing and entropy use 64 KiB chunks and check cancellation. Entropy workers own and close their file streams, so coroutine cancellation cannot close a handle while the worker still reads it. Offloading applies to all sizes, including files over 10 MiB. |

`asyncio.to_thread` uses the event loop's thread executor. These operations remain static inspection; target code is not executed.

## Timeout policy

`api/app.py::_size_scaled_timeout_seconds` recognizes both public surface names and canonical target kinds. `_limits` and `_run_scan_in_background` use that policy. The worker selects the smaller of the request's explicit limit and the surface budget.

| Public surface | Canonical target | Seconds |
|---|---|---:|
| `source_repo` | `source_tree` | 90 |
| `source_archive` | `git_archive` | 90 |
| Binary / library / cloud KMS | `file` (or binary format kind) | 1200 |
| Container | `oci_image` / `docker_archive` | 1200 |

Size does not change these budgets. A smaller request limit is retained. Timeout handling persists `failed` with `scan_timeout`, a completion timestamp, and activity cleanup.

## Scanner scheduling verification (before queue/polling repair)

- Added nine scanner regression cases in `tests/scanners/test_async_scanners.py`: deep directory cancellation and traversal shutdown; slow AST work; ZIP and TAR cancellation cleanup; real 11 MiB entropy with event-loop progress; entropy-worker cancellation and stream closure; entropy chunk cancellation; dense metadata match responsiveness and line numbers; nonmatching binary-symbol cancellation.
- Added six surface-mapping cases and two real worker watchdog cases to `tests/api/test_worker_lifecycle.py`. Watchdog cases verify both budget choices and inspect SQLite before polling, then verify terminal API status and activity cleanup. Existing lifecycle tests cover immediate 422 and early/runtime failures.
- Focused scanner/workflow/lifecycle run: **74 passed** before the last two scanner cases were added. Both additional cases passed in the full run.
- Full suite: **327 passed, 1 failed, 2 skipped**. The sole failure is `tests/api/test_report_pdf.py::test_post_pdf_report_contains_all_sections`, which observed `FAILED` while waiting for a source scan. This same scheduling-sensitive test failed before these changes. Its isolated rerun **passed**. The current run alone does not establish which queued/polling race produced that failure.
- Mypy: **passed across 85 source files** under the repository configuration, which suppresses API-module errors.
- Ruff: **passed** on the five changed scanner files and both regression-test files. This does not claim a clean lint result for unrelated existing changes.

## Boundaries still relevant

Cooperative timeouts are not process-enforced deadlines. Cancellation interrupts awaits and loop checkpoints; a thread cannot forcibly terminate an OS read or native parser already executing. Some native work can also hold the GIL. `asyncio.run` waits for executor shutdown, so final persistence can be delayed until in-flight work returns. Hashing, entropy and source traversal receive cancellation signals, but parser internals do not have a universal interruption hook.

Target acquisition precedes this execution watchdog. Normalization, risk evaluation and persistence also retain synchronous sections. Hard end-to-end wall-time and memory guarantees require a supervised process and a deadline covering those stages. Other audit findings and comprehensive archive resource enforcement are not resolved by the scanner scheduling patch. The subsequent queue/polling repair is documented below.

## Queue ownership and bounded polling: ORCH-03 and ORCH-04

`api/app.py::create_scan` now registers the ID as `queued` before executor submission. Submission rejection writes a sanitized terminal result with `scan_submission_failed`, clears registration, and returns HTTP 503. `get_scan` preserves `pending`/`queued` rows and reports them as `QUEUED`, including while all executor slots are occupied.

Running workers maintain a persisted timestamp in the additive `qrypton_run_heartbeats` table, created automatically by `SqliteRunStore` for both new and existing databases. The worker starts its heartbeat after marking the row running and stops it in its outer `finally`. The interval is the smaller of 10 seconds and one third of the grace period. Polling in another API process can therefore recognize a live worker without sharing its in-memory dictionary.

`_expire_orphaned_running_scan` only fails a row when all three conditions hold: status is `running`, local registration is absent, and its heartbeat is older than `QRYPTON_SCAN_ORPHAN_GRACE_SECONDS` (default 60 seconds). Invalid, nonfinite or nonpositive settings fall back to 60. Legacy running rows with no timestamp receive one grace period on first observation; repeated polls do not renew it. A conditional transactional update prevents a stale poll from overwriting a completed row.

`web/src/app/page.tsx` now imports the bounded polling implementation from `web/src/lib/scan-polling.ts`:

- Each request has a 5-second timeout, shortened when the overall deadline is closer. HTTP failures, malformed responses and network failures are explicit `ERROR`/`UNAVAILABLE` polling results. A failed primary status request no longer falls back to posture or pretends to be `RUNNING`.
- Three consecutive polling failures return a local `FAILED` result. A valid queued/running response resets the error counter. A successfully retrieved terminal backend `ERROR`/`FAILED` result still stops immediately.
- A monotonic 15-minute deadline bounds the entire polling loop, including requests and retry delays. Status requests bypass the cache.
- The existing submission error handler displays the visible `Scan failed` alert and the workflow's `submitError`, and clears submitting/polling flags. Messages retain the scan ID and explain that loss of monitoring does not cancel the backend scan; Scan History can be checked later.

This does not introduce a durable queue capable of recovering queued work after a process restart. Unowned queued rows remain queued, as required; the frontend deadline prevents indefinite loading. A heartbeat proves worker liveness, not forward progress inside a stuck native operation.

### Verification after queue/polling repair

- Full backend suite: **346 passed, 2 skipped**. The previously failing PDF workflow passes in this run.
- **18 new backend regressions** cover a real saturated executor, registration before submission, rejected submission cleanup, stale/live/cross-process heartbeats, legacy-row grace, terminal-state protection, configuration and heartbeat-thread shutdown. The older queued-orphan test now asserts preservation of queued jobs.
- **20 frontend tests** pass via `npm test` (Node 22 with TypeScript stripping): HTTP 404/401/429/500/503, malformed JSON/status, network loss, real request abort, consecutive timeouts, error-counter reset, terminal responses and the 15-minute cutoff with deterministic time.
- TypeScript `tsc --noEmit --incremental false`, ESLint on the page/polling module/tests, and backend mypy all pass. Ruff passes on the new queue tests and modified SQLite storage module.

## Algorithm aliases and parameter preservation: NORM-01

`contracts/algorithm_names.py` supplies exact hash spelling aliases to both discovery and risk classification. `source/rules.py::algorithm_for_name` first resolves canonical names, then named API aliases; every rule's canonical spelling round-trips. `sha256`, `sha-256`, `sha_256` and their case variants resolve to the existing persisted canonical name **`sha-256`**. SHA-1, the other supported SHA-2 digests, and explicit SHA-3 digest variants use the same mechanism. SHA-3 digest variants remain distinct; a bare `sha3` no longer guesses SHA3-256. `risk/taxonomy.py::classify_finding` uses the shared spelling normalization for historical/direct aliases as well.

`SourceNormalizer._finding` preserves explicit integer `key_size_bits` as an observed value referencing its supporting evidence. Missing, boolean, out-of-range or unresolved values remain unknown instead of raising a normalization error or inventing a size. The valid range follows the existing Algorithm contract: 1 through 1,000,000 bits.

`python_ast.py::_Visitor._parameters` now reads the bit-valued positional/keyword signatures of PyCryptodome `RSA.generate` and cryptography `rsa.generate_private_key`. Thus `RSA.generate(2048)` reaches `CryptoFinding.algorithm.value.key_size_bits.value == 2048`. Generic `length` is no longer treated as bits: APIs such as HKDF use byte lengths, and units cannot safely be inferred from that keyword alone. Explicit `key_size` metadata remains supported.

Mode parameters are retained for composite names such as `AES-CBC`, explicit algorithm/mode attributes, PyCryptodome `AES.new(..., AES.MODE_CBC)`, and inline cryptography `Cipher(algorithms.AES(...), modes.CBC(...))` calls. The AST binder only associates the algorithm and mode within that same Cipher call. Bare `CBC`/`GCM`/`ECB` evidence retains `parameters={"mode": ...}` on an unknown Algorithm with partial identification; it does not manufacture AES identity or a known key size. Modes are stored in uppercase in canonical findings and converted to the CycloneDX schema's lowercase spelling during export.

SQLite's audited evidence attribute allowlist now retains `algorithm_name`, `key_size_bits` and `mode`; the existing full finding serialization preserves their canonical values. Confidence and supporting evidence references remain attached to the normalized identity and size.

Verification: **97 new normalization regression cases** cover aliases, all rule canonical names, actual AST-to-finding SHA-256/RSA paths, invalid and unresolved sizes, mode bindings, unrelated mode calls, taxonomy consistency, SQLite persistence and CycloneDX mode export. The full backend suite passed with **443 passed, 2 skipped**. Mypy passed across **86 source files** and Ruff passed on all eight changed code/test files. The original SHA-256 audit reproduction was inverted to assert the fixed round trip and passed separately.

## PDF targets, priority ordering and retrieval: PDF-01 and PDF-02

`api/reporting.py::_target_label` replaces the blanket ML-KEM/ML-DSA fallback in both the findings table and migration roadmap. Identified findings retain their explicit targets. Empty symmetric targets receive labelled AEAD/key-length review guidance (`AES-256-GCM`); empty hash targets receive labelled collision-resistance review guidance (`SHA-3 / SHA-512`). These are review prompts, not assertions that every AES or SHA-256 finding requires replacement. Unidentified findings, unknown families and empty asymmetric targets display `Validation / Manual Review Required`. The renderer does not infer an asymmetric use case from an empty recommendation.

Historical ML-KEM, ML-DSA and SLH-DSA targets are filtered from hash, symmetric, MAC, KDF and RNG findings. Persisted explanatory actions remain intact, including text explicitly warning against an asymmetric replacement. Thus those names can legitimately appear in explanatory prose without being migration targets for hashes. The executive briefing also distinguishes public-key migration from symmetric and hash review.

`ui/sqlite_provider.py::run_view_from_result` sorts roadmap rows by descending numeric priority, then finding ID and action for stable ties. Roadmaps are constructed from the persisted JSON result rather than a separate SQL roadmap table, so ordering is applied to the DTO collection. `api/reporting.py::executive_pdf` sorts defensively as well, retains the most urgent action for each findings-table entry, and truncates only after sorting. Reports show the highest 40 actions and state how many additional actions remain.

`api/app.py::_build_pdf_report` opens the configured store, resolves tenant ownership from lightweight run metadata when necessary, calls `get_run` once, and closes the store before rendering. The same deserialized result builds the dashboard view and all finding details. `SqliteDashboardDataProvider.finding_details_from_result` indexes evidence, assessments, recommendations and Mosca evaluations once instead of querying and deserializing the complete run for each finding. Existing single-finding API calls delegate to the same projection. The persistence port exposes a type-only `PersistedRun` contract so the UI adapter retains its existing application-layer import boundary.

The renderer receives `RunResult`, `ExecutivePosture`, `InventoryRow` and `MoscaPoint` sequences, `RoadmapRow` records, and a finding-ID-to-`FindingDetail` mapping. No reporting-only database schema or migration is introduced.

Visual verification also exposed invalid PDF cross-reference offsets caused by replacing page-count text in already serialized bytes. `_PageCountCanvas` now writes page totals through ReportLab before serialization. Chart widths, legend spacing and the severity column were adjusted to fit the page and avoid overlapping content.

Verification after all PDF changes:

- **26 report tests** pass, including 19 new cases covering category-specific targets, unidentified findings, descending top-40 selection, one deserialization per report with explicit/implicit tenant selection, and PDF cross-reference/page-count integrity. The focused report/provider run passed **33 tests**.
- Full backend suite: **462 passed, 2 skipped**. Skips are the Windows symlink privilege case and the opt-in remote acquisition test. The existing Starlette/AnyIO deprecation warning remains.
- Mypy passed across **86 source files** under the repository configuration. Ruff passed on the report renderer, persistence port, SQLite UI adapter and report/provider tests.
- The original SHA-256 PDF audit reproduction now passes, checking migration targets separately from explanatory prose.
- A three-page synthetic RSA/AES/SHA-256 report passed strict `pypdf` parsing and PNG visual inspection, including priority ordering, category-specific guidance, chart layout and page totals.

## Scan wizard recovery and development issues

The wizard treated any validation message as a failed execution. Its Back button changed the step number while the parent submission error continued to hide the form. Field validation now keeps the form editable. Execution errors are tracked separately, and `Back to target` clears the submission outcome and returns to step 2 with the failed target preserved for correction. Closing and reopening an idle wizard clears old completion/error messages; reopening a running scan preserves monitoring.

On confirmed completion, `web/src/app/page.tsx`'s scan submission handler clears the repository locator, branch and uploaded-artifact fields through `lib/scan-form.ts::clearScanTarget`, preserving the selected surface, input mode and business context. The target is consumed before result/history retrieval, so a later dashboard request error cannot retain a completed target in the input box. The result metadata still identifies the scanned target. The review copy now correctly states the 15-minute monitoring bound.

Browser verification exposed a second cause of valid scans failing: `_build_request` passed the wizard's default `data_sensitivity="unclassified"` into `BusinessContext.data_classification`, whose contract only permits public/internal/confidential/restricted. `_ctx_field` now converts empty and unclassified sentinels to unknown values for both structured and flat business context. A real synthetic local scan that failed before this correction completed afterward, with unknown classification retained rather than invented.

`api/scan_errors.py` classifies wrapped acquisition failures using bounded exception cause chains and supplies fixed public messages for missing repositories/branches, denied access, rate limits, connection errors, timeouts and missing local files. Polling returns the safe failure code/stage and run ID instead of replacing every failure with the same retry message. Stored/raw exception text is not returned. Canonical schema validation failures encountered during request construction are labelled configuration failures.

The Next.js three-issue indicator came from the migration priority queue: several actions for one finding shared `key={finding_id}`. `risk-prioritization.tsx` now keys each read-only action row by its finding, action and position, including identical repeated rows. All actions remain visible. `layout.tsx` also declares `data-scroll-behavior="smooth"`, as required by the installed Next.js 16 guide for the application's global smooth-scroll setting.

During verification on this Windows environment, Turbopack's CSS evaluation child exited before its IPC connection could start. The supported Webpack development mode compiled and rendered correctly; `npm run dev` now selects that mode explicitly. The normal Next.js indicator remains enabled and shows no issue count on the verified page.

Verification: the full backend suite passed **480 tests, with 2 skips**, after the wizard/default-context and diagnostic changes; **18 new backend cases** cover safe acquisition diagnostics and default-context completion. All **26 frontend tests** pass, including six target-reset cases. Backend mypy passed across **87 files**; frontend TypeScript and scoped ESLint checks passed. Browser checks covered editable validation, failed-scan Back navigation, successful completion, cleared target fields and the exact historical scan with two SHA-256 actions sharing one finding ID. The fresh console reported no errors or warnings for that scan and the issue badge was absent.
