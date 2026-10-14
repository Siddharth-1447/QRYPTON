# QRYPTON backend diagnostic audit

Audit date: 6 October 2026. Repository: `C:/Users/SIDDHARTH PATEL/QRYPTON`.

**Historical snapshot:** the findings and line references below describe the pre-remediation audit. Subsequent ORCH-01/05 lifecycle fixes and ORCH-02 cooperative scanner changes are recorded in [scan-worker-remediation.md](scan-worker-remediation.md), including current verification and remaining timeout limitations.

HEAD: `2a043fad954ad8cee626f4f8ae79a662acd7ee42`; findings refer to the **current working tree**, which already contained extensive uncommitted changes. Application code was not changed by this audit.

## Findings that explain the reported symptoms

**There is a reproducible permanent-running failure, not merely a slow scanner.** The API accepts negative Mosca durations, the worker records `running`, and then `MoscaParameters` raises outside the worker's protected block. The executor retains the exception in a discarded `Future`; the process-local activity entry survives. Every subsequent status request sees that entry and returns `RUNNING` indefinitely.

**There are also independent ways to keep the browser loading:** scanners block their private asyncio event loop so `wait_for` cannot reliably interrupt them; target acquisition is outside that timeout; the browser converts persistent request failures into `RUNNING` and polls forever. Separately, a queued job can be falsely marked failed before it starts.

**The SHA-256 → ML-KEM/ML-DSA problem is reproducible in PDF rendering.** The current recommendation engine intentionally leaves hash and symmetric targets empty; the PDF roadmap substitutes asymmetric targets for every empty target list.

| ID | Priority | Finding | Evidence strength |
|---|---|---|---|
| ORCH-01 | P1 | Uncaught worker configuration validation leaves permanent `running` and stale activity entry | Reproduced with a real executor, temporary DB, and `data_lifetime=-1` |
| ORCH-02 | P1 | Non-yielding scan code defeats cooperative timeout | Code trace plus bounded async-generator reproduction |
| ORCH-03 | P1 | Polling mistakes a live queued job or another process's job for an orphan | Queued-job case reproduced deterministically |
| ORCH-04 | P1 | Browser polls forever on persistent API/network errors | Direct frontend code trace |
| ORCH-05 | P1 | Resolution failure uses invalid `RunFailure(stage="resolve")`, preventing structured failure persistence | Reproduced; polling subsequently repairs only the status column |
| ORCH-06 | P2 | SQLite waits, repeated writes, missing connection ownership, and inconsistent DB selection aggravate failures | Code trace; no live deadlock claimed |
| SCAN-01 | P1 | Four advertised surfaces share lexical token inspection; major semantic analysis is absent | Complete routing/implementation trace |
| SCAN-02 | P1 | Archive resource limits are only partially enforced; errors can be silently swallowed | Code trace |
| NORM-01 | P1 | Canonical SHA-256 cannot round-trip through normalization; key sizes/modes are lost | SHA alias defect reproduced; parameter loss traced |
| PDF-01 | P1 | Empty targets receive ML-KEM/ML-DSA in the PDF roadmap | Reproduced using canonical SHA-256 and actual recommendation engine |
| PDF-02 | P2 | Roadmap truncation/order, repeated DB deserialization, and raw PDF byte patching | Code trace |

Priority describes audit repair order, not a CVSS rating.

## Scope and verification

The repository inventory includes backend, frontend integration, tests, configuration, CI, documentation, demo inputs, and local persisted databases. All **85 Python backend modules, totaling 12,443 lines**, were parsed and indexed with SHA-256 hashes, imports, symbols, source locations, and docstrings in [backend-audit-index.json](<C:/Users/SIDDHARTH PATEL/QRYPTON/docs/backend-audit-index.json>). Manual tracing concentrated on every path involved in the five requested areas. Installed dependencies, Git internals, generated caches, and binary artifacts were not treated as authored source. An index is not a claim that every branch was dynamically exercised.

Verification against the working tree:

| Check | Result |
|---|---|
| Existing `pytest -q` suite | **267 passed, 1 failed, 2 skipped** in 34.54 seconds |
| Failed test | `tests/api/test_report_pdf.py::test_post_pdf_report_contains_all_sections`: scan settled as `FAILED` before PDF rendering |
| Isolated rerun of that test | **Passed**; consistent with a scheduling-sensitive lifecycle failure, but the original failure alone does not prove which race occurred |
| Audit defect reproductions | **6 passed**; passing means the existing defect was observed, not repaired |
| `ruff check src tests` | **259 existing violations** |
| `mypy src --no-error-summary` | Exit 0; API modules are explicitly excluded from useful checking by `pyproject.toml` overrides and `app.py`'s file-level type ignore |
| Ruff on new reproduction file | Passed |

The six reproducible cases live in [test_backend_audit_reproductions.py](<C:/Users/SIDDHARTH PATEL/QRYPTON/scratch/test_backend_audit_reproductions.py>). They use temporary databases and controlled local inputs. The timeout demonstration sleeps for 80 ms under a 10 ms timeout and completes successfully rather than timing out; it does not launch an infinite loop. The PDF case supplies a canonical SHA-256 finding because the separate normalization defect would otherwise erase that identity.

The existing scratch watchdog test merely constructs a failure DTO; it does not exercise cancellation, worker death, or DB updates. The normal suite's remote-acquisition test is opt-in and was skipped; the Windows symlink test was also skipped. No production process stack, authenticated cloud endpoint, or external registry was inspected.

Read-only SQL inspection of the available `qrypton.sqlite3` found 85 completed, 66 partial, 9 failed, 3 pending, and 3 queued rows. All six pending/queued rows have null `result_json`; one failed row also has null `result_json`. These are evidence of unfinished/metadata-only records, **not proof that those rows are currently owned by a live or dead worker**: the schema has no lease, heartbeat, or creation timestamp for provisional rows. Other available DBs were inspected for aggregate status counts without printing target contents.

## 1. Orchestration, asynchronous work, and persistence

### Actual lifecycle

1. `POST /api/v1/scans` → `create_scan`, [src/qrypton/api/app.py:1488](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1488>). This is a synchronous FastAPI route, not an async HTTP handler.
2. `ScanRequest`, [src/qrypton/api/app.py:247](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:247>), accepts target metadata and required float values for X/Y/Z. The floats have no range or finite-value constraints at this boundary.
3. `_validate_scan_locator`, [src/qrypton/api/app.py:1041](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1041>), resolves shape with `fetch_remote=False`; `_check_locator_shape`, line 993, checks target-specific file/directory requirements. This is not entirely I/O-free: local resolution, upload metadata, and KMS/container descriptor creation still occur.
4. `create_scan` derives a provisional HMAC run ID using tenant, target, reference, and wall-clock time, then commits a `queued` row with no request/result payload at lines 1522–1551.
5. `_SCAN_EXECUTOR.submit(_run_full_scan_in_background, request, scan_id)`, line 1556, enqueues work in a process-local `ThreadPoolExecutor(max_workers=2)`, declared at line 69. There is no Celery, Redis, RQ, broker, durable job queue, admission bound, retry scheduler, or request replay record. The returned `Future` is discarded.
6. `_run_full_scan_in_background`, line 1411, sets `_ACTIVE_SCANS[id]="resolving repository"`, updates SQL status to `running`, and calls `_build_request`. Remote acquisition, full file reads, hashing, descriptor normalization, and domain validation happen here.
7. At lines 1472–1483 it constructs `QryptonConfig` and `MoscaParameters`, sets stage to `scanning cryptographic evidence`, and invokes `_run_scan_in_background`.
8. `_run_scan_in_background`, line 1323, builds an orchestrator and executes `asyncio.run(asyncio.wait_for(orchestrator.run(...), timeout=wall_time))`. The provisional ID is passed explicitly, so the normal API path does not have an ID mismatch between submission and finalization.
9. `build_services`, [src/qrypton/application/config.py:53](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/config.py:53>), constructs six scanner instances, normalizers, correlation, Mosca risk, PQC recommendations, CycloneDX exporter, and one `SqliteRunStore` for the run. Source-tree and archive scanners intentionally share the name `qrypton-source`, but accept different target kinds.
10. `QryptonOrchestrator.run`, [src/qrypton/application/orchestration.py:87](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/orchestration.py:87>), calls `begin_run`, selects eligible scanners, and awaits `asyncio.gather` of `_scan_one` behind a semaphore. API configuration defaults to one scanner execution at a time inside each run; the outer executor permits two runs at once.
11. `_scan_one`, line 264, consumes raw observations into a list, normalizes them, derives candidates, and persists a scanner execution record. It then returns evidence and findings to the orchestrator.
12. `DeterministicCorrelationEngine.correlate`, [src/qrypton/application/correlation.py:35](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/correlation.py:35>), groups canonical identity plus usage context/location, retains evidence fingerprints, and derives stable finding IDs. This is not repository-wide merging by algorithm name.
13. `_assess_and_recommend`, [src/qrypton/application/orchestration.py:357](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/orchestration.py:357>), produces assessments, persisted Mosca evaluations, recommendation records, plans, and downstream failures. Export uses `CycloneDx16CbomExporter.export`, [src/qrypton/exporters/cyclonedx_1_6.py:81](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/exporters/cyclonedx_1_6.py:81>), with one immediate retry.
14. The orchestrator builds a `RunResult`, calls `persist_artifacts` and then `finalize_run`, lines 237–238. `finalize_run` calls `persist_artifacts` again: the final JSON/CBOM is serialized and committed twice.
15. `_run_scan_in_background` clears activity in `finally`, line 1406. `GET /api/v1/scans/{scan_id}` reads SQL status and either uses the activity dictionary or rebuilds a persisted dashboard view.

The HTTP response uses `QUEUED`/`RUNNING`; the raw SQL values are `queued`/`running`. `RunStatus` in [src/qrypton/contracts/enums.py:150](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/contracts/enums.py:150>) instead defines `pending`, scanning/normalizing/correlating/assessing/recommending/exporting/persisting, completed/partial/failed. Most of those intermediate domain states are never persisted by this path. There is no actual `IN_PROGRESS` member. The displayed 10/20/50/100 percent progress is stage-based, not measured throughput.

### ORCH-01: exception escapes after target construction and survives as a live-looking scan

Exact sequence:

```text
ScanRequest(data_lifetime=-1) is accepted
create_scan commits queued
worker sets process-local stage and SQL running
_build_request succeeds for an ordinary local source tree
MoscaParameters(data_shelf_life_years=-1) raises ValidationError
exception escapes _run_full_scan_in_background
executor Future contains exception, but nobody reads it
activity entry remains; SQL remains running; GET reports RUNNING forever
```

The `_build_request` catch at [src/qrypton/api/app.py:1428](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1428>) ends before config construction at line 1472. The cleanup at line 1466 belongs only to that resolution-exception path; there is no outer `try/finally` around the full worker. `_run_scan_in_background`'s cleanup has not yet been entered. Negative migration/horizon or values over the Mosca maximum create equivalent opportunities. A transient filesystem failure during `workspace_root` selection is another possible exception in this gap.

This is a confirmed bug even though the user's particular hung run has not been tied to a captured request payload. The reproduction waits for the actual future to finish, verifies its `ValidationError`, then verifies that `get_scan` still returns `RUNNING`.

### ORCH-02: the watchdog is cooperative, inconsistently configured, and starts late

[src/qrypton/api/app.py:273](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:273>) returns 90 seconds only for the UI names `source_repo` and `source_archive`, otherwise 1,200 seconds. `_limits` passes the UI target type. But the worker at line 1340 passes `run_request.target.kind.value`, which is `source_tree` or `git_archive`; therefore **the outer source timeout is 1,200 seconds, while the source scanner's internal limit is 90 seconds**. `size_bytes` is unused despite the size-scaled function name.

More fundamentally:

- `LocalSourceScanner.scan`, [src/qrypton/scanners/source/scanner.py:30](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/scanner.py:30>); `ExtendedStaticScanner.scan`, [src/qrypton/scanners/extended.py:193](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:193>); and `LocalBinaryScanner.scan`, [src/qrypton/scanners/binary/scanner.py:91](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/binary/scanner.py:91>) contain synchronous walking, file reads, parsing, decompression, regex matching, and entropy work. They have async-generator syntax but no awaited scheduling point in their loops.
- `yield observation` is not by itself a yield to the event-loop scheduler when the consumer immediately requests the next element. The `_scan_one` loop can run continuously.
- Normalization, correlation, risk/recommendation, schema validation, serialization, and SQLite access are also synchronous on the private scan loop. A timer cannot run while that loop is blocked; overdue work can complete before cancellation is delivered.
- The semaphore bounds coroutine admission; it does not supply process isolation, memory limits, preemption, or actual CPU parallelism.
- `build_orchestrator(config)` is evaluated before `wait_for` starts waiting, so service/schema/DB construction is outside its effective protection too.
- All `_build_request` work is outside the outer watchdog. `locator.read_bytes()` at [src/qrypton/api/app.py:1090](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1090>) loads an entire local artifact before any scanner file-size gate.
- `_fetch_tarball_to_source_dir`, line 438, uses a 10-second URL socket timeout and a 30-second checked deadline. Checks occur after download reads and between tar members; `getmembers()` and individual reads are not preempted. There is no durable acquisition deadline in SQL.

An infinite parser loop or stuck filesystem call can occupy one of two worker threads indefinitely. A large but finite target can appear hung while repeatedly performing whole-file operations. A hard deadline requires an independently supervised execution boundary; wrapping more synchronous code in `wait_for` is insufficient.

### ORCH-03: orphan detection races with real queues and is invalid across processes

At [src/qrypton/api/app.py:1596](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1596>), any `pending`/`queued`/`running` row without `_scan_stage(id)` is marked failed. The activity entry is installed only when the thread starts at line 1423, **not when the job is enqueued**.

With both workers busy, the third job has a valid queued future but no dictionary entry. Its first poll changes it to failed. Even an otherwise idle executor has a small scheduling window between submission and stage registration. The queued future is not cancelled; when it eventually starts, it changes failed → running → completed, violating terminal-state monotonicity. The isolated reproduction deliberately occupies an executor slot and confirms this false failure.

In multiple Uvicorn processes, each process has its own executor/dictionary. A poll handled by process B cannot see process A's worker and may mark a healthy run failed. A real process restart loses all queued requests because SQL stores no executable request payload; the route only lazily marks metadata rows failed when polled.

There is also a read/update race: a poll can read running, the worker can finish and clear activity, then the poll can blindly `UPDATE ... SET status='failed'`. `_persist_scan_status` has no expected-state/lease condition. It can overwrite a completed status while leaving a completed `result_json`; `get_scan`, history, and provider views then disagree. This interleaving is code-established, not a separately reproduced live incident.

### ORCH-04: frontend hides errors behind endless polling

`fetchScanStatus`, [web/src/app/page.tsx:207](<C:/Users/SIDDHARTH PATEL/QRYPTON/web/src/app/page.tsx:207>), returns `RUNNING` on fetch exceptions. Non-OK responses fall back to `/api/v1/posture`; failure there also returns `RUNNING`. JSON failures are swallowed by the polling loop.

`pollScanUntilSettled`, line 239, uses `while (true)` and a 1,500 ms interval, terminating only on recognized success/failure strings. There is no total deadline, consecutive-error threshold, explicit unknown/unavailable state, or cancellation argument. Each status/posture request has a 5-second timeout. A persistent 404, 500, 503, malformed response, wrong backend origin, or unavailable API can therefore produce an eternal spinner even when no worker is running.

The POST itself uses a 10-second timeout at line 640; upload uses 30 seconds in [web/src/components/scan-workflow.tsx:599](<C:/Users/SIDDHARTH PATEL/QRYPTON/web/src/components/scan-workflow.tsx:599>). SQL acceptance can wait 10 seconds plus other work, so the browser can time out after the server has accepted a job. A retry creates another ID; there is no idempotency key.

### Exception containment: what works and what does not

| Boundary | Current handling | Remaining gap |
|---|---|---|
| Scanner iteration/normalization | `_scan_one` catches ordinary `Exception` at orchestration line 328, returns a failed scanner DTO | `persist_scanner_result` at line 338 is outside that catch; outer API wrapper normally catches its exception |
| All scanners fail | Orchestration lines 119–131 finalizes `FAILED` | Store failure can escape; failure result omits asset/target context |
| Correlation | Lines 132–153 return `PARTIAL` | Partial persistence can fail |
| Individual risk/Mosca/recommendation | Lines 376–435 record failures, continue with other findings | `TypeError` compatibility retries can mask an internal programming error as a signature mismatch |
| CBOM | Lines 168–208 retry twice then persist `PARTIAL` | Both attempts are synchronous; repeated expensive failure; logging/result construction/store can still escape |
| Inner worker ordinary exception/timeout | API lines 1342–1405 attempt a failed `RunResult` on a new store, then clear stage | If error persistence fails, only logs remain; no durable retry/dead-letter mechanism |
| Full-worker target resolution | API lines 1430–1467 try to persist failure, clear stage | **`RunFailure(stage="resolve")` is invalid**; schema accepts only scanner/normalization/correlation/risk/recommendation/export/store at [src/qrypton/application/schemas.py:41](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/schemas.py:41>) |
| Full-worker config construction | API lines 1472–1485 | No surrounding exception containment or cleanup |
| Queue submission | API line 1556 | Submit failure after queued commit leaves a stranded row; no `Future` callback |
| Cancellation/process termination | No durable supervisor/lease | `Exception` does not cover all `BaseException` cases; OS process death cannot execute `finally` |

ORCH-05 was reproduced: after `_build_request` raises, the attempt to construct `RunFailure(stage="resolve")` raises its own validation error, swallowed as a supposed DB error at line 1462. SQL remains running/null. The activity entry is cleared, so a later status GET changes SQL to failed, still with no structured failure artifact. This path **does not indefinitely report RUNNING in the current same-process GET implementation**; it leaves incomplete history until polling and loses the original diagnostic. The failure message also interpolates unrestricted exception text despite a 256-character schema limit.

### SQLite and lock assessment

`SqliteRunStore.__init__`, [src/qrypton/storage/sqlite.py:14](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/storage/sqlite.py:14>), opens with `check_same_thread=False`, a 30-second timeout, `PRAGMA journal_mode=DELETE`, and `busy_timeout=30000`. Every new store executes schema DDL and version checks. Status polling instantiates this write-capable store at API line 1584, loads all tenant run IDs to find one ID, then may instantiate a second provider/store.

`_ACTIVE_SCANS_LOCK` at API line 71 is a short-held dictionary mutex. Its accesses at lines 1298–1310 neither nest nor hold it during SQLite work. **There is no evidence of a deadlock in that mutex.** The failure is incorrect lifecycle ownership, not a missing unlock there.

SQLite concurrency concerns are different:

- `DELETE` journaling serializes writers; starting multiple scans while polling/reporting repeatedly opens schema-initializing connections and creates contention.
- `check_same_thread=False` is not a transaction lock. `_active` is mutable store state; sharing a store across simultaneous runs would be unsafe. The standard API currently builds a separate store per run, which limits that specific risk.
- Neither the successful `build_orchestrator(...).run(...)` path nor request-scoped dashboard providers explicitly closes its owning store. Disposal depends on object lifetime/GC. This is a resource-lifetime defect, not proof each such connection holds a permanent write lock.
- A failed transaction has no explicit rollback guard before the error handler opens another store. Retained connection/transaction state can obstruct failure persistence.
- Two full final writes increase lock and serialization cost.
- `_persist_scan_status` uses 10 seconds; the regular store uses 30. Both exceed the browser status request timeout.
- `get_provider` at API line 85 tries `qrypton.db`, `qrypton.sqlite3`, then `qrypton_demo.db` without an environment override, while writes/status use `qrypton.sqlite3`. If both the first two DBs exist, polling can read status from one DB and a terminal dashboard from another.
- GET's orphan repair writes status only; no failure JSON, timestamps, ownership token, or version check accompanies the change.

The local DB snapshot alone cannot identify a current lock holder. No unsupported assertion of a SQLite deadlock is necessary to explain the confirmed hang.

## 2. Exact implementations of the six scan surfaces

The router is `SCANNER_ROUTING`, [src/qrypton/api/app.py:979](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:979>).

| Surface | Target kind | Registered implementation/version | Actual analysis |
|---|---|---|---|
| Source code | `source_tree` | `LocalSourceScanner`, qrypton-source 0.2.0 | Python stdlib AST; token fallback; C/C++ regex |
| Source archive | `git_archive` | `ExtendedStaticScanner`, qrypton-source 0.4.0 | Recursive ZIP/TAR extraction, generic text token search |
| Binary/executable | `file` | `LocalBinaryScanner`, qrypton-binary 0.3.0 | Custom struct-based ELF/PE/Mach-O parsing, symbols/imports, entropy, fallback substring scan |
| Package manifest | `file` | `LibraryDependencyScanner`, qrypton-library 0.4.0 | Subclass of the same extended token scanner |
| Container | `oci_image` | `ContainerImageScanner`, qrypton-container 0.4.0 | Same recursive archive/token scanner or identifier-only descriptor |
| Cloud KMS | `file` | `CloudKmsScanner`, qrypton-kms 0.4.0 | Same token scanner or identifier-only descriptor |

There are six registered instances, not six independent semantic engines. The base extended scanner also advertises OCI/Docker/file support, but API name selection routes library/container/KMS to the named subclasses.

### A. Source code

`iter_source_files`, [src/qrypton/scanners/source/traversal.py:96](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/traversal.py:96>), uses deterministic `os.walk(topdown=True, followlinks=False)`, sorted directories/files, and hard pruning of `.git`, `.hg`, `.svn`, `.venv`, `venv`, `node_modules`, `vendor`, `dist`, `build`, `__pycache__`, `.tox`, `.next`, `.cache`, `.mypy_cache`, `.ruff_cache`, and `site-packages`. Root `.gitignore` uses `pathspec` gitwildmatch; ignored patterns filter files rather than pruning arbitrary matching directories. Nested `.gitignore` files are not loaded.

Extensions are exactly `.py`, `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, from [src/qrypton/scanners/source/policy.py:16](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/policy.py:16>). JavaScript/TypeScript, Java, Go, Rust, C#, PHP, etc. are not semantically scanned as source trees. A repository dominated by those files can complete with few or zero findings.

Source limits: 5 MiB/file, 512 MiB accumulated source bytes, 1,024-byte snippet cap, API 100,000 files/evidence, and 1,000,000 AST nodes. The traversal materializes all selected raw bytes and decoded strings in a tuple before analysis, so 512 MiB of input is not a 512 MiB process-memory ceiling. Time is checked between directories/files and before file analysis, not during a single parser call. Encoding uses UTF-8 BOM handling, replacement fallback, and reduced confidence for degraded decoding.

Python `analyze_python_ast`, [src/qrypton/scanners/source/python_ast.py:210](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/python_ast.py:210>), invokes stdlib `ast.parse`, then `_Visitor(ast.NodeVisitor)`. Imports/aliases populate a dictionary; calls are inspected for recognized algorithm names in the tail and then dotted segments. Literal keyword `key_size` or `length` is recorded as `key_size_bits`. No expression evaluation, interprocedural dataflow, call reachability, scope-aware rebinding, or type resolution occurs. The call check only requires a recognized name and a dot; it does not require that the root is an authenticated crypto import. For example, an unrelated object's `.sha256()` can be classified despite the “import-bound” description. AST construction occurs before node-count enforcement.

AST confidence is .80 for imports, .95 for ordinary recognized calls, and 1.00 when literal parameters are found. Mode constructors use .95; TLS/SSLContext/wrap_socket and literal `set_ciphers` arguments have explicit rules. These are fixed detector confidences, not empirical probabilities.

Syntax failure falls back to `analyze_python_lexical`, [src/qrypton/scanners/source/python_lexical.py:55](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/python_lexical.py:55>): stdlib `tokenize.generate_tokens` materializes the token list; only NAME tokens and call-like NAME + `(` patterns count. Comments are ignored. This function discards the passed limits and policy; the caller bounds emitted results.

C/C++ `analyze_cpp_lexical`, [src/qrypton/scanners/source/cpp_lexical.py:97](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/cpp_lexical.py:97>), uses:

```text
comments: //[^\n]*|/\*.*?\*/                 (DOTALL)
includes: ^\s*#\s*include\s*[<"]([^>"]+)[>"] (MULTILINE)
calls:    \b([A-Za-z_]\w*)\s*\(
strings:  "([^"\\]*(?:\\.[^"\\]*)*)"
```

API prefixes include EVP_aes/AES_, EVP_sha/SHA, MD5, RSA_, EVP_PKEY_RSA/EC, crypto_box/sign, BCrypt, CCCrypt, mbedtls_aes/sha, wolfSSL. Header prefixes include OpenSSL, mbedTLS, wolfSSL, sodium, bcrypt, CommonCrypto. Confidence is .55 with a crypto header, .35 without; TLS_/ECDHE strings are .35. Regex comment removal is not a C lexer and can alter string content. Broad SHA/EVP_sha prefixes resolve to SHA-256 even when the API name means a different digest. No tree-sitter, libclang, or C/C++ AST is used.

`gcc_syntax_status`, [src/qrypton/scanners/source/gcc_gate.py:22](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/gcc_gate.py:22>), optionally runs gcc/g++ with fixed `-fsyntax-only`, shell disabled and a maximum 10-second subprocess timeout. It is disabled by default and is a syntax gate, not a semantic detector.

`ALGORITHM_RULES` and `_ORDERED_TOKENS`, [src/qrypton/scanners/source/rules.py:15](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/rules.py:15>), cover MD5/SHA families, AES/ChaCha, RSA/EC/DSA/DH/25519/448, HMAC/KDFs, PQC names, and broad Windows crypto APIs. `algorithm_for_name`, line 88, applies casefolding, hyphen/dot → underscore, exact/prefix matching, then substring matching. This permissive matching is shared with binary normalization.

### B. Source archives

`ExtendedStaticScanner._extract`, [src/qrypton/scanners/extended.py:131](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:131>), creates a temporary tree. It detects formats using `zipfile.is_zipfile` and `tarfile.is_tarfile`, reads ZIP central-directory entries or TAR members, writes regular-file contents, and recursively unpacks archive-looking children into `_<name>_extracted` directories.

Path checks reject empty names, leading `/`, backslashes, and resolved paths outside the destination. TAR nonregular members are skipped. Extraction does not use a generic unchecked `extractall`.

Implemented bounds and gaps:

- Expanded member sizes accumulate against 512 MiB; nested archive bytes and their expanded children both count.
- Recursion stops only when `current_depth > 8`; levels 0 through 8 run. Deeper content is silently skipped rather than marked partial.
- ZIP `archive.read(info)` allocates whole members; TAR uses bounded reads, but member enumeration is eager. No streaming member-count or RSS guard exists.
- `max_compressed_bytes`, `max_file_count`, `max_layer_count`, `max_memory_bytes`, and wall-time are not enforced inside this engine. API upload caps help only uploaded inputs; arbitrary local artifacts reach `_build_request` first.
- Files above `max_file_bytes` (64 MiB) are skipped in the scan walk without a partial warning.
- `_extract` is invoked before the scan's `try/finally`; an extraction exception can leak its temporary tree.
- The inner extractor catches `OSError`, `KeyError`, `TarError`, and `BadZipFile` and executes `pass` at lines 176–177. Malformed/partially readable archives can yield incomplete or empty “completed” scans. `ValueError` for limits/path safety does escape.
- `sorted(root.rglob("*"))` eagerly enumerates the whole extracted tree, with no source hard-ignore pruning. Nested archive bytes remain in the tree and may themselves be decoded/searched in addition to extracted files, duplicating noisy evidence.

**Uploaded source archives do not invoke the Python AST/C++ source scanner.** Hosted repositories downloaded through `_fetch_tarball_to_source_dir` become source trees and do use it. The same code uploaded as ZIP versus scanned as a directory therefore takes different detection paths and can produce materially different findings.

Remote TAR acquisition is a separate extractor, [src/qrypton/api/app.py:438](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:438>): 64 MiB compressed download limit, a 30-second checked deadline, up to 64 MiB read per file, but no aggregate expanded-byte or file-count limit. Oversized member content is truncated without an explicit scanner partial flag. Successful download/descriptors have no complete worker-owned temp cleanup path.

### Shared token engine for archives, manifests, containers, and KMS

[src/qrypton/scanners/extended.py:21](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:21>) defines the exact token map:

```text
rsa→rsa; sha1→sha-1; sha-256/sha256→sha-256; md5→md5;
des→des; 3des→3des; ecdh→ecdh; ecdsa→ecdsa;
ed25519→ed25519; x25519→x25519; aes→aes; chacha20→chacha20;
ml-kem/kyber→ml-kem; ml-dsa/dilithium→ml-dsa;
tls/ssl/https→tls; crypto/cipher→aes;
container/docker→sha-256; nginx→rsa;
dvwa/web-dvwa/vulnerables→md5.
```

The compiled regex is case-insensitive `(?<![A-Za-z0-9-])(escaped alternation)(?![A-Za-z0-9-])`. Package matching instead uses `(?<![A-Za-z0-9_-])(...)(?![A-Za-z0-9_-])` for cryptography, pycryptodome, pycrypto, pyopenssl, openssl, libsodium, boringssl, libressl, mbedtls, cryptodome, nacl, bcrypt, scrypt (mbedtls is redundantly listed).

Every candidate is read and UTF-8 decoded with replacement. Algorithm observations have fixed confidence .75, package observations .85. Line numbers use `text.count("\n", 0, match.start())` for each match, creating repeated prefix scans on dense text. Comments, documentation, names, inactive config, and binary bytes are not distinguished. Generic words such as `crypto`, `docker`, and `nginx` are unjustified algorithm assertions on ordinary supplied documents. Self-generated descriptors bypass this map, which fixes that particular source of fabricated evidence but not the general token behavior.

Metadata observations use `language="python"`/`detector_type="python_lexical"` to fit `SourceObservation`, while attributes say metadata/static_metadata. Evidence kind selection for generic tokens uses the **outer archive's suffix**, not the inner candidate's type. Normalization must reconcile these inconsistent labels.

### C. Binaries and executables

`parse_binary`, [src/qrypton/scanners/binary/formats.py:41](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/binary/formats.py:41>), identifies ELF magic, MZ/PE, or 32/64-bit thin Mach-O. Parsers are custom Python `struct` and random-access reads; **no pefile, pyelftools, LIEF, disassembler, or executable invocation** is used.

- `_parse_elf`, line 60: 32/64-bit, little/big endian; section table cap 4,096; SHT_SYMTAB/SHT_DYNSYM string-table names; `shndx==0` identifies imports; SHT_DYNAMIC/DT_NEEDED libraries. It depends on section headers; this is not a general program-header/dynamic-loader reconstruction for sectionless images.
- `_parse_pe`, line 134: DOS offset and PE header, sections/RVA mapping, PE32/PE32+ thunk width, import descriptors (cap 4,096), import thunks (65,536 per descriptor), export names (cap 1,000,000). No delay-import or COFF/debug-symbol analysis is implemented.
- `_parse_macho`, line 222: load commands (cap 4,096), selected library commands, segment sections, LC_SYMTAB/nlist imports/exports (cap 1,000,000). Fat/universal binaries and full chained-fixup/export-trie analysis are absent.

`_read_at` range-checks reads; `_cstr` truncates to 1,024 bytes. Some malformed internal sizes still reach `struct.unpack` without sufficient entry-size checks. `struct.error` is not caught by the binary scanner's `(OSError, ValueError)` structured-parse fallback, so those cases become scanner failures via the orchestrator rather than strings fallback.

`LocalBinaryScanner._is_crypto_symbol`, [src/qrypton/scanners/binary/scanner.py:263](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/binary/scanner.py:263>), does case-insensitive substring checks using `_CRYPTO_TOKENS`: aes, argon, bcrypt, blowfish, camellia, cert, chacha, crypt, 3des, des_, _des, dh_, _dh, diffie, dsa, ec_, ecdsa, ecdh, ed25519, evp_, hkdf, hmac, md5, ncrypt, pbkdf, pkcs, pfx, rc2, rc4, rsa, sha, scrypt, tls, x25519, x509. A hardcoded exclusion list attempts to suppress generic substrings such as description/descriptor/shared/shape. Crypto-like library names have separate substring rules.

Symbol observations have .90 confidence; library imports .95. `shannon_entropy`, [src/qrypton/scanners/binary/entropy.py:10](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/binary/entropy.py:10>), counts bytes in 64 KiB chunks and computes `-Σ p·log2(p)`. Sections of at least 32 bytes with entropy ≥7.5 bits/byte emit a .55 observation. Entropy proves neither encryption nor a primitive.

Only when **zero** observations have been emitted does the fallback decode the entire binary as UTF-8 with replacement and search for up to 20 token substrings, confidence .65. This is not printable-string extraction, UTF-16 strings analysis, or offset-aware matching. One unrelated high-entropy finding can suppress useful string detection. Fallback observations misleadingly use `detector_type="entropy"`; parse failure defaults format to ELF even for an unrecognized/PE input. Time checks surround sections, not full parsing/symbol enumeration/digest/string passes.

### D. Package manifests

`LibraryDependencyScanner`, [src/qrypton/scanners/extended.py:372](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:372>), changes only name/version/accepted kind. It has **no requirements.txt parser, package.json dependency graph, Cargo.toml parser, lockfile resolver, PEP 440/SemVer processing, registry lookup, vulnerability advisory lookup, or transitive dependency resolution**.

Plain manifests are copied to the temporary directory and searched by shared regex; wheels/JARs/ZIPs/TARs can be unpacked. The scanner can identify the word `cryptography`, but it does not resolve `==41.0.0` into `LibraryMetadata.version`. The source normalizer sets ecosystem to `source`, version/package URL/maintenance state unknown at [src/qrypton/scanners/source/normalization.py:246](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/normalization.py:246>). `tomllib` elsewhere in the repository parses QRYPTON CLI configuration, not Cargo manifests.

### E. Container layers

`ContainerImageScanner`, [src/qrypton/scanners/extended.py:385](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:385>), inherits the same extractor/walker. An uploaded docker-save tar can expose an inner `layer.tar` via archive detection. A reference such as `nginx:latest` becomes a small JSON file through `_materialize_container_descriptor`, [src/qrypton/api/app.py:505](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:505>); no registry pull or container execution occurs.

There is no OCI index/manifest graph interpretation, content-digest verification, layer order application, whiteout handling, opaque-directory semantics, merged-root filesystem, architecture selection, actual layer-count enforcement, or package-manager inventory. Deleted files from lower layers can still be reported; digest/layer attribution is not reconstructed. Files containing certificate text receive token scanning, **not X.509 parsing**. Crypto binaries inside layers do not invoke `LocalBinaryScanner`; they are decoded and searched like other bytes.

`_descriptor_observation`, [src/qrypton/scanners/extended.py:299](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:299>), emits a library-like `container-image:<reference>` record with .70 confidence and rule `static.container-reference`. It proves only that an identifier was supplied, not image existence or inspected contents.

### F. Cloud KMS

`CloudKmsScanner`, [src/qrypton/scanners/extended.py:399](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/extended.py:399>), has no provider SDK, authentication, DescribeKey/GetCryptoKey requests, IAM policy evaluation, effective-permission calculation, key rotation evaluation, exportability check, key usage compatibility logic, or algorithm/key-size extraction from provider schemas.

The API regex-validates AWS ARN/key/alias, Azure Key Vault URL, and GCP resource-shaped identifiers at [src/qrypton/api/app.py:306](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:306>). `_materialize_kms_descriptor`, line 478, writes `{"kms_key_id": ..., "note": ...}`. `_parse_descriptor_document`, extended line 84, performs `json.loads` only for documents ≤64 KiB carrying `kms_key_id` or `container_image_reference`. A KMS record emits a library-like `aws-kms-key`, `azure-kms-key`, or `gcp-kms-key` at .90 confidence.

Arbitrary JSON/YAML exports without those descriptor keys receive plain regex token matching. **There is no YAML parser and no structured AWS/GCP metadata extractor.** Even strings like `RSA_2048` lose their numeric parameter in this pipeline. Identifier descriptors cannot establish that a key exists or that encryption/signing is enabled.

All evidence from qrypton-kms is labeled static_identifier/inferred by `SourceNormalizer._collection_semantics`, line 56, and [src/qrypton/contracts/evidence_quality.py:45](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/contracts/evidence_quality.py:45>), including supplied exports. This preserves a no-live-cloud-access warning, but also conflates inspection of an actual supplied metadata document with identifier-only inference.

### Shared normalization defects affecting all surfaces

`SourceNormalizer._finding`, [src/qrypton/scanners/source/normalization.py:171](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/scanners/source/normalization.py:171>), is also used by `BinaryNormalizer`. Important losses:

1. `algorithm_for_name("sha256")` returns canonical `sha-256`, but `algorithm_for_name("sha-256")` returns `None`: normalization converts it to `sha_256`, while the catalog expects `sha256`. SHA-224/384/512 have the analogous spelling gap. The scanner's canonical output is then classified only partially identified, with no observed algorithm. This was verified for SHA-256.
2. Literal `key_size_bits` captured by the Python visitor is discarded: line 203 constructs `key_size_bits=_unknown()`. Positional `RSA.generate(2048)` is not captured by the visitor in the first place.
3. For `subject_kind="mode"`, line 196 forces `rule=None`; the branch that would attach `parameters={"mode": ...}` cannot be reached for mode observations. There is no later join of mode/key-size observations to an algorithm call. The correlator retains a selected exemplar rather than fusing those attributes.
4. Generic `tls` tokens emitted as algorithms have no direct algorithm rule, while source TLS observations correctly use protocol category. Likewise, DES/3DES tokens are not present in the source rule catalog and can remain unidentified despite the risk taxonomy supporting them.
5. `CryptoRoleClassifier` cannot recover operation details never extracted: bare RSA remains ambiguous. Broad Windows API matching can label library/API-family presence as an asymmetric algorithm without a known primitive.

These defects explain why downstream logic can have good rules yet produce unknown strengths, missed ECB risk, or manual-review recommendations for seemingly obvious input.

## 3. Mosca, risk tiers, and HNDL

### Active calculator and input provenance

`build_services` wires **`MoscaRiskEngine`**, not `evaluate_qrypton_risk`. Active math is `MoscaRiskCalculator.evaluate`, [src/qrypton/risk/mosca.py:73](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/risk/mosca.py:73>):

```text
required = X + Y
margin = Z - required
immediate_vulnerability = required > Z
exposure_score = clamp(100 * required / Z, 0, 100), rounded to 4 decimals
if Z == 0: score = 100 when required > 0, otherwise 0

urgency = critical if required > Z
          high     if required == Z
          medium   if exposure_score >= 50
          low      otherwise
```

Equality is not immediate vulnerability. `X=Y=Z=0` produces score 0 but urgency high because equality is evaluated independently.

`MoscaParameters`, line 30, requires finite years between 0 and 10,000. X and Y are resolved separately by `_timeline_for`, line 228: finding override → supplied asset business context → run scenario. Sources are persisted as finding/asset/scenario labels. Z is run-scenario scoped. The API takes the three top-level request values; nested `business_context.data_lifetime`/`migration_time` become asset overrides at API lines 1246–1255. They can disagree with top-level scenario values and take precedence for findings. The UI defaults are **7/4/8**; `QryptonConfig` defaults are **5/2/10**. No AI, statistical forecast, measured migration estimator, or automatic shelf-life classifier assigns these durations.

`MoscaRiskCalculator.evaluate_target`, line 107, selects the worst exposure, then lowest margin; the normal API persists per-finding evaluations rather than invoking that target aggregation. `/api/v1/mosca/eval` at API line 1918 returns stored DTOs despite its “Calculates” docstring.

Additional boundary defect: X and Y can each be 10,000, but `MoscaEvaluation.required_security_years` is capped at 10,000 and margin at ±10,000. Individually valid large inputs can fail evaluation. Per-finding catches normally turn that into a partial result, unlike ORCH-01.

### Algorithm applicability and independent risk dimensions

`classify_finding`, [src/qrypton/risk/taxonomy.py:150](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/risk/taxonomy.py:150>), classifies an observed canonical algorithm:

- PQC family/status/name markers: quantum low, Mosca no.
- Classical public-key families or names: quantum high, Mosca yes.
- Symmetric/hash/MAC/KDF: quantum medium, Mosca no.
- Absent/unrecognized classification: unknown; no invented urgency.

The applicability check includes signatures, so it models public-key migration timing more broadly than confidentiality/HNDL alone.

Classical risk precedence in `_crypto_risk`, taxonomy line 85:

| Condition | Crypto risk |
|---|---|
| MD2/MD4/MD5/DES/RC2/RC4/SHA0/3DES name marker | Critical |
| ECB or deprecated/disallowed lifecycle | High |
| Recognized PQC primitive | Low |
| SHA-1 | High |
| SHA-224 | Medium |
| RSA <1024 / <2048 / <3072 / ≥3072 | Critical / High / Medium / Low |
| AES <128 / =128 / =192 or 256 | Critical / Medium / Low |
| ECC size <256 / =256 / =384 or 521 | High / Medium / Low |
| Named SHA-256/384/512 or listed SHA-3 | Low |
| Ed25519/X25519 | Medium |
| Missing required size or unmatched algorithm | Unknown |

These are repository policy tiers, not independently verified standards compliance. Earlier lifecycle checks can override later size/name cases. In particular the scanner catalogs RSA as `legacy` (not automatically deprecated), while key-size loss prevents its classical strength band from being determined.

Numeric dimension values are explicit tables: crypto informational/low/medium/high/critical = **0/10/40/75/95**; quantum informational/low/medium/high/critical = **0/0/20/100/100**. Unknown remains absent, not zero evidence. Exploitability is always unknown in the active assessment.

### Final priority is categorical, not a weighted composite

`_business_impact`, [src/qrypton/risk/mosca.py:162](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/risk/mosca.py:162>), takes the highest evidenced category: observed criticality; public/internal/confidential/restricted → low/medium/high/critical; true internet exposure → high; regulatory scope → high only when business evidence IDs exist. No observed context means unknown. Migration complexity is not a numeric input here.

`_priority_and_score`, line 124:

```text
ranks: informational=0, low=1, medium=2, high=3, critical=4
priority = max(known crypto rank, known quantum rank, min(business rank, 2))
if business >= high and priority >= high: priority = min(priority + 1, critical)
ordinal score = 25 * priority
all inputs unknown => unknown score state
```

There is no weighted sum of the 0–100 risk factors. Confidence and Mosca urgency are explicitly excluded from final priority. A recognized SHA-256 hash has crypto low, quantum medium, and thus at least medium final priority under this policy; that does not imply the hash needs an asymmetric replacement. A classical public-key finding can be high priority even when its Mosca scenario is low urgency.

The separate exported compatibility API `evaluate_qrypton_risk`, [src/qrypton/risk/engine.py:42](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/risk/engine.py:42>), uses `(X+Y)/Z`, positive overlap, ±uncertainty overlap, and an average of five 1–5 business scores. It treats X=None as permanent and uses a **0.75** medium threshold, unlike the active calculator's **0.50**. It intentionally returns final risk `unknown` without canonical algorithm evidence. It is covered by tests but is not wired into `build_services`; mixing its documentation with production results gives conflicting expectations.

### HNDL implementation

There is **no separate backend HNDL score, rating model, or evidence-based ciphertext-collection analysis**. HNDL appears in PDF explanatory prose and the frontend timeline. [web/src/components/mosca-timeline.tsx:24](<C:/Users/SIDDHARTH PATEL/QRYPTON/web/src/components/mosca-timeline.tsx:24>) computes `isExposed=(X+Y)>Z`, uses defaults 7/4/8, and hardcodes base year 2026. The label is scenario arithmetic, not detection of recorded traffic. This component exists independently; its presence does not establish that every current dashboard path renders it.

## 4. PQC remediation and ontology mapping

### Active recommendation path

`CryptoRoleClassifier.classify`, [src/qrypton/recommendations/engine.py:71](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/recommendations/engine.py:71>), first honors policy role overrides, then certificate/protocol/library categories, then observed algorithm/family and explicit crypto role. Library-only and unidentified findings produce manual review. Bare RSA/EC with insufficient operation context is ambiguous.

`PqcRecommendationEngine.plan`, line 180, calls `_targets`, line 264:

| Observed role | Target/action |
|---|---|
| KEM/key establishment, with FIPS-203 enabled | Generic `ml-kem`; optional policy hybrid mode |
| Signature, default policy | Generic `ml-dsa`, FIPS-204 |
| Signature, explicit SLH policy and FIPS-205 | `slh-dsa` |
| Policy-ranked signatures | ML-DSA with optional SLH-DSA alternative |
| Hash | No target algorithm; validate or retire weak hash for an appropriate SHA-2/SHA-3 profile |
| Symmetric cipher | No target algorithm; validate mode/nonce/size, or replace weak construction with approved AEAD |
| MAC/KDF/RNG | Role-specific validation; no KEM/signature substitution |
| Protocol/certificate | Protocol/PKI compatibility review, no guessed per-finding replacement |
| Unknown/ambiguous | Manual review; empty targets |
| Already ML-KEM/ML-DSA/SLH-DSA | Validate deployment; suppress replacement targets |

The active engine does not choose ML-KEM-768 or a concrete AES-GCM parameter profile automatically. `minimum_security_strength_bits` exists in the policy but does not drive target selection. Capability flags, operational constraints, peer/protocol/HSM support, and certificate ecosystem support become blockers. Confidence subtracts .1 per unknown peer/protocol/HSM field and .2 for blockers; it is recommendation confidence, not risk score.

Recommendations have integer priority critical/high/medium/low/informational/unknown = **100/85/65/40/20/20**. Most known roles also get a crypto-agility action at five points lower; unknown/manual review uses priority 1. An explicit role override or a contradictory `crypto_role` can force a wrong family: overrides are not validated for family compatibility. That is a latent input-contract issue, separate from the demonstrated PDF fallback.

The older `PqcMapper`, [src/qrypton/risk/pqc_mapping.py:58](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/risk/pqc_mapping.py:58>), is exported/tested but not wired into the API composition. It maps RSA-KEM/DH/ECDH → ML-KEM; RSA-PSS/ECDSA/Ed25519 → ML-DSA; 3DES → AES-256; SHA-1 → SHA3-256; everything else → None. Its priority scale differs from the active engine. It is not the source of the current SHA-256 fallback.

### PDF-01: exact false recommendation path

1. A canonical SHA-256 finding classifies as hash.
2. `_targets` returns `target_algorithms=()`.
3. `_heuristic_action`, [src/qrypton/recommendations/engine.py:457](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/recommendations/engine.py:457>), explicitly avoids KEM/signature substitution.
4. `SqliteDashboardDataProvider.get_run_view`, [src/qrypton/ui/sqlite_provider.py:302](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/ui/sqlite_provider.py:302>), correctly copies the empty plan targets into `RoadmapRow`.
5. `executive_pdf`, [src/qrypton/api/reporting.py:631](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/reporting.py:631>), renders each roadmap row with:

```python
targets = ", ".join(str(t) for t in (getattr(row, "target_algorithms", ()) or ())) \
          or "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
```

Thus the PDF can literally say not to replace a hash with ML-KEM/ML-DSA in its action and append those exact algorithms as the target. Unknown libraries, AES/MAC/KDF validation, and already-PQC checks are affected too. The report's finding-table helper `_pqc_target`, line 110, already preserves empty targets by returning the action or a review message; the roadmap tail is inconsistent with it.

`PQC_TARGETS`, reporting line 61, contains older name-hint mappings, including SHA-1 plus ML-DSA, but repository reference search finds no consumer of that constant. Do not attribute the active bug to this unused table. The active generic briefing at lines 458–461 also says FIPS PQC standards are the target state for every finding, which is overbroad for hashes and symmetric primitives.

## 5. PDF/report generation and exact data contracts

### Entry points and data assembly

`POST /api/v1/reports/pdf` and `GET /api/v1/scans/{scan_id}/report/pdf` call `_build_pdf_report`, [src/qrypton/api/app.py:1837](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1837>). `PdfReportRequest`, line 1831, contains optional `run_id`, alias `scan_id`, and `tenant_id`; it is the HTTP selector, not the rendering model.

The builder resolves a `DashboardRunView`, separately reopens `SqliteRunStore` to retrieve a `RunResult`, then calls `provider.get_finding_detail` for **every inventory row**. It passes:

| `executive_pdf` argument | Actual runtime model |
|---|---|
| `scan_id` | `str` |
| `run` | `qrypton.application.schemas.RunResult` |
| `posture` | `qrypton.ui.contracts.ExecutivePosture` |
| `inventory` | `list[qrypton.ui.contracts.InventoryRow]` |
| `mosca` | `list[qrypton.ui.contracts.MoscaPoint]` |
| `roadmap` | `list[qrypton.ui.contracts.RoadmapRow]` |
| `finding_details` | `dict[str, qrypton.ui.contracts.FindingDetail]` keyed by finding ID |

The renderer annotates these as `Any`/`list[Any]` at [src/qrypton/api/reporting.py:344](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/reporting.py:344>), so this real contract is not enforced by its signature.

Exact DTO fields, defined in [src/qrypton/ui/contracts.py:53](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/ui/contracts.py:53>) onward:

- `ExecutivePosture`: total_findings, unique_asset_ids, critical/high/medium/low/informational/unknown/unassessed_findings_count, run_status, scanner_failed_count, scanner_partial_count, policy_passed, policy_violations.
- `InventoryRow`: finding_id, category, algorithm_name, algorithm_family, algorithm_variant, crypto_role, library_name, identity_status, identity_label, identification_confidence, usage_confidence, confidence_reasons, key_size_bits, lifecycle_status, risk_level, risk_assessment_state, business_criticality, risk_score, confidence, evidence_count, first_observed_at, last_observed_at.
- `MoscaPoint`: finding_id, urgency, mosca_applicable, exposure_score, x_data_lifetime_years, y_migration_years, z_crqc_horizon_years, required_security_years, time_margin_years, timeline_state.
- `RoadmapRow`: finding_id, priority, action, role, target_algorithms, hybrid_mode, blocking_conditions, standards_references.
- `FindingDetail`: finding (`CryptoFinding`), optional assessment (`RiskAssessment`), business_criticality, optional mosca (`MoscaPoint`), recommendations (`tuple[Recommendation,...]`), evidence_provenance (`tuple[Evidence,...]`), failures (`tuple[SafeRunFailure,...]`), optional evidence_authenticity (`EvidenceAuthenticity`: quality, summary, confidence_applicable).

`RunResult`, [src/qrypton/application/schemas.py:99](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/application/schemas.py:99>), carries run_id, tenant_id, status, started_at, completed_at; optional Asset/ScanTarget/BusinessContext; per-finding business contexts; scanner_results; failures; Evidence/CryptoFinding/RiskAssessment/Recommendation tuples; PqcRecommendationPlan tuples; PersistedMoscaEvaluation tuples; CBOM bytes/digest; and PolicyOutcome. `SqliteRunStore._sanitized`, line 62, strips excerpts/raw-content digests and most evidence attributes before storage. PDF details therefore use persisted locations/provenance, not original source excerpts.

### Visual mapping

`executive_pdf` uses ReportLab Platypus `SimpleDocTemplate`, A4 pages, Helvetica, `Paragraph`, `Table`, `KeepTogether`, `HRFlowable`, spacers, and ReportLab vector charts. It returns `BytesIO` PDF bytes; it is synchronous and runs on demand, not during scan finalization.

| Output element | Input/calculation | Code |
|---|---|---|
| Summary card | Asset reference/kind, scan ID, UTC rendering time, persisted status/policy, severity counts | reporting lines 360–429 |
| Severity pie | `_severity_counts`; seven buckets including unknown/unassessed | lines 187–214 |
| Algorithm bars | `_family_bucket` maps canonical algorithm family, not text guessing | lines 98–107, 216–236 |
| Percentage bars | Per-severity counts divided by total findings | lines 238–258 |
| Findings table | Sort severity then finding ID; identity_label, Mosca urgency, `_pqc_target` | lines 514–554 |
| Details | Identity/family/role/library, key size, confidence, protocol fields, up to two evidence locations, stored timeline/factors and action | lines 557–625 |
| Roadmap | First 40 rows, priority/action/targets | lines 628–647 |
| Footer | `_NumberedCanvas`, then byte-level page-number replacement | lines 261–319, 649–663 |

### Report-specific correctness/performance defects

- **Priority inversion/truncation:** provider sorts roadmap by ascending priority at [src/qrypton/ui/sqlite_provider.py:336](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/ui/sqlite_provider.py:336>), although higher numbers mean more urgent. The PDF takes only the first 40 rows. Low-priority/manual-review actions can displace critical migration items, with no omitted-row count.
- **One action selected per finding:** reporting line 358 builds a dictionary by finding ID, overwriting earlier recommendation rows. Because input is sorted ascending, the highest-numbered action usually wins; this loses multiple-action context in the findings table/details while the roadmap lists individual rows.
- **N full-run reloads:** `get_finding_detail`, [src/qrypton/ui/sqlite_provider.py:358](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/ui/sqlite_provider.py:358>), calls `get_run` for each finding, deserializing the full run and CBOM then scanning its collections. `_build_pdf_report` repeats this N times. This can approach quadratic work in findings/evidence and overwhelm report latency on large runs. It is a report/download delay, not itself scan-worker finalization.
- **Malformed PDF risk:** `_finalize_page_numbers`, reporting line 313, regex-replaces bytes after ReportLab has serialized the PDF. Adding ` of N` changes stream lengths and object/xref offsets without rewriting them. Tolerant readers may repair it; a raw `%PDF`/substring test does not establish valid structural offsets.
- **Layout width:** A4 minus two 48-point margins leaves about 499 points; the chart row is 540 and the findings table 492. Chart overflow is a code-established layout risk; visual rendering was not part of this source audit.
- **Findings language:** “Target Surface” displays a shortened asset reference for every row, not the individual evidence surface. Full source locations are limited to two entries per finding. The renderer receives authenticity/partial-failure information but does not comprehensively display those limitations.
- **Generic conclusions:** nonzero findings force “elevated” attention and generic PQC program language even for low/unknown/non-asymmetric records. This is presentation logic, not calculated risk.
- `_build_pdf_report` catches only selected errors while obtaining details. Validation/SQLite failures elsewhere propagate as request errors. There is no separate bounded report job.

## Additional deployment and contract observations

These findings are adjacent to the requested code paths and should be considered before exposing this API beyond its trusted local environment:

- No authentication/authorization dependency is applied to the API routes. A supplied tenant query is a filter, not authenticated tenant ownership; listing without a tenant can include all tenants. The dashboard provider's scoping tests do not establish an HTTP authentication boundary. See [src/qrypton/api/app.py:108](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:108>) and [src/qrypton/api/app.py:1656](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1656>).
- Arbitrary server-local paths are accepted. The worker derives `workspace_root` from the requested locator itself at [src/qrypton/api/app.py:1472](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/api/app.py:1472>), so scanner `allowed_root` checks do not impose an independently configured server filesystem boundary. Inputs that are already resolved also lose original symlink identity in several paths.
- Provisional rows do not retain target, request, creation time, or recovery data. Metadata-only history cannot reconstruct what was scanned or resume it.
- `pyproject.toml` declares Pydantic, pathspec, jsonschema, and ReportLab but not FastAPI, an ASGI server, python-multipart, or the test HTTP client dependencies. The populated local virtual environment can conceal a clean-install API failure. CI's `pip install .` exercises the CLI path rather than demonstrating that the HTTP service can start.
- The command-line scan enters the same orchestrator via `asyncio.run` at [src/qrypton/cli.py:211](<C:/Users/SIDDHARTH PATEL/QRYPTON/src/qrypton/cli.py:211>) without the API wrapper. Scanner-local limits still apply, but the API's attempted outer timeout and failure persistence are absent.

## Repair order and acceptance criteria

These are concrete proposed changes, **not changes applied by this audit**.

1. **Contain the entire worker.** Validate finite bounded X/Y/Z before enqueueing. Wrap acquisition, configuration, orchestration, error persistence, and cleanup in one outer lifecycle guard. Use a valid failure stage and bounded sanitized message. Retain futures and observe completion/errors; make submit failure terminal.
2. **Persist ownership and progress.** Store queued_at, started_at, heartbeat, deadline, worker/lease token, and a recoverable request descriptor. Distinguish queued from orphaned with durable ownership; never infer worker death solely from a process-local dictionary. Use compare-and-set transitions so terminal status cannot regress or disagree with result_json.
3. **Enforce execution limits outside scanner control.** Use a supervised worker process for untrusted CPU/parsing/decompression and enforce memory/time/file/member budgets. Apply one end-to-end deadline including acquisition. Correct the UI-name versus target-kind timeout mismatch. Cooperative checks remain useful but cannot substitute for independent termination.
4. **Make polling failures explicit.** Preserve the scan ID; distinguish running, temporarily unavailable, unknown ID, and terminal failure. Add cancellation/error-budget handling and a user-visible retry/status-recovery path. A client timeout must not itself falsely mark the job failed.
5. **Own DB resources.** Initialize schema once, use one configured database path, close stores with explicit lifecycle management, rollback failed transactions, write final artifacts once, query one run directly, and select a journaling/concurrency strategy appropriate to deployment. A WAL setting alone does not solve the lifecycle defects.
6. **Repair normalization before expanding scoring.** Make algorithm aliases round-trip; preserve key size and parameters; link modes to evidenced algorithm usage; constrain name-based recognition; distinguish metadata/library presence from actual crypto operations.
7. **Make capability labels truthful.** Either implement structured manifests/OCI/KMS/certificate analysis or expose each adapter as bounded lexical/identifier inspection. Propagate skipped files, recursion/byte limits, and archive errors as partial outcomes.
8. **Remove PDF-invented targets.** Render the canonical plan's empty target as review/validation, not ML-KEM/ML-DSA. Sort urgency correctly, paginate all actions or disclose truncation, load run details once, and use a proper two-pass ReportLab page-count mechanism.

Required regression scenarios: invalid/oversized/nonfinite timelines; acquisition exception; more jobs than executor slots; polling before thread startup; second-process polling; process restart; concurrent completion/poll; DB lock and failure-persistence failure; source/binary/archive CPU stalls; expanded bytes/member/depth limits; canonical hash round-trips; size/mode retention; SHA/AES/MAC/KDF/library/already-PQC PDF rows; large reports; strict PDF parse and visual QA. After repairs, invert the diagnostic assertions into expected-correctness tests rather than retaining “bug observed” assertions in the product suite.

The current evidence supports several independent causes of the reported loading behavior. It does not justify treating every historical pending row as the same incident or claiming that scanner-specific hangs were all reproduced.
