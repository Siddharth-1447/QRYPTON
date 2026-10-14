# QRYPTON / ECDAT adversarial acceptance audit

Date: 2026-10-12, Asia/Calcutta. Scope: current working tree, including pre-existing uncommitted changes. No fixes applied.

## 1. Verdict

**NO — not ready for a serious SIH technical review.** The largest blocker is that the declared clean installation cannot import the API or collect its acceptance tests. The packaged CLI does scan, persist and export successfully, and the existing environment completes the data chain, but unauthenticated scan mutation, invented metadata algorithms, broken PE exports and container-limit/whiteout errors invalidate enterprise acceptance. Passing suites do not cover those adversarial failures.

The named **Master Execution Roadmap** and **UX Specification** were not found or supplied. Their exact Final Engineering Gate cannot be scored honestly. The following is an audit-derived stage gate against the user-provided chain, not a quotation of a missing roadmap.

| Stage | Result | Evidence / limit |
|---|---|---|
| Fresh manifest install | PASS | install-manifest.json; wheel built and installed |
| Fresh CLI first scan | PASS | clean-cli.json; 4 findings, completed, exit 0 |
| Fresh backend/dashboard prerequisites | FAIL | fastapi undeclared; fresh-import.json |
| Existing test suite stability | FAIL | 534/1/2 then 535/0/2 twice; cold-start failure |
| Lint / Python type gate | FAIL | 170 scoped lint issues; 13 mypy errors |
| Source discovery | FAIL acceptance | Ordinary fixture paths work; DES3 and dynamic misses |
| Binary discovery | FAIL acceptance | Real PE export parsing corrupts symbols |
| Dependencies | FAIL acceptance | Missing structured versions/transitives/Maven; invented primitives |
| Container/OCI | FAIL acceptance | Limits, type validation and whiteouts |
| Normalization / correlation | FAIL acceptance | Composite RSA alias misclassified; cross-surface asset merge unproven |
| Mosca + contextual priority | FAIL acceptance | Extreme accepted inputs crash; required context-tier distinctions incomplete |
| PQC recommendations | PASS tested role cases | ML-KEM/ML-DSA roles and non-public-key exclusion; broader coverage in suite |
| CycloneDX CBOM | PASS tested samples | Official 1.6 schema: populated twice, empty, 200 components |
| Dashboard data API | PASS tested synthetic chain | Persisted inventory/risk/roadmap/heatmap return 200 |
| Full visual demo / all controls | NOT COMPLETE | Browser scope and untouched controls listed below |
| CI gate | FAIL acceptance | Correct baseline deltas; invalid baseline/unknown plugin handling fail |
| Authorization / deployment acceptance | FAIL | Anonymous create/delete reproduced on audit data |
| Docker build | BLOCKED | Docker daemon unavailable; product Dockerfile not found |

### Evidence and reproducibility rules

VERIFIED = reproduced in this run. INFERRED = code inspection only or a root-cause hypothesis. UNTESTED = no executed proof. Every command runner log contains argv, cwd, timeout, elapsed time, exit code and captured output. Run from the repository root with `python qa_audit/repro/run.py <label> --timeout <seconds> -- <command>`; concrete command lines are retained in evidence JSON. Repeat scripts use isolated synthetic paths; choose fresh audit DB filenames for CLI reruns because QA-17 is intentional snapshot immutability exposed poorly.

All product source/test/docs/config hashes captured before execution are unchanged (summary-data.json). Python bytecode, pytest/Hypothesis/type caches, uploads, databases, fixtures and the copied Next build live under qa_audit. Initial pip retries used the default host cache before PIP_CACHE_DIR was centralized; this is an audit-containment limitation, not a product defect. Initial reconnaissance did not yet use subprocess deadlines. Windows sandbox asyncio hangs even for sleep(0); normal-permission smoke succeeds, and actual asynchronous tests were rerun with normal local permissions. No scanned artifact was executed; target source canary remained absent. Initial UI retries had audit-server contention and screenshot-injected caret styles; those errors are excluded from product findings.

## 2. Scorecard

Counts below are discrete audit acceptance checks in acceptance-checks.json, not a sum of repeated pytest runs. BLOCKED checks were not executed; confidence is limited to the enumerated fixtures. A successful command is not automatically a passed product acceptance check.

| Area | Tests run | Passed | Failed | Blocked | Confidence |
|---|---:|---:|---:|---:|---|
| T0 | 9 | 4 | 5 | 3 | Medium; partial scope |
| T1 | 23 | 21 | 2 | 1 | High for tested fixtures; limited generalization |
| T2 | 4 | 3 | 1 | 1 | Medium; partial scope |
| T3 | 6 | 1 | 5 | 1 | Medium; partial scope |
| T4 | 12 | 5 | 7 | 1 | High for tested fixtures; limited generalization |
| T5 | 6 | 4 | 2 | 1 | Medium; partial scope |
| T6 | 17 | 14 | 3 | 0 | Medium; partial scope |
| T7 | 7 | 7 | 0 | 0 | Medium; partial scope |
| T8 | 7 | 7 | 0 | 0 | High for tested fixtures; limited generalization |
| T9 | 12 | 12 | 0 | 1 | Medium; partial scope |
| T10 | 17 | 17 | 0 | 1 | Medium; partial scope |
| T11 | 8 | 6 | 2 | 1 | Medium; partial scope |
| T12 | 4 | 1 | 3 | 1 | Medium; partial scope |
| T13 | 4 | 3 | 1 | 1 | High for tested fixtures; limited generalization |
| T14 | 2 | 2 | 0 | 1 | Medium; partial scope |
| T15 | 3 | 1 | 2 | 1 | Medium; partial scope |

### Existing suite results (reported separately)

| Environment/run | Passed | Failed | Skipped | Collection errors |
|---|---:|---:|---:|---:|
| Fresh manifest environment | 0 | 0 | 1 module | 16 |
| Existing environment 1 | 534 | 1 | 2 | 0 |
| Existing environment 2 | 535 | 0 | 2 | 0 |
| Existing environment 3 | 535 | 0 | 2 | 0 |
| Coverage run, existing environment | 535 | 0 | 2 | 0 |

Web focused tests: **25 passed / 0 failed**. Web TypeScript and scoped ESLint succeed. Root Ruff: 3853 reported issues, including prior tmp fixtures; scoped src/tests: 170. Python mypy: 13 errors in four sample modules. Fresh API failure is not hidden by adding undeclared product dependencies.

## 3. Working well

- **VERIFIED, T0-clean-cli/T9:** Installed CLI scans synthetic Python, records four findings in SQLite and emits CBOM; clean-cli.json.
- **VERIFIED, T1-rsa_alias/rsa_multiline/from_hash/wrapper:** Aliases, multiline calls and wrapper-contained calls resolve in the controlled fixtures; probes.json.
- **VERIFIED, T1-traps/T1-canary:** Comment/string/docstring traps produce no algorithms and the execution marker is absent; accuracy.json and canary.json.
- **VERIFIED, T1-nonutf8-confidence/T1-bom:** Non-UTF8 evidence confidence is bounded at .35; BOM/CRLF hashes are detected; probes.json.
- **VERIFIED, T4-traversal/absolute/bounded-gzip-bomb:** Traversal, absolute tar paths and a 346-byte/256KiB bounded expansion fixture are rejected; probes.json and extra-observations.json.
- **VERIFIED, T5-unknown-widget:** Unknown algorithm stays unknown; deep-observations.json.
- **VERIFIED, T6-hand-0..4:** Five independently specified categorical-priority expectations match outputs; deep-observations.json.
- **VERIFIED, T7:** ECDH targets ML-KEM and ECDSA targets ML-DSA; AES/hash/MAC and ambiguous RSA do not receive universal PQC replacements; already-ML-KEM is not Mosca-applicable. Evidence: deep-observations.json and existing recommendation/risk tests.
- **VERIFIED, T8:** Fixed-context populated CBOM bytes are identical across separate DBs; populated, empty and 200-component exports pass the downloaded official schema; cbom-validation.json, deep-observations.json, extra-observations.json.
- **VERIFIED, T9/T10-KPI:** Synthetic scan serves dashboard/inventory/heatmap/risk/roadmap. Four findings, one asset, one Critical, one High and two Unknown independently reconcile to persisted IDs/assessments; all 14 KPI/partition checks pass (kpi-check.json).
- **VERIFIED, T11:** New, removed, worsened, unchanged baseline debt and drift deltas match the controlled cases; ci-deltas.json. New MD5 Critical scan exits policy=3 and preserves artifacts.
- **VERIFIED, T12-secret-canaries:** No canary API-key/private-key bytes found in inspected generated logs/JSON/SQLite/CBOM/API response evidence; secrecy.json. This is bounded output inspection, not proof for every input.
- **VERIFIED, existing role tests:** Action-specific Engineer/CI Publisher enforcement and immutable finalized snapshot protections pass the existing suite; these do not cover QA-02 scan routes.

## 4. Defects

Severity follows the requested definitions. Critical resource-limit findings prove policy violation, not unlimited practical exhaustion. Recommendations below are directions only; no product edits were made. All root-cause paragraphs are INFERRED even when behavior is VERIFIED.

### QA-01 — Blocker — Declared install cannot launch the backend

**Area:** T0 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run fresh-import and fresh-suite commands saved in evidence.
**Expected:** Manifest + dev group supplies backend and test dependencies.
**Actual:** API import raises ModuleNotFoundError: fastapi; 16 collection errors. Installed packaged CLI does work.
**Evidence:** fresh-import.json, fresh-suite.json, install-manifest.json; source `pyproject.toml:13`.
**Root-cause hypothesis — INFERRED:** FastAPI, uvicorn, multipart and the test HTTP client are used outside declared dependencies.
**Fix direction:** Declare supported backend/runtime/test extras and make the documented install sufficient.

### QA-02 — Critical — Anonymous clients can create and delete scan records

**Area:** T12 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run pipeline.py via the recorded pipeline command; only disposable audit data is mutated.
**Expected:** 401/403 for anonymous scan creation/deletion; tenant bound to principal.
**Actual:** POST /api/v1/scans returns 200 and completes; DELETE audit run returns 204 without Authorization.
**Evidence:** api-probes.json, pipeline.json; source `src/qrypton/api/app.py:1611`.
**Root-cause hypothesis — INFERRED:** Scan and delete routes lack principal/role dependencies; user-supplied tenant selection is not identity authorization.
**Fix direction:** Enforce authenticated, tenant-bound authorization consistently across scan, upload, export and history routes.

### QA-03 — Critical — Metadata invents RSA, AES and SHA-256

**Area:** T3/T4 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run probes.py; inspect T3-benign.json and T3-package.json.
**Expected:** Library or unknown/capability evidence, without invented primitive use.
**Actual:** Benign nginx/docker/cipher/crypto fields yield RSA/SHA-256/AES at .75 confidence; npm crypto becomes AES.
**Evidence:** probes.json, probes-final.json; source `src/qrypton/scanners/extended.py:47`.
**Root-cause hypothesis — INFERRED:** Token aliases map product/package words directly to cryptographic algorithms.
**Fix direction:** Replace keyword guessing with structured manifest/config parsers and capability-only library evidence.

### QA-04 — Critical — DES3 calls become Windows CAPI

**Area:** T1 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run probes.py; T1-des3 uses Crypto.Cipher.DES3.new.
**Expected:** 3DES algorithm, CBC mode and relevant classical risk.
**Actual:** windows-capi observed; 3des absent.
**Evidence:** probes.json, accuracy.json; source `src/qrypton/scanners/source/rules.py:137`.
**Root-cause hypothesis — INFERRED:** Substring fallback matches crypt in crypto-qualified DES3 names; no DES3 catalog entry.
**Fix direction:** Use exact qualified API rules and add DES/3DES identities and parameters.

### QA-05 — Critical — RSA signature alias loses its public-key identity

**Area:** T5 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run deep.py normalization of RSAWithSHA256.
**Expected:** RSA signature with SHA-256 hash component, no loss of quantum-relevant identity.
**Actual:** Only sha-256/hash survives at .95 confidence. RSA-2048/rsa2048 normalize to rsa but discard encoded key size.
**Evidence:** deep-observations.json; source `src/qrypton/scanners/source/rules.py:137`.
**Root-cause hypothesis — INFERRED:** Hash-token-first substring matching collapses composite names. Downstream non-public-key risk is an INFERRED consequence.
**Fix direction:** Parse composite algorithm roles and preserve constituent primitives and encoded parameters.

### QA-06 — Critical — Archive resource limits are not enforced consistently

**Area:** T4 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run probes.py T4-many and extra_checks.py compressed-limit/member-size-limit/depth-limit.
**Expected:** Configured limits fail closed with an explicit error/partial state.
**Actual:** 20 members accepted with max_file_count=10; 106-byte archive accepted with compressed cap=1; oversized member and excessive nesting silently return zero findings, partial=false.
**Evidence:** probes.json, extra-observations.json; source `src/qrypton/scanners/extended.py:163`.
**Root-cause hypothesis — INFERRED:** Extraction checks aggregate expansion but omits compressed/member-count/layer checks and silently skips other bounds.
**Fix direction:** Enforce all limits before extraction/scan and persist explicit coverage failure at each limit.

### QA-08 — Critical — PE export parser interprets function addresses as symbol names

**Area:** T2 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run pe-export-proof; copied real Git OpenSSL libcrypto DLL is never executed.
**Expected:** Read named crypto exports from IMAGE_EXPORT_DIRECTORY AddressOfNames.
**Actual:** 5865 export entries are machine-code fragments; RSA_public_encrypt and AES_encrypt exist in DLL bytes but are not returned as named exports. Scanner emits gibberish strings as crypto evidence.
**Evidence:** pe-export-proof.json, deep-probes.json; source `src/qrypton/scanners/binary/formats.py:208`.
**Root-cause hypothesis — INFERRED:** The two values at offsets 24 and 28 are NumberOfNames and AddressOfFunctions; AddressOfNames is at 32.
**Fix direction:** Correct export-directory offsets and validate against independently parsed real PE exports.

### QA-09 — Critical — Docker whiteouts do not remove prior-layer findings

**Area:** T4 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run deep.py Docker-save fixture with crypto.conf=RSA then .wh.crypto.conf.
**Expected:** Final-filesystem scan excludes deleted crypto file; historical layer evidence distinguished.
**Actual:** RSA remains; an additional AES token is inferred from manifest/config wording; partial=false.
**Evidence:** deep-probes.json; source `src/qrypton/scanners/extended.py:160`.
**Root-cause hypothesis — INFERRED:** Generic recursive unpacking is used without Docker/OCI layer ordering or whiteout semantics.
**Fix direction:** Build the effective layered filesystem and attach verified layer provenance before scanning.

### QA-07 — Critical — Accepted timeline values crash result validation

**Area:** T6 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** N

**Reproduce:** Run probes.py; Mosca input X=10000,Y=10000,Z=0.
**Expected:** Every accepted parameter combination returns a valid bounded result or is rejected up front.
**Actual:** MoscaParameters accepts inputs; MoscaEvaluation rejects required=20000 and margin=-20000.
**Evidence:** mosca-probes.json; source `src/qrypton/risk/mosca.py:55`.
**Root-cause hypothesis — INFERRED:** Output bounds reuse single-input year bounds without bounding the sum.
**Fix direction:** Align input/output bounds and validate the full arithmetic domain.

### QA-10 — Major — Corrupt archives are silently treated as text

**Area:** T4 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run probes.py T4-corrupt.tar, bytes not tar RSA.
**Expected:** Malformed archive rejected/degraded with clear type error.
**Actual:** RSA finding at .75 confidence; partial=false and no warning.
**Evidence:** probes.json; source `src/qrypton/scanners/extended.py:212`.
**Root-cause hypothesis — INFERRED:** Failed archive recognition falls through to arbitrary text inspection.
**Fix direction:** Validate declared target kind and archive structure before fallback inspection.

### QA-11 — Major — Dependency scanning does not resolve versions or transitive dependencies

**Area:** T3 · **Behavior:** VERIFIED · **Effort:** L · **Demo impact:** Y

**Reproduce:** Run requirements/Cargo/npm fixtures in probes.py and inspect observation attributes.
**Expected:** Structured direct/transitive package records with versions/ranges and confidence.
**Actual:** Package tokens appear without pinned/ranged/unpinned version semantics; no transitive graph is resolved.
**Evidence:** probes.json; source `src/qrypton/scanners/extended.py:439`.
**Root-cause hypothesis — INFERRED:** Dependency adapter inherits the same archive/token implementation rather than ecosystem resolvers.
**Fix direction:** Implement supported ecosystem parsers and label unavailable transitive resolution explicitly.

### QA-12 — Major — Maven cryptographic dependency is missed

**Area:** T3 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run probes.py T3-pom.xml containing org.bouncycastle:bcprov-jdk18on:1.78.
**Expected:** Bouncy Castle library/version capability evidence.
**Actual:** Zero observations and no warning, partial=false.
**Evidence:** probes.json; source `src/qrypton/scanners/extended.py:64`.
**Root-cause hypothesis — INFERRED:** Static package token catalog excludes the Maven dependency; no XML manifest parser.
**Fix direction:** Add XML dependency parsing with ecosystem-specific identifiers.

### QA-13 — Major — Resolvable dynamic hashlib choice is missed

**Area:** T1 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run T1-dynamic: name=sha256; hashlib.new(name,b"x").
**Expected:** Resolve local literal flow or emit uncertain hashing evidence.
**Actual:** Only hashlib library record; no SHA-256 algorithm observation.
**Evidence:** probes.json, accuracy.json; source `src/qrypton/scanners/source/python_ast.py:262`.
**Root-cause hypothesis — INFERRED:** AST rules inspect explicit calls without this local literal-flow case.
**Fix direction:** Add bounded literal propagation and emit uncertain operations when selection cannot be resolved.

### QA-14 — Major — Three asset contexts do not produce three priority tiers

**Area:** T6 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run deep.py RSA gateway/logger/test-app contexts.
**Expected:** Distinct explained contextual tiers; test environment and short retention affect migration priority.
**Actual:** Gateway critical; logger high; short-lived low-impact test-app high. Mosca urgency differs but is excluded from final priority.
**Evidence:** deep-observations.json; source `src/qrypton/risk/mosca.py:124`.
**Root-cause hypothesis — INFERRED:** Current categorical rule takes worst technical risk with only upward business adjustment. This is a contract gap, not evidence that every High result is unsound.
**Fix direction:** Separate technical severity from contextual migration priority and align the intended acceptance examples.

### QA-15 — Major — Missing business context does not lower assessment confidence

**Area:** T6 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run deep.py compare RSA gateway and missing context.
**Expected:** Business unknown stays unknown with reduced assessment/context confidence.
**Actual:** Business state is unknown (good), but evidence_confidence remains .9 for every context.
**Evidence:** deep-observations.json; source `src/qrypton/risk/mosca.py:414`.
**Root-cause hypothesis — INFERRED:** Only finding detection confidence is carried into risk factors; completeness confidence is not represented.
**Fix direction:** Keep detection confidence and add explicit risk/context completeness confidence.

### QA-16 — Major — Scoring thresholds and timeline defaults are not configurable through the CLI

**Area:** T6/T9 · **Behavior:** INFERRED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Inspect default config and Mosca priority code; CLI help.
**Expected:** Auditable policy config controls thresholds and assumptions.
**Actual:** Mosca score >=50 and rank uplift live in code; CLI config permits only db,max_concurrency,max_risk and cannot supply business/timeline assumptions.
**Evidence:** scanner-read.json, tooling-libraries.json, cli-scan-help.json; source `src/qrypton/cli.py:109`.
**Root-cause hypothesis — INFERRED:** Policy version strings exist, but the decisions and usable CLI context are compiled constants.
**Fix direction:** Expose validated risk policy/context inputs with versioned effective configuration.

### QA-17 — Major — Fixed-time repeat scan silently fails instead of reusing a result

**Area:** T5/T9 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Compare cli-scan-a and cli-scan-b with same target/db/reference-time.
**Expected:** Safe idempotent reuse, or documented specific duplicate-result error.
**Actual:** First exits 0; second exits 2, empty output and no second CBOM. Separate fresh database produces byte-identical CBOM.
**Evidence:** cli-scan-a.json, cli-scan-b.json, cbom-validation.json; source `src/qrypton/storage/sqlite.py:56`.
**Root-cause hypothesis — INFERRED:** Stable run ID encounters immutable snapshot protection; CLI converts this into unexplained invocation error.
**Fix direction:** Reuse matching immutable result or return a documented, explanatory duplicate-run outcome.

### QA-18 — Major — Invalid baseline is misclassified and artifacts are absent

**Area:** T11 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run ci-command-invalid-baseline with inventory=not-an-object.
**Expected:** Validate complete baseline before scan; BASELINE_ERROR=5 with actionable message.
**Actual:** Exit 2, blank output; no CI artifact.
**Evidence:** ci-command-invalid-baseline.json; source `src/qrypton/cli.py:238`.
**Root-cause hypothesis — INFERRED:** Only top-level dict/schema_version is checked; malformed inventory fails later and is caught as usage error.
**Fix direction:** Validate full baseline schema before any scan and emit sanitized failure artifacts.

### QA-19 — Major — Unknown scanner selection is silently ignored

**Area:** T9/T11 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Run ci-command-unknown-scanner with qrypton-source plus does-not-exist.
**Expected:** Reject unknown plugin selection as usage/scanner error.
**Actual:** Exit 3 policy violation, scanner.failed=0, scanner.partial=0; unknown selection has no diagnostic.
**Evidence:** ci-command-unknown-scanner.json, ci-artifact-unknown-scanner.json; source `src/qrypton/application/orchestration.py:266`.
**Root-cause hypothesis — INFERRED:** Selection filters known scanners without requiring every requested name to resolve.
**Fix direction:** Validate scanner names before execution and distinguish unavailable scanner from policy failure.

### QA-20 — Major — Cross-target canonical asset correlation is not demonstrated

**Area:** T5 · **Behavior:** INFERRED · **Effort:** L · **Demo impact:** Y

**Reproduce:** Inspect correlate interface and scope validation.
**Expected:** One canonical library asset across source/binary/dependency/container evidence, with explicit explanations.
**Actual:** Correlator operates within one supplied asset/target and retains location/context anchors; cross-target canonical asset merger is not evident.
**Evidence:** deep-interfaces.json, existing-archive-claims.json; source `src/qrypton/application/correlation.py:35`.
**Root-cause hypothesis — INFERRED:** Per-usage correlation deliberately avoids broad same-name merges; there is no tested cross-surface identity layer.
**Fix direction:** Introduce explicit library identity/version/context graph correlation while preserving usage records.

### QA-21 — Major — Documented engineering checks fail

**Area:** T0/T15 · **Behavior:** VERIFIED · **Effort:** M · **Demo impact:** Y

**Reproduce:** Run lint, focused-lint and mypy commands.
**Expected:** Required lint/type checks exit 0.
**Actual:** Root lint reports 3853 issues including old tmp fixtures; src/tests-only lint still reports 170; mypy reports 13 errors in 4 sample modules.
**Evidence:** lint.json, focused-lint.json, mypy.json; source `pyproject.toml:60`.
**Root-cause hypothesis — INFERRED:** Sample/fixture inclusion and genuine style/type failures are not reconciled with the published gates; API typing is additionally suppressed in config.
**Fix direction:** Define intentional fixture exclusions and make the declared supported code pass required checks.

### QA-22 — Major — README contradicts shipped functionality

**Area:** T0/T15 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Read README verbatim.
**Expected:** Current install/entrypoint/scanner/UI description and explicit runtime networking limitations.
**Actual:** README says tool does not scan/persist/expose UI while code and fresh CLI scan do; no complete backend dependency install is documented.
**Evidence:** recon.json, clean-cli.json; source `README.md:5`.
**Root-cause hypothesis — INFERRED:** Contract-only introduction remained while implementation expanded.
**Fix direction:** Replace stale instructions with tested install, scan, dashboard and gate commands.

### QA-23 — Minor — Legacy empty/corrupt database shows demo metrics

**Area:** T10 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** Y

**Reproduce:** Existing AppTest cases exercise empty, missing and corrupt DBs.
**Expected:** Empty/error presentation for persisted assessments; sample mode only explicit opt-in.
**Actual:** Legacy dashboard substitutes MockDashboardDataProvider. Sidebar does explicitly say Demo Mode, so this is not concealed production fabrication.
**Evidence:** suite-2.xml, source-tests.json, security-and-ui-code.json; source `src/qrypton/ui/app.py:49`.
**Root-cause hypothesis — INFERRED:** Fallback-to-mock is intentional and tested rather than a strict persisted-data empty state.
**Fix direction:** Require explicit sample-mode choice and preserve corrupt-storage errors.

### QA-24 — Minor — Legacy Streamlit test is sensitive to cold-start timing

**Area:** T0/T10 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** N

**Reproduce:** Compare all three suite XMLs.
**Expected:** Repeatable acceptance suite on declared environment.
**Actual:** First run times out at 15s for empty-db AppTest; same test passes in runs 2 and 3 and coverage run.
**Evidence:** suite-1.json, suite-2.json, suite-3.json; source `tests/ui/test_app_e2e.py:23`.
**Root-cause hypothesis — INFERRED:** Cold import/render timing is an INFERRED cause; concurrent audit load may contribute. This does not prove an intrinsic product race.
**Fix direction:** Measure and stabilize cold startup/readiness before enforcing an AppTest deadline.

### QA-25 — Minor — CLI has no version command

**Area:** T15 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** N

**Reproduce:** Run cli-version.
**Expected:** --version reports packaged tool version.
**Actual:** Exit 2 with required-command usage error.
**Evidence:** cli-version.json; source `src/qrypton/cli.py:32`.
**Root-cause hypothesis — INFERRED:** argparse has no version action.
**Fix direction:** Provide a consistent packaged CLI/scanner version command.

### QA-26 — Minor — Demo SQLite database is tracked

**Area:** T15 · **Behavior:** VERIFIED · **Effort:** S · **Demo impact:** N

**Reproduce:** Run git -c core.fsmonitor=false ls-files *.db *.sqlite3.
**Expected:** Explicitly governed sample artifacts, no unexplained generated database in source control.
**Actual:** qrypton_demo.db is tracked; .gitignore excludes qrypton.db but not this demo file. No real secret in it was asserted or inspected.
**Evidence:** final-code-evidence.json; source `.gitignore:12`.
**Root-cause hypothesis — INFERRED:** Demo DB hygiene is inconsistent with other generated storage exclusions.
**Fix direction:** Document/version a sanitized fixture format or exclude generated DB state.

## 5. Spec vs reality and feature inventory

Named master specs: **UNTESTED — unavailable**. Available contract: .kiro/specs/cryptographic-discovery-workflow/requirements.md, copied to evidence/workflow-spec.txt. Requirement-section matrix follows; PARTIAL does not imply every subcriterion was run.

| Contract section | Status | Actual behavior / evidence |
|---|---|---|
| 1.1 Source Repository | PARTIAL | Python/C/C++ local tree; hosted acquisition code; controlled source tests. Config/build/reference coverage incomplete. |
| 1.2 Source Archive | PARTIAL | ZIP/tar recursive extraction exists; T4 bounds/type-validation failures. |
| 1.3 Binary | PARTIAL | ELF/PE/thin Mach-O parser code; real PE tested and broken exports; real ELF/Mach-O not tested. |
| 1.4 Dependency Manifest | PARTIAL | Token-based adapter, pip names observed; Maven missed; versions/transitives unimplemented in adapter. |
| 1.5 Container Image | PARTIAL | Archives and supplied references accepted; registry is not pulled; no correct layer/whiteout reconstruction. |
| 1.6 Cloud KMS | STUBBED-OR-MOCKED | Static ARN/URL/resource descriptor only; no authenticated AWS/Azure/GCP metadata collection. This limitation is explicitly represented in evidence semantics. |
| 2 Normalized finding / operations | PARTIAL | Typed canonical contracts and source parameters exist; composite identity/3DES/column/location and coverage gaps. |
| 3 Context classification | PARTIAL | Context-aware correlation and test/example classifiers exist; full pyca benchmark not rerun. |
| 4 CBOM | IMPLEMENTED | Official CycloneDX 1.6 sample validation and deterministic exporter reproduced; many semantic fields not exhaustively independently recomputed. |
| 5 Quantum risk / HNDL | PARTIAL | Algorithm taxonomy and role-aware Mosca applicability exist; input/identity defects contaminate outputs. |
| 6 Mosca / business inputs | PARTIAL | Finite checks, scenario-labelled X/Y/Z and independent urgency; extreme sum crash and confidence/config gaps. |
| 7 Prioritization | PARTIAL | Categorical explanatory rule; only uplift for business; low-impact test RSA remains high. |
| 8 Risk Dashboard | PARTIAL | Real persisted API + Next UI; tested synthetic KPIs; exhaustive GUI actions not completed. |
| 9 Heatmap | PARTIAL | Persisted matrix and filtering code/tests; every real browser cell click not exercised. |
| 10 Mosca visualization | PARTIAL | Timeline/sensitivity code and existing tests; browser interaction/export incomplete. |
| 11 PQC/hybrid recommendations | IMPLEMENTED | Role-first tested mappings; FIPS names checked with NIST. Compatibility fields explicitly unknown, not measured performance. |
| 12 Migration roadmap | PARTIAL | Persisted roadmap and rank rationale; browser actions/dependency blockers not exhaustive. |
| 13 Actionable remediation | PARTIAL | Recommendation plans and lifecycle/action routes exist; real external ticket integrations not invoked. |
| 14 Evidence/explainability | PARTIAL | Provenance/confidence/rationale survive CBOM; primitive identity and PE evidence bugs; no source-column field. |
| 15 Scan summary | PARTIAL | Persisted KPIs and branded PDF/report paths tested in existing suite; all narrative claims not reviewed. |
| 16 Search/filter/drilldown | PARTIAL | Inventory helper tests pass; browser control inventory observed; every combinatorial filter/export not tested. |
| 17 History/comparison | PARTIAL | SQLite history, comparison API/UI, immutable snapshots; anonymous delete and repeat-run error gaps. |
| 18 Platform differentiation | PARTIAL | Real AST/risk/CBOM chain beyond keywords; dependency/container remain keyword-centric. |
| 19 User experience | PARTIAL | Next login, role home, inventory/risk/exports; legacy sample fallback; no complete WCAG audit. |
| 20 Demonstration benchmark | PARTIAL | Local synthetic benchmark and sample app exist; real pyca/cryptography acquisition benchmark not executed. |
| NFR security/multitenancy | PARTIAL | Sanitized bounded samples and governed action routes pass; scan-route authentication is missing. |
| NFR performance/scalability/accessibility | PARTIAL | 15 local scanner runs measured; enterprise scale, >100k LOC, stress and WCAG not demonstrated. |
| Network inspection preview | UNDOCUMENTED-EXTRA / STUBBED-OR-MOCKED | Synthetic random telemetry, seeded 48213 keys/1174 violations/326 tunnels; explicitly says preview, not measured traffic. |
| Auth/roles/settings/notifications/finding lifecycle | UNDOCUMENTED-EXTRA relative to available workflow text | Account/OAuth, server roles, local settings, scan notifications and decisions implemented; exact UX spec unavailable. |

Source feature inventory: argparse commands `scan`, `report`, `ci scan`; all advertised flags captured in cli-*-help.json. CLI asset kinds include repository/application/service/host/container_image/binary/library/datastore/other, but target routing is directory→source_tree and file→FILE, so advertised asset labels are not proof of backend capability. Six registered adapters: qrypton-source (tree and archive adapters), qrypton-binary, qrypton-library, qrypton-container, qrypton-kms. Versions are 0.2.0 source, 0.3.0 binary and 0.4.0 extended adapters; exporter 0.7.0; package 0.1.0. Runtime versions are in available-packages.json and fresh install logs.

API feature inventory: 45 decorated route definitions found by AST, including account signin/signup, session/OAuth, upload/scan/progress/history, sample workspace, persisted dashboard/inventory/detail/heatmap/risk/Mosca/roadmap/CBOM/PDF, decisions/tickets, saved views/comparison/CI publishing. Exact file/function/line inventory: summary-data.json. Decorated router paths need their router prefix added; this is source inventory, not proof every route works.

Next navigation: Dashboard, Results, Crypto Inventory, Risk & Prioritization, Migration Roadmap, CBOM / Reports, Integrations, Network Inspection, Your Scans. Legacy Streamlit tabs: Executive Posture, Crypto Inventory, Risk Heatmap, Mosca Analysis, Finding Detail, CBOM Export, PQC Roadmap. Both are present; Next is README launcher target. No product Dockerfile or top-level LICENSE found; manifest labels license Proprietary and font licenses exist. Missing standalone license is packaging information, not asserted illegal use.

## 6. Measured metrics

| Metric | Measurement | Scope |
|---|---:|---|
| Python statement coverage | 84.72% (6378/7528) | Existing suite; no branch coverage; Streamlit app script itself shows 0% due harness execution context |
| Python AST fixture precision / recall / F1 | 0.9375 / 0.8824 / 0.9091 | 15 valid fixtures; per-file unique algorithm/protocol labels |
| Python AST TP / FP / FN | 15 / 1 / 2 | 3DES→CAPI FP+FN and dynamic SHA-256 FN |
| Fresh packaged first scan process | 2.240 s | CLI process including imports, scan, risk, DB and export; install time excluded |
| Other detector precision/recall | not measured | C/C++, binary, lexical fallback, package/version classifiers |
| Largest CBOM measured | 820425 bytes / 200 components | Official-schema valid synthetic export |
| Largest real binary tested | 5791900 bytes | Copied real PE DLL, read only |
| Largest hostile source file | 5,242,882 bytes | Oversized file skipped, partial=true |
| Bounded expansion fixture | 346 compressed bytes / 262144 payload bytes | 65536-byte expanded cap correctly rejects |

| Repo | Files | Bytes | Lines | Runs | Median s | p95 s | Python allocation peak bytes | Process cumulative peak working set bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| small | 10 | 2440 | 220 | 5 | 0.01443 | 0.03885 | 630996 | 47931392 |
| medium | 100 | 24400 | 2200 | 5 | 0.10229 | 0.17212 | 510685 | 48775168 |
| large | 1000 | 244000 | 22000 | 5 | 1.58248 | 2.31994 | 4397092 | 59658240 |

p95 is the nearest-rank fifth sample for n=5. Source-scanner timing includes traversal, AST and raw-observation serialization under tracemalloc; it excludes normalization/risk/CBOM/database. Working-set high-water marks are cumulative within the benchmark process, not isolated per scan or container memory enforcement. Repository sizes are 220/2200/22000 lines and do not prove enterprise or >100k LOC performance. The earlier performance.json measurement with an invalid Windows handle yielded zero memory; performance-memory.json contains the corrected measurements used here.

### Hand recomputation

| X | Y | Z | X+Y | Margin Z−(X+Y) | Exposure | Expected / observed urgency |
|---:|---:|---:|---:|---:|---:|---|
| 5 | 2 | 10 | 7 | 3 | 70% | medium / medium |
| 5 | 5 | 10 | 10 | 0 | 100% | high / high |
| 8 | 4 | 10 | 12 | −2 | capped 100% | critical / critical |
| 0 | 0 | 0 | 0 | 0 | 0% | high / high under equality rule |
| 0 | 0 | 10 | 0 | 10 | 0% | low / low |

Categorical rule hand cases: low/low/low→low=25; high/high/low→high=75; high/high/critical→critical=100; unknown/unknown/critical→medium=50; all unknown→unknown with no observed score. All five match. These verify the implemented formula, not the business suitability of excluding Mosca urgency.

### Standards and dependency advisories

NIST names/roles verified on official pages: [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final). ML-KEM establishes key material; it is not a universal drop-in signature or bulk-encryption replacement. Tested recommendation plans preserve this distinction.
Official [CycloneDX 1.6 schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json) SHA-256: `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93`. Bundled schema differs from the 1.6 release schema; the tested emitted samples still validate against the official release. This does not prove every future payload or bundled modification valid.

pip-audit reported **5 advisory records in 2 packages**, including a duplicate pytest advisory: pytest 8.4.2 / CVE-2025-71176 (UNIX temporary-directory issue; this audit is Windows), urllib3 2.7.0 / CVE-2026-97687, CVE-2026-97688, CVE-2026-97689 (proxy/streaming conditions). Thus **4 unique CVE IDs** were reported. VERIFIED only means installed versions and advisory response matched; exploitation/reachability is UNTESTED. These include dev/UI transitive dependencies, not necessarily the minimal CLI wheel. Exact service data and fixes: pip-audit.json. No blanket Critical vulnerability claim is made from package presence alone.

## 7. Not tested / incomplete

| Area | Reason / exact limitation |
|---|---|
| T0 named specs and exact Final Engineering Gate | Master roadmap/UX spec absent; available workflow contract used instead |
| T0 verbatim README launcher/npm install | Would write outside qa_audit; isolated copied launch used; no root npm dependency mutation |
| T0 Docker build | Daemon unavailable and Dockerfile not found |
| T1 symlink loops/permission errors | Symlink privilege unavailable; exhaustive OS ACL race tests not run |
| T1 every language/API/parameter combination | Controlled Python classes plus existing tests; C/C++ detector accuracy, Java/JS source discovery and every TLS/key mode variant not measured |
| T2 real ELF/Mach-O/stripped/static fixtures | Real PE only; code support and mocked metadata tests are not proof of those formats |
| T3 transitive resolution/EOL datasets | No resolver or dated rules identified; full ecosystem variants not independently exercised |
| T4 all OCI registry/schema/package DB/layer/memory attacks | Minimal OCI plus Docker-save whiteout/local tar cases; no full package-DB or enforced OS-memory stress |
| T5 four surfaces/conflicting 2048 vs 4096 | Correlation code and existing tests reviewed; complete synthetic cross-surface identity fixture not run |
| T6 every policy/config/sensitivity path | Scalar and context cases run; broad property coverage from existing tests only; full sensitivity visualization not independently exercised |
| T8 all semantic fields | Four official-schema samples; all evidence/risk/recommendation meanings not exhaustively compared at maximum scale |
| T9 corrupt SQLite/concurrent writers/ACL failures | Existing tests cover portions; dedicated long concurrency stress and corrupted CLI DB not independently run |
| T10 every control/full wizard-to-export flow | Real browser login/dashboard/wizard start/narrow layout observed; all filter/sort/search/nav/heatmap-cell combinations, external integration actions and full submission flow not completed |
| T10 WCAG/contrast/screen readers | Basic viewport/tab probe only; no conformance claim |
| T11 hosted workflow/actionlint | actionlint unavailable; no real GitHub PR, remote artifact upload or comment posting |
| T12 network auth/SSRF/CVE exploitation | Local bounded fixtures only; no secrets/cloud credentials or hostile external servers used |
| T13 enterprise scale | Largest measured repo 1000 files / 22000 lines; performance cannot be extrapolated |
| T14 exhaustive honesty/state semantics | Targeted claim search and sample observations only |
| T15 complete unused dependencies/dead code | Targeted grep and inventory only |

No absence of generic vulnerability scanning, SQLi/XSS or generic secret hunting is counted as a product defect. Canary secrets test QRYPTON output handling only.

## 8. Top 10 fixes

Rank is qualitative (correctness and demo impact relative to effort); no fabricated numeric return-on-effort score.

| Rank | Fix | Finding(s) | Effort |
|---:|---|---|---|
| 1 | Declare and verify clean backend/test dependencies | QA-01 | S |
| 2 | Enforce principal/tenant authorization on scan mutations | QA-02 | M |
| 3 | Remove invented primitive mappings from metadata | QA-03 | M |
| 4 | Correct PE AddressOfNames parsing | QA-08 | S |
| 5 | Correct DES3 and composite RSA identity rules | QA-04, QA-05 | S/M |
| 6 | Enforce compressed/count/depth/member/layer limits with explicit partial/error | QA-06, QA-10 | M |
| 7 | Reconstruct effective Docker/OCI layers and whiteouts | QA-09 | M/L |
| 8 | Make deterministic reruns and malformed CI inputs explainable | QA-17, QA-18, QA-19 | S/M |
| 9 | Complete contextual priority/confidence and policy configuration | QA-07, QA-14..16 | M |
| 10 | Implement manifest identities/versions; align docs and gates | QA-11..13, QA-21, QA-22 | M/L |

## Evidence index

- repro/run.py: command deadlines, argv/output capture and audit environment isolation.
- repro/probes.py, deep.py, extra_checks.py: synthetic scanners/risk/recommendation/archive/binary/CBOM probes.
- repro/pipeline.py and pipeline_completion.py: CLI/API/persistence/auth/secrecy and deterministic CBOM.
- repro/ci_probes.py: baseline/delta/invalid-selection checks.
- repro/performance.py, accuracy.py, coverage_run.py: measured metrics.
- repro/ui_prepare.py, ui_launch.py, ui_browser.cjs: isolated Next + API/headless browser.
- evidence/acceptance-checks.json: exact scoreboard check ledger.
- evidence/defects.json: ranked findings with dynamically resolved source lines.
- evidence/summary-data.json: before/after source hashes, suite totals, route and claim inventory.
- evidence/claims search data is in summary-data.json; raw docs are claims, not passing tests.
