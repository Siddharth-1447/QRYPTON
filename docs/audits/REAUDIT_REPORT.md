# QRYPTON re-audit

Date: 2026-10-13. Scope: the current, heavily modified working tree. Product code and configuration were not changed in this re-audit. New probe files and results are confined to `qa_audit/`. This is a working-tree assessment, not an immutable-release certification.

**Verdict: the historical roadmap's Final Engineering Gate is not met.** Its ten-stage chain requires an end-to-end run on a clean environment. The synthetic target exists, but anonymous scan creation/deletion, archive limits, metadata false positives, whiteouts, cross-surface correlation, and scoped Ruff remain open. The requested live browser flow could not be completed because the Next server is unavailable in this environment. Do not treat that flow as passed.

**Evidence tags:** VERIFIED means this re-audit executed the stated check; INFERRED means source inspection supports the finding but its end-to-end effect was not exercised; UNTESTED means no current execution proof. FIXED means the original acceptance fixture now meets its specified behavior; NOT FIXED means the repro remains or required evidence is absent; REGRESSED is reserved for a newly verified product failure against the previous baseline.

## Source authority and limitations

The user supplied the exact historical documents after the initial re-audit: [QRYPTON Execution.pdf](<C:/New folder/Desktop/QRYPTON Execution.pdf>) (28 pages; SHA-256 `83d728984eb9dc6d435d81a744b840edbf414cdf8fb7fb7c2765ecba885d3bee`), [QRYPTON UIUX.pdf](<C:/New folder/Desktop/QRYPTON UIUX.pdf>) (13 pages; SHA-256 `38fe378cefa459570ed2b3a73efcaf92f9d71ec81a910f1fff00d9499ab02223`), and [Qrypton User Perspective.pdf](<C:/New folder/Desktop/Qrypton User Perspective.pdf>) (23 pages; SHA-256 `16acada5568869d83579a67da416ab7e206c17371ee0d8e9983b408b86902`). Text was extracted from all pages; the mathematical and gate pages were also visually rendered and checked because extraction omits some symbols. The score below now uses the **Final Engineering Gate on Execution p. 28**, with the exact demo flows on UIUX p. 13 and User Perspective p. 22. The later [Product Roadmap & Governance](https://app.notion.com/p/3cfc51d1063a812983ccf30770c3a354) is supplemental context, not the authority for this historical gate.

The PDFs contain embedded “Exact Codex /plan Prompt” and “AI build prompt” passages. Those are historical specifications to assess, not instructions or authorization to change product code. The current user request remains a read-only re-audit with this report written under `qa_audit/`.

The local Windows sandbox stalls even on standalone `asyncio.run(asyncio.sleep(0))`. Direct `qa_audit/repro/probes.py` and `qa20_four_surface.py` each timed out at 20 seconds with no output ([timeout records](evidence/reaudit-probes.json), [correlation timeout](evidence/reaudit-qa20.json)). Running their functions inside pytest completed; the [audit bridge](repro/test_reaudit_bridge.py) records that method. Every hostile probe uses the bounded scripts and only synthetic files beneath `qa_audit/`.

## Executed command record

| ID | Command (repository root unless noted) | Output |
|---|---|---|
| C1 | `.venv\Scripts\python.exe -m pytest -q qa_audit/repro/test_reaudit_bridge.py --basetemp qa_audit/tmp/reaudit-bridge-2` | `3 passed, 2 warnings in 4.46s`; produced [probes](evidence/probes.json), [archive checks](evidence/extra-observations.json), [four-surface result](evidence/reaudit-qa20-four-surface.json). |
| C2 | `.venv\Scripts\python.exe -m pytest -q qa_audit/repro/test_reaudit_bridge.py::test_original_deep_and_accuracy --basetemp qa_audit/tmp/reaudit-deep` | `1 passed in 5.53s`; produced [deep observations](evidence/deep-observations.json) and [accuracy](evidence/accuracy.json). |
| C3 | `.venv\Scripts\python.exe -m pytest -q qa_audit/repro/test_reaudit_bridge.py::test_anonymous_scan_mutation --basetemp qa_audit/tmp/reaudit-qa02` | `1 passed in 3.09s`; [response record](evidence/reaudit-qa02.json): anonymous POST 200, DELETE 204. The test passing means the repro completed, **not** that authorization passed. |
| C4 | `.venv\Scripts\python.exe -m pytest -x -q tests/scanners/test_qa08_pe_exports.py tests/scanners/test_qa10_qa12_static_parsing.py tests/scanners/test_python_ast.py tests/risk/test_corrective_phase.py tests/risk/test_mosca.py tests/integration/test_cli_failure_contracts.py tests/integration/test_cli_version.py tests/ui/test_app_e2e.py tests/api/test_network_inspection_absent.py --basetemp qa_audit/tmp/reaudit-focused-direct` | `96 passed, 1 warning in 15.96s`. A wrapper attempt with custom audit cache environment timed out after 120 seconds; this direct invocation is the valid result. |
| C5 | `.venv\Scripts\python.exe -m pytest -q --basetemp qa_audit/tmp/reaudit-full` | `650 passed, 2 skipped, 1 warning in 73.44s`. Skips: Windows symlink privilege; opt-in remote acquisition. |
| C6 | `.venv\Scripts\ruff.exe check src tests` / `.venv\Scripts\mypy.exe src` | Ruff exit 1, `Found 124 errors`; mypy exit 0, `Success: no issues found in 103 source files`. |
| C7 | `cd web; npm test` | Exit 1: 55 passed, 7 failed because `web/node_modules/react/index.js` is missing. Earlier failed `npm ci` left React and Next absent; this is an environment failure, not proof of a frontend code regression. |
| C8 | `.venv\Scripts\python.exe qa_audit/repro/reaudit_cold.py` | [Ten fresh-process results](evidence/reaudit-qa24-cold.json): 10/10 pass; wall times 7.786–8.340 seconds; nearest-rank p95 8.340 seconds. Sandbox temp cleanup printed PermissionError after the successful test processes. |
| C9 | `Get-FileHash src/qrypton/exporters/schemas/cyclonedx/bom-1.6.schema.json -Algorithm SHA256` and same for `qa_audit/evidence/official-bom-1.6.schema.json` | Bundled: `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5cecca5b37d`; official copy: `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93`. |
| C10 | `.\qa_audit\venv\Scripts\python.exe -m pip_audit --path .venv\Lib\site-packages --format json --timeout 5 --output qa_audit\evidence\reaudit-pip-audit.json` | Exit 1, DNS failure resolving `pypi.org`; no current advisory verdict. The earlier [post-bump audit](evidence/qa-ex4-pip-audit-after.json) is historical evidence only. |
| C11 | `.\tmp\qa22-fresh-venv\Scripts\python.exe -c "import fastapi, uvicorn, streamlit, qrypton.api.app; print('fresh-api-ui-import=ok')"` then `pip check` | `fresh-api-ui-import=ok`; `No broken requirements found.` This does not re-prove the exact install command. |
| C12 | `parse_binary(Path('qa_audit/fixtures/libcrypto-real.dll'))` | `exports 5883 imports 199 RSA_public_encrypt True AES_encrypt True`; the DLL was read, never executed. |
| C13 | Real in-app browser: `http://127.0.0.1:3000/` | `net::ERR_CONNECTION_REFUSED`. Neither port 3000/3307 nor 8000/8307 had a listener. `web/node_modules/next/dist/bin/next` and React are absent. |
| C14 | `docker version --format '{{.Server.Version}}'` | Exit 1: Docker Desktop Linux engine pipe not found; image build UNTESTED. |
| C15 | Bounded `.venv\Scripts\python.exe -m qrypton.cli ci scan qa_audit/fixtures/ci ...` invocations; each linked command record contains its full argv | [Invalid baseline](evidence/ci-command-invalid-baseline.json): exit 5, `invalid_baseline: baseline inventory must be an object`, [failure artifact](evidence/ci-artifact-invalid-baseline.json) has `error_code=invalid_baseline`. [Unknown scanner](evidence/ci-command-unknown-scanner.json): exit 2, names all valid scanners; [artifact](evidence/ci-artifact-unknown-scanner.json) records `unavailable_scanners=["does-not-exist"]`. The [valid-baseline scan](evidence/ci-command-empty-baseline.json) hit its 25-second timeout, so its outcome is UNTESTED by this probe. |

## Original QA acceptance checks

Each row names the executed command above or a specific inspection command and gives the decisive output. A passing pytest process does not override a failed adversarial repro.

| Item | Status; tag | Command / output and remaining limit |
|---|---|---|
| QA-01 | **NOT FIXED as an acceptance claim; VERIFIED/UNTESTED** | C11: API/UI imports succeed in the fresh venv; `pip check` reports no broken requirements. The exact fresh install command was not rerun, so the complete installation acceptance remains UNTESTED. |
| QA-02 | **NOT FIXED; VERIFIED** | C3: anonymous `POST /api/v1/scans` = **200**, anonymous `DELETE /api/v1/scans/{id}` = **204** on a disposable audit run. This fails the secure service boundary. |
| QA-03 | **NOT FIXED; VERIFIED** | C1 [T3-benign.json and T3-package.json](evidence/probes.json): benign metadata yields RSA, SHA-256 and AES observations; package wording yields AES. Malformed JSON also yields algorithm observations. |
| QA-04 | **FIXED; VERIFIED** | C1 T1-des3: `Crypto.Cipher.DES3.new` yields `3des`, no Windows-CAPI algorithm. |
| QA-05 | **NOT FIXED; VERIFIED** | C2 alias `RSAWithSHA256` still normalizes to only `sha-256/hash`; RSA identity is absent. `RSA-2048` and `rsa2048` now retain 2048-bit size. |
| QA-06 | **NOT FIXED; VERIFIED** | C1 T4-many: 20 members accepted under file-count cap 10, partial=false. Compressed cap 1 still yields one observation; excess member size and depth yield zero observations with partial=false. Bounded gzip-bomb still raises `ValueError: archive expansion limit exceeded`. No complete fail-closed limit contract. |
| QA-07 | **FIXED; VERIFIED** | C1 [Mosca probes](evidence/mosca-probes.json): X=10000, Y=10000, Z=0 evaluates to required=20000 and margin=-20000 without validation crash; C4 exercises boundary/property tests. |
| QA-08 | **FIXED; VERIFIED** | C12 real PE exports include `RSA_public_encrypt` and `AES_encrypt`; C4 synthetic malformed/export regressions pass. |
| QA-09 | **NOT FIXED; VERIFIED** | C1 T4-whiteout retains RSA after `.wh.key.conf`, partial=false. No effective Docker/OCI layered filesystem or historical deletion provenance demonstrated. |
| QA-10 | **FIXED; VERIFIED** | C1 T4-corrupt.tar produces zero findings, partial=true and `invalid_archive` warning. C4 includes corrupt tar, truncated tar.gz, corrupt zip, zero-byte archive, valid tar and text cases (18 parsing tests within focused run). |
| QA-11 | **NOT FIXED; VERIFIED** | C1 requirements observations have no `library_version` or transitive field; Cargo fixture becomes RSA/AES algorithm tokens. No structured lockfile graph. |
| QA-12 | **FIXED; VERIFIED** | C1 pom.xml yields Bouncy Castle, Maven, version `1.78`, scope `compile`, algorithm `unknown`; C4 covers placeholder, malformed and entity payloads. |
| QA-13 | **FIXED; VERIFIED** | C1 T1-dynamic yields SHA-256; C2 [accuracy](evidence/accuracy.json) on the original 15-fixture AST corpus is TP=17, FP=0, FN=0, versus the first audit's TP=15, FP=1, FN=2. |
| QA-14 | **NOT FIXED; VERIFIED** | C2 gateway/logger/test-app RSA priorities remain Critical/High/High; Mosca urgency is excluded by `_priority_and_score` in `src/qrypton/risk/mosca.py`. No versioned urgency×impact matrix. |
| QA-15 | **FIXED; VERIFIED** | C4 risk/CBOM tests pass: detection confidence remains separate while assessment confidence/context completeness drop with missing fields; CBOM extension properties are asserted. The old deep probe does not serialize those new fields, so its omission is a probe limitation. |
| QA-16 | **NOT FIXED; INFERRED** | `rg -n "allowed =|score >= 50|_priority_and_score" src/qrypton/cli.py src/qrypton/risk/mosca.py`: CLI config still permits only db/concurrency/max-risk; threshold and uplift are compiled. No effective policy hash in the run was demonstrated. |
| QA-17 | **FIXED; VERIFIED** | C4 integration tests exercise identical immutable-result reuse, byte-identical CBOM, and distinct run-content conflict exit 7; all pass. |
| QA-18 | **FIXED; VERIFIED** | C4 invalid-baseline tests cover string/list/null/missing/wrong version; C15 directly returns exit 5 with `invalid_baseline` message and machine-readable failure artifact. |
| QA-19 | **FIXED; VERIFIED** | C4 scanner-selection tests cover unknown only, known+unknown, all known, and policy exit distinction; C15 directly returns exit 2 with valid names and an artifact listing the unavailable scanner. |
| QA-20 | **NOT FIXED; VERIFIED** | C1 [four-surface result](evidence/reaudit-qa20-four-surface.json): source 1, binary 2, manifest 1, container 4 findings (8 total); explicit cross-target correlate call raises `ValueError: candidate lies outside the correlation asset and target scope`. One caller-supplied asset ID is not a canonical merged library asset. |
| QA-21 | **NOT FIXED; VERIFIED** | C6: scoped Ruff 124 errors, despite mypy success. The declared quality gate does not exit 0. |
| QA-22 | **NOT FIXED; VERIFIED/UNTESTED** | `Get-Content README.md` shows corrected current CLI/API/UI scope and limits, but the exact documented scan/CI/frontend commands could not all be rerun in a fresh environment; C7/C13 block web verification. Content improved, acceptance incomplete. |
| QA-23 | **FIXED; VERIFIED** | C4 Streamlit AppTest cases pass: empty DB shows “No scan data yet”; missing/corrupt DB show sanitized errors; mock data requires explicit opt-in. |
| QA-24 | **FIXED; VERIFIED** | C8: ten consecutive fresh-process empty-DB AppTests pass; measured p95 8.340 seconds against the warm-up fixture's 30-second deadline. |
| QA-25 | **FIXED; VERIFIED** | C4 version test passes; fresh CLI `qrypton --version` exits 0 and lists package, source, binary, extended adapters and CBOM exporter versions. |
| QA-26 | **FIXED in working tree; VERIFIED** | `git -c core.fsmonitor=false ls-files qrypton_demo.db` returns no path; index records deletion, local file remains; `.gitignore` has `qrypton_demo.db*`; `scripts/regenerate_demo_db.py` exists and its tests pass. Prior current+historical blob scan found no tested secret-marker matches. No history rewrite was performed. |

EX-7 remains a decision, not an approved fix: C1 equality X=5,Y=5,Z=10 and X=Y=Z=0 both yield High; the current calculator uses `required == horizon -> high` after `required > horizon -> critical`. Execution p. 12 explicitly says `X + Y <= Z` is outside the modeled urgency window and `X + Y > Z` is urgent; the implemented equality branch conflicts with that classification. No code was changed.

## Other audit items and new-defect search

| Item | Status; tag | Current result |
|---|---|---|
| EX-1 Network Inspection | **NOT FIXED as an acceptance claim; VERIFIED/INFERRED/UNTESTED** | C4 confirms the API returns 404 with sample mode off. Source inspection shows the navigation condition and persistent banner text, and `rg -n "48213|1174|326" web/src/lib web/src/components/scan-export.tsx src/qrypton/exporters` finds no seeded export-path matches. Flag-on browser behavior is UNTESTED because C13 blocks the UI; its focused Node test also cannot load missing React. |
| EX-2 KMS collection | **NOT FIXED; INFERRED** | KMS remains descriptor-only; authenticated metadata ingestion was plan-first and never approved. Output-label completeness was not rechecked end to end. |
| EX-3 CycloneDX schema | **NOT FIXED; VERIFIED** | C9 bundled hash differs from official 1.6 hash. C2 validates sampled generated CBOMs against the official copy, but default bundled validation remains modified. |
| EX-4 dependency advisories | **FIXED manifest; VERIFIED/UNTESTED** | `pyproject.toml` requires pytest >=9.0.3 and urllib3 >=2.8.0; installed versions are 9.1.1 and 2.8.0, and C5 passes. Current pip-audit is UNTESTED due C10 DNS failure; historical post-bump JSON reported no vulnerabilities. |
| EX-5 Docker environment | **FIXED artifact; UNTESTED build** | `Dockerfile` and `.dockerignore` exist; C14 has no daemon. No build or runtime claim. |

New-defect search executed C1/C2 adversarial fixtures, C4 focused regressions, C5 full backend suite, C6 static gates, C7 frontend tests, and C8 repeated cold starts. **No newly confirmed product regression attributable to the fixes was established.** A verification-environment problem is confirmed: failed `npm ci` left local `node_modules` incomplete, causing seven frontend tests to fail on missing React and preventing the browser demo. This is not a source-code regression and should be repaired before rerunning web validation. Existing unresolved QA-02/03/05/06/09/11/14/16/20/21 and EX-3 are substantive release blockers.

## Four-surface correlation result

The [synthetic fixture](repro/qa20_four_surface.py) contains source OpenSSL RSA, an ELF importing `libcrypto.so.3`, a requirements manifest with `openssl==3.0.13`, and a Docker archive containing the binary and package metadata. C1 produced completed scanner statuses on all four surfaces, 8 evidence items and 8 findings. The library identity is fragmented: binary import, package manifest, container records, and source usage do not yield one canonical library record with four linked evidence items. The explicit combined call rejects cross-target candidates. The fixture's shared application asset ID was supplied by the caller; it does not prove a library-identity merge. Same-name/different-version and unrelated-target negatives remain UNTESTED because the prerequisite merge is absent.

## Browser UX walk

The requested real-browser route was attempted with the Codex in-app browser at `http://127.0.0.1:3000/`; C13 returned `net::ERR_CONNECTION_REFUSED`. The local Next and API ports have no listener. The local `node_modules` lacks Next/React after a failed install, and `npm test` fails for that environmental reason. Therefore the exact User Perspective p. 22 flow—**Dashboard → New Scan → upload/select target → Business Context → Start Scan → Live Progress → Crypto Inventory → Critical Finding → Evidence → Mosca X+Y vs Z → Business Risk → PQC/Hybrid Recommendation → Migration Roadmap → CBOM Export**—is UNTESTED end to end. UIUX p. 13 adds login, scan summary, report export, and rescan/compare progress; those are likewise UNTESTED. No current-page dead controls, browser console errors, or unexplained numbers can be enumerated honestly. C7's missing React error is a Node test/module-resolution error, not a browser console error. Old screenshots and the first audit's browser observations are not substituted for this run.

The supplied UX PDFs require a guided scan with explicit unknown context, visible evidence versus inference, editable X/Y/Z assumptions only for authorized users, role-compatible recommendations, export states, and scan history/comparison. C1/C2 demonstrate backend gaps in identity/correlation and C4 demonstrates passing focused DTO/export tests, but neither establishes that these UI controls work. The authorization failure in C3 also conflicts with the User Perspective p. 22 permission criterion.

## Historical Final Engineering Gate score

Execution p. 28 says the following ten-stage chain must work **end to end on a clean environment**. The stage statuses below distinguish a present artifact or passing unit test from a verified connected demo. Its separate rule says any manually fabricated stage makes the system a presentation mock-up; the synthetic target itself is expressly allowed.

| Stage from Execution p. 28 | Status; tag | Current evidence |
|---|---|---|
| 1. Synthetic Enterprise Target | **PASS; VERIFIED** | C1 four-surface fixture contains source OpenSSL RSA, a binary importing libcrypto, a pinned manifest entry, and a Docker archive with the binary and package metadata. This is declared synthetic, not passed off as enterprise telemetry. |
| 2. Source/Binary/Dependency/Container Evidence | **FAIL; VERIFIED** | All four scanners returned records in C1, but C1 also confirms manifest token false positives, missing structured dependency versions/transitives, and a Docker whiteout that leaves deleted RSA evidence effective. The evidence set is not trustworthy across all four surfaces. |
| 3. Canonical Crypto Findings | **FAIL; VERIFIED** | C1 benign metadata invents algorithms; C2 `RSAWithSHA256` loses the RSA identity. Normalization is not reliably canonical. |
| 4. Correlation | **FAIL; VERIFIED** | C1 produces eight findings and no canonical library asset with four links; the combined correlate call rejects cross-target candidates. |
| 5. Mosca + Business Risk | **FAIL; VERIFIED** | C2 three-asset assessment differs in context but QA-14 shows urgency excluded from final priority; EX-7 equality contradicts Execution p. 12. |
| 6. Risk Tier | **FAIL; VERIFIED** | Gateway/logger/test-app yield Critical/High/High rather than three distinct tiers under the requested fixture; no documented urgency×impact matrix. |
| 7. PQC/Hybrid Recommendation | **UNTESTED end to end; VERIFIED unit coverage** | C5 recommendation tests pass, but no connected finding→risk→role-compatible migration decision was run through the unavailable UI/demo chain. |
| 8. CBOM | **FAIL; VERIFIED** | C2 sampled CBOMs validate against an official 1.6 copy, but C9 shows the product's bundled default schema differs. A complete correlated scan-specific export was not demonstrated. |
| 9. Dashboard | **UNTESTED** | C13 browser connection refused; no live data, dead-control, console, or number audit could be performed. |
| 10. CI Policy Gate | **UNTESTED end to end; VERIFIED failure contracts** | C15 confirms invalid-baseline and unknown-scanner exits/artifacts, but the valid-baseline scan timed out; no clean new-finding→policy→artifact demo was completed. |

**Final Gate: FAIL. One stage (the synthetic target) is independently verified; zero complete ten-stage chains were demonstrated.** This is more precise than the earlier provisional 0/6 score against the later Notion roadmap. Execution pp. 23–25 additionally require per-scanner accuracy, malformed-input/resource tests, determinism, performance, and explicit limits; C1, C2 and C6 show these are not all satisfied. Execution p. 26 forbids fabricated dashboard counts, and UIUX p. 13 requires a continuous flow through export and comparison; neither can be certified without the browser run.

## Next verification boundary

Restore a complete `web/node_modules` from the lockfile in an environment with package-registry access, start the API and Next server on loopback, then repeat both supplied PDF demo flows with a disposable audit DB while capturing console/network logs. Rerun pip-audit when the advisory service is reachable. None of those missing results is silently scored as a pass.
