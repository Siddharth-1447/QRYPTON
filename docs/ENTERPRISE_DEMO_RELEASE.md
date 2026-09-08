# QRYPTON enterprise demo and release package

## Release claim

The release demo proves the evidence-backed path from source discovery through
normalization, correlation, CycloneDX 1.6 CBOM export, Mosca X+Y>Z evaluation,
PQC recommendation mapping, SQLite persistence, and dashboard presentation. It
uses only `demo/enterprise/`, a pinned environment, and a fresh database.

The demo must not claim binary discovery, business-context risk differentiation,
or a CI policy decision that was not produced by the run being shown. Those
capabilities are present as contracts or tests but are not wired into the
current CLI demo invocation.

## Reproducibility contract

* Python 3.11, 3.12, or 3.13; install from the checked-in `pyproject.toml`.
* For the dashboard, install the checked-in UI extra and use the checked-in
  `web/package-lock.json` only for the separate Next.js prototype; the release
  dashboard is Streamlit.
* Run from the repository root with a fresh `artifacts/enterprise-demo/`.
* Use the fixed tenant, asset metadata, 32-byte demo secret, corpus, scanner
  versions, default risk/PQC policies, single-worker default, and
  `--reference-time 2026-01-15T10:00:00+00:00`.
* Never commit the secret, SQLite database, generated CBOM, or evidence bundle.
* Preserve `demo.cdx.json`, `evidence.json`, command transcript, Python version,
  package lock/version output, and the corpus SHA-256 manifest as release
  evidence.

## Pre-demo health checks

```powershell
python --version
python -c "import qrypton, pydantic, jsonschema; print('python: PASS')"
pytest -q
ruff check .
mypy src
python -c "from pathlib import Path; assert all((Path('demo/enterprise') / p).is_file() for p in ['payment_service.py','edge_gateway.cpp','modern_service.py']); print('corpus: PASS')"
```

The demo is blocked if any check fails. Do not substitute the mock dashboard
provider for a failed database or scanner: that would invalidate the evidence.

## End-to-end proof points

1. **Multi-surface discovery:** the corpus includes Python AST and C++ lexical
   evidence, and `evidence.json` records the completed source scanner plus
   SHA-256 digests for all three corpus files. Persisted evidence locations are
   intentionally redacted by SQLite storage.
2. **Normalization and correlation:** the verifier requires every finding to have
   evidence and matching assessments; IDs are derived from the fixed secret and
   canonical payloads.
3. **CBOM:** the persisted CBOM bytes and exported file must be identical; validate
   the JSON against `src/qrypton/exporters/schemas/cyclonedx/bom-1.6.schema.json`.
4. **Mosca prioritization:** every finding has one persisted evaluation with X, Y,
   Z, required years, margin, exposure score, and urgency.
5. **PQC mapping:** findings for `sha-1`, `rsa`, and `ec` must yield mapped
   recommendations; the modern control fixture must not create a legacy
   recommendation.
6. **Interactive dashboard:** the UI must select the persisted run with
   `QRYPTON_DB` and `QRYPTON_TENANT_ID`; screenshots must show the run ID and
   persisted counts from `evidence.json`.
7. **Shift-left policy gate:** the scan must exit `0` only when the completed run
   passes the default medium-risk gate. A deliberately failing gate rehearsal is:

   ```powershell
   qrypton scan demo\enterprise --tenant-id tenant_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --asset-kind application --asset-reference enterprise-demo --asset-name "QRYPTON Enterprise Demo" --id-secret-env QRYPTON_DEMO_SECRET --reference-time 2026-01-15T10:00:00+00:00 --db artifacts\enterprise-demo\gate.sqlite3 --max-risk low --quiet
   ```

   This command must exit `3`; retain the exit code in the CI transcript.

## Accuracy, coverage, and performance evidence

The release evidence bundle must include:

* **Coverage:** corpus file count, evidence count, finding count, recommendation
  count, and the exact source paths from `evidence.json`; zero missing-path or
  orphan-evidence assertions.
* **Accuracy:** a hand-audited expected-algorithm table checked against the
  persisted findings (`sha-1`, `rsa`, `ec`, `aes`, and `tls` where emitted);
  false-positive control for `ML-KEM-768`; and CBOM schema validation.
* **Determinism:** two fresh runs with equal `run_id`, CBOM bytes, CBOM digest,
  and sorted evidence/finding identifiers.
* **Performance:** record wall-clock seconds and peak RSS for the scan and
  verifier on the release runner. Publish the observed values, not a promise;
  fail the release if the second run differs in identifiers or bytes.
* **Tests:** the pre-demo checks above plus the existing scanner, risk,
  recommendation, exporter, orchestration, and UI test modules.

## Fallback and stop conditions

If the scanner fails, stop and retain the non-zero transcript and sanitized
diagnostic. Do not silently fall back to mock data. If the Streamlit UI fails,
use `evidence.json` plus the CBOM schema validation and a static JSON report;
the interactive-dashboard proof point remains unproven and the release must be
marked partial. If a dependency cannot be installed offline, use the pinned
release environment; do not change the corpus or expected metrics.

## Unsupported cases and known limitations

The current release does not defensibly prove: native binary scanning in this
corpus; dependency/SBOM ingestion; certificate/key-material extraction;
business-context differentiated scoring through the CLI; hybrid negotiation
compatibility; historical trend accuracy; or production authentication and
multi-tenant deployment. The Next.js web directory is a prototype and is not
the release dashboard. The mock provider is test/demo scaffolding only.

## Remove before release

Remove or disable any screenshot, metric, or script sourced from
`MockDashboardDataProvider`, the checked-in `qrypton.db`/`qrypton_demo.db`, or
the Next.js prototype. Remove claims that the CLI accepts business context or
that a failed scanner is safely covered by UI fallback. These artifacts are
unstable or not evidence from the deterministic corpus.
