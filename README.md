# QRYPTON

QRYPTON is an enterprise cryptographic discovery and quantum-risk assessment engine.

Phase 1 establishes the canonical, offline-only domain contracts. It deliberately
does not scan repositories, execute binaries, fetch images, persist data, or expose
a UI. Treat all future scan inputs as untrusted.

## Development

Use Python 3.11–3.13 and install the `dev` dependency group with your approved
package-management workflow. Run `pytest`, `ruff check .`, and `mypy src` before
merging. No network access is required at runtime.

## Contract guarantees

- Pydantic v2 models are immutable and reject unknown fields.
- Dates are timezone-aware and normalized to UTC.
- Deterministic identifiers are tenant-scoped HMAC-SHA-256 values.
- Observation state differentiates uninspected, indeterminate, and proven-absent data.
- Raw repositories, binaries, archives, and images are not represented in model payloads.
