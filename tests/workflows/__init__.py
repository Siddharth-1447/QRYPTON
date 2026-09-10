"""Backend workflow acceptance suite: five scan workflows end to end.

Reuses the existing architecture (FastAPI routes, ScanRequest, SCANNER_ROUTING,
registered scanners, CycloneDX exporter, Mosca risk engine, SqliteRunStore).
No mocks of scanners, no parallel architecture, no network in default runs.
"""
