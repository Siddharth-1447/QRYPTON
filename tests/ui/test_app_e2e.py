"""End-to-end tests for the Streamlit dashboard using AppTest when Streamlit is installed."""

from __future__ import annotations

from pathlib import Path

import pytest

from qrypton.storage.sqlite import SqliteRunStore

streamlit = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP_PATH = str(Path(__file__).resolve().parents[2] / "src" / "qrypton" / "ui" / "app.py")


def test_streamlit_app_empty_db_falls_back_to_mock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "empty.sqlite3"
    SqliteRunStore(db_path)
    monkeypatch.setenv("QRYPTON_DB", str(db_path))
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert len(app.metric) >= 4


def test_streamlit_app_missing_db_falls_back_to_mock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_path = tmp_path / "nonexistent.sqlite3"
    monkeypatch.setenv("QRYPTON_DB", str(missing_path))
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert len(app.metric) >= 4


def test_streamlit_app_corrupted_db_falls_back_to_mock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corrupted = tmp_path / "corrupted.sqlite3"
    corrupted.write_text("NOT A SQLITE FILE")
    monkeypatch.setenv("QRYPTON_DB", str(corrupted))
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert len(app.metric) >= 4


def test_streamlit_app_renders_with_populated_run(
    populated_sqlite_store: tuple[SqliteRunStore, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, tenant_id, _run_id = populated_sqlite_store
    monkeypatch.setenv("QRYPTON_DB", str(store._path))
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant_id)
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert len(app.metric) >= 4
