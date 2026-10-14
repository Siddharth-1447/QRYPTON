"""End-to-end tests for the Streamlit dashboard using AppTest when Streamlit is installed."""

from __future__ import annotations

from pathlib import Path

import pytest

from qrypton.storage.sqlite import SqliteRunStore

streamlit = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP_PATH = str(Path(__file__).resolve().parents[2] / "src" / "qrypton" / "ui" / "app.py")


@pytest.fixture(scope="session", autouse=True)
def warm_streamlit_app(tmp_path_factory: pytest.TempPathFactory) -> None:
    db_path = tmp_path_factory.mktemp("streamlit-warmup") / "empty.sqlite3"
    store = SqliteRunStore(db_path)
    store.close()
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("QRYPTON_DB", str(db_path))
        patch.delenv("QRYPTON_DEMO_MODE", raising=False)
        app = AppTest.from_file(APP_PATH, default_timeout=30).run()
    assert not app.exception


def test_streamlit_app_empty_db_shows_no_scan_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "empty.sqlite3"
    store = SqliteRunStore(db_path)
    store.close()
    monkeypatch.setenv("QRYPTON_DB", str(db_path))
    monkeypatch.delenv("QRYPTON_DEMO_MODE", raising=False)
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert not app.metric
    assert any("No scan data yet" in item.value for item in app.info)
    assert not any("Demo Mode" in item.value for item in app.sidebar.info)


def test_streamlit_app_missing_db_shows_sanitized_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_path = tmp_path / "nonexistent.sqlite3"
    monkeypatch.setenv("QRYPTON_DB", str(missing_path))
    monkeypatch.delenv("QRYPTON_DEMO_MODE", raising=False)
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert not app.metric
    assert any("ERR_STORAGE_CONNECT" in item.value for item in app.error)
    assert all(str(missing_path) not in item.value for item in app.error)
    assert not missing_path.exists()


def test_streamlit_app_corrupted_db_shows_sanitized_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corrupted = tmp_path / "corrupted.sqlite3"
    corrupted.write_text("NOT A SQLITE FILE")
    monkeypatch.setenv("QRYPTON_DB", str(corrupted))
    monkeypatch.delenv("QRYPTON_DEMO_MODE", raising=False)
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert not app.metric
    assert any("ERR_STORAGE_CONNECT" in item.value for item in app.error)
    assert all(str(corrupted) not in item.value for item in app.error)


def test_streamlit_app_mock_data_requires_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QRYPTON_DB", str(tmp_path / "missing.sqlite3"))
    monkeypatch.setenv("QRYPTON_DEMO_MODE", "1")
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert len(app.metric) >= 4
    assert any("Demo Mode" in item.value for item in app.sidebar.info)


def test_streamlit_app_renders_with_populated_run(
    populated_sqlite_store: tuple[SqliteRunStore, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, tenant_id, _run_id = populated_sqlite_store
    monkeypatch.setenv("QRYPTON_DB", str(store._path))
    monkeypatch.delenv("QRYPTON_DEMO_MODE", raising=False)
    monkeypatch.setenv("QRYPTON_TENANT_ID", tenant_id)
    app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not app.exception
    assert "QRYPTON Enterprise Cryptographic Dashboard" in app.title[0].value
    assert len(app.metric) >= 4
