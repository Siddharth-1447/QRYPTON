"""Shared fixtures for the workflow acceptance suite.

Every test runs against an isolated database and upload directory. Nothing here
touches the network unless a test is explicitly marked for remote acquisition.
"""

from __future__ import annotations

import io
import json
import os
import struct
import tarfile
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qrypton.api.app import app
from qrypton.storage.sqlite import SqliteRunStore

TENANT_ID = f"tenant_{'a' * 52}"

client = TestClient(app)


@pytest.fixture
def isolated_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[dict[str, Any]]:
    """Point the API at a fresh database and upload directory."""
    db_path = tmp_path / "workflows.sqlite3"
    uploads = tmp_path / "uploads"
    monkeypatch.setenv("QRYPTON_DB", str(db_path))
    monkeypatch.setenv("QRYPTON_UPLOADS", str(uploads))
    monkeypatch.setenv("QRYPTON_TENANT_ID", TENANT_ID)
    yield {"db": db_path, "uploads": uploads, "client": client, "tenant": TENANT_ID}


def scan_payload(**overrides: Any) -> dict[str, Any]:
    """Business context is identical for every target type (spec section 10)."""
    payload: dict[str, Any] = {
        "environment": "production",
        "business_criticality": "critical",
        "system_name": "workflow-acceptance",
        "owner": "team-crypto",
        "data_sensitivity": "restricted",
        "internet_exposure": True,
        "regulatory_relevance": "regulated",
        "migration_complexity": "high",
        "data_lifetime": 7,
        "migration_time": 4,
        "crqc_horizon": 8,
    }
    payload.update(overrides)
    return payload


def upload_artifact(name: str, data: bytes) -> dict[str, Any]:
    response = client.post("/api/v1/uploads", files={"file": (name, data)})
    assert response.status_code == 200, f"upload failed: {response.text[:300]}"
    return response.json()


def submit_scan(payload: dict[str, Any]) -> str:
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 200, f"scan submit failed: {response.text[:300]}"
    body = response.json()
    assert body["scan_id"], "scan response carried no run ID"
    return str(body["scan_id"])


def settle_scan(scan_id: str, timeout_seconds: int = 120) -> str:
    """Poll the existing scan-status route until the run settles."""
    deadline = time.monotonic() + timeout_seconds
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}").json()
        last = str(body["status"])
        if last in ("COMPLETED", "PARTIAL", "FAILED"):
            return last
        time.sleep(1)
    raise AssertionError(f"scan {scan_id} did not settle, last status {last}")


def fresh_store(db_path: Path) -> SqliteRunStore:
    """A brand-new repository instance over the same database file."""
    return SqliteRunStore(db_path)


def crypto_source_tree(root: Path) -> Path:
    """Deterministic source fixture with real cryptographic API usage."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "crypto_service.py").write_text(
        "import hashlib\n"
        "from Crypto.Cipher import AES\n"
        "from Crypto.PublicKey import RSA\n"
        "key = RSA.generate(2048)\n"
        "cipher = AES.new(b'0' * 16, AES.MODE_ECB)\n"
        "digest = hashlib.md5(b'x').hexdigest()\n",
        encoding="utf-8",
    )
    return root


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def build_wheel() -> tuple[str, bytes]:
    """A real .whl (zip) package artifact carrying cryptographic usage."""
    module = (
        "from Crypto.Cipher import AES\n"
        "from Crypto.PublicKey import RSA\n"
        "CIPHER = AES.new(b'0' * 16, AES.MODE_ECB)\n"
        "KEY = RSA.generate(2048)\n"
    )
    metadata = "Metadata-Version: 2.1\nName: demo-crypto-pkg\nVersion: 1.0.0\n"
    data = zip_bytes(
        {
            "demo_crypto_pkg/__init__.py": module.encode(),
            "demo_crypto_pkg-1.0.0.dist-info/METADATA": metadata.encode(),
            "demo_crypto_pkg-1.0.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
        }
    )
    return "demo_crypto_pkg-1.0.0-py3-none-any.whl", data


def build_docker_tar() -> tuple[str, bytes]:
    """A minimal docker-save-style tar archive with a crypto-bearing layer file."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as layer_tar:
        payload = b"const RSA = require('node-rsa');\nconst key = new RSA({b: 2048});\n"
        info = tarfile.TarInfo("app/crypto.js")
        info.size = len(payload)
        layer_tar.addfile(info, io.BytesIO(payload))
    manifest = json.dumps(
        [{"Config": "config.json", "RepoTags": ["demo/app:1.0"], "Layers": ["layer.tar"]}]
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as outer:
        for name, data in (
            ("manifest.json", manifest),
            ("config.json", b'{"architecture":"amd64"}'),
            ("layer.tar", layer.getvalue()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
    return "demo-app.tar", buffer.getvalue()


def build_minimal_elf(symbols: tuple[str, ...] = ("RSA_public_encrypt", "AES_encrypt")) -> bytes:
    """A minimal valid ELF64 whose symtab names real crypto imports.

    Parsed by the REAL format parser (no mocks): section type 2 (SYMTAB)
    entries with shndx == 0 classify as imports.
    """
    strtab = b"\x00" + b"\x00".join(s.encode() for s in symbols) + b"\x00"
    offsets = []
    cursor = 1
    for symbol in symbols:
        offsets.append(cursor)
        cursor += len(symbol.encode()) + 1
    entries = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    for off in offsets:
        entries.append(struct.pack("<IBBHQQ", off, 0x10, 0, 0, 0, 0))
    symtab = b"".join(entries)
    header_size, sh_size = 64, 64
    shoff = header_size
    symtab_off = shoff + 3 * sh_size
    strtab_off = symtab_off + len(symtab)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,
        62,
        1,
        0,
        0,
        shoff,
        0,
        header_size,
        0,
        0,
        sh_size,
        3,
        3,
    )
    null_section = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sym_section = struct.pack(
        "<IIQQQQIIQQ", 0, 2, 0, 0, symtab_off, len(symtab), 2, 0, 8, 24
    )
    str_section = struct.pack(
        "<IIQQQQIIQQ", 0, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0
    )
    return header + null_section + sym_section + str_section + symtab + strtab


def cbom_root(cbom_bytes: bytes) -> dict[str, Any]:
    document = json.loads(cbom_bytes)
    assert document["specVersion"] == "1.6"
    return document["metadata"]["component"]


def root_properties(root: dict[str, Any]) -> dict[str, str]:
    return {entry["name"]: entry["value"] for entry in root.get("properties", [])}


# Opt-in marker helper: remote acquisition tests never run by default, so the
# ordinary suite stays independent of GitHub availability.
needs_network = pytest.mark.skipif(
    os.environ.get("QRYPTON_RUN_NETWORK_TESTS") != "1",
    reason="remote acquisition test; set QRYPTON_RUN_NETWORK_TESTS=1 to run",
)
