from __future__ import annotations

from pathlib import Path

from qrypton.ports.scanners import ScanLimits
from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from qrypton.scanners.source.traversal import SourceFile


def _limits() -> ScanLimits:
    return ScanLimits(
        max_compressed_bytes=1,
        max_expanded_bytes=1,
        max_file_count=100,
        max_nesting_depth=1,
        max_layer_count=1,
        max_ast_nodes=10_000,
        max_evidence_count=100,
        max_wall_time_seconds=10,
        max_memory_bytes=1_000_000,
    )


def _source(text: str) -> SourceFile:
    raw = text.encode("utf-8")
    return SourceFile(
        path=Path("legacy.py"),
        relative_path="legacy.py",
        raw_bytes=raw,
        digest=f"sha256:{'a' * 64}",
        language="python",
        text=text,
    )


def _subjects(text: str) -> set[str]:
    policy = SourceScanPolicy(allowed_root=Path.cwd())
    return {
        str(item.attributes["subject_value"])
        for item in analyze_python_ast(_source(text), policy=policy, limits=_limits())
        if item.attributes["subject_kind"] == "algorithm"
    }


def test_detects_hashlib_sha1() -> None:
    assert "sha-1" in _subjects("import hashlib\nhashlib.sha1(b'payload')\n")


def test_detects_pycryptodome_rsa_generate() -> None:
    assert "rsa" in _subjects("from Crypto.PublicKey import RSA\nRSA.generate(2048)\n")


def test_detects_cryptography_ec_generate_private_key() -> None:
    source = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
    )
    assert "ec" in _subjects(source)


def test_ignores_crypto_names_in_comments_and_strings() -> None:
    assert not _subjects("# hashlib.sha1(b'not-called')\nmessage = 'RSA.generate(2048)'\n")
