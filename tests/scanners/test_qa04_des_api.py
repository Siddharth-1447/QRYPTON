"""DES API identities and literal parameters; inputs are parsed, never executed."""

from pathlib import Path

import pytest

from qrypton.scanners.source.policy import SourceScanPolicy
from qrypton.scanners.source.python_ast import analyze_python_ast
from tests.scanners.test_python_ast import _limits, _source


def algorithms(text: str) -> list[dict[str, str | int | float | bool | None]]:
    return [
        dict(item.attributes)
        for item in analyze_python_ast(
            _source(text), policy=SourceScanPolicy(allowed_root=Path.cwd()), limits=_limits()
        )
        if item.attributes["subject_kind"] == "algorithm"
    ]


@pytest.mark.parametrize(
    ("cipher", "identity", "length", "bits"),
    [("DES3", "3des", 24, 192), ("DES3", "3des", 16, 128), ("DES", "des", 8, 64)],
)
def test_des_api_literal_parameters(cipher: str, identity: str, length: int, bits: int) -> None:
    rows = algorithms(
        f"from Crypto.Cipher import {cipher}\n"
        f"{cipher}.new(b'x' * {length}, {cipher}.MODE_CBC, iv)\n"
    )
    assert len(rows) == 1
    assert rows[0]["subject_value"] == identity
    assert rows[0]["mode"] == "CBC"
    assert rows[0]["key_size_bits"] == bits


@pytest.mark.parametrize("mode", ["selected_mode", "choose_mode()", "2", "'CBC'"])
def test_des3_unresolved_mode_stays_unknown(mode: str) -> None:
    rows = algorithms(f"from Crypto.Cipher import DES3\nDES3.new(key, {mode}, iv)\n")
    assert len(rows) == 1 and rows[0]["subject_value"] == "3des"
    assert rows[0].get("mode") is None
    assert rows[0].get("key_size_bits") is None


@pytest.mark.parametrize(
    "text",
    [
        "from Crypto.Cipher import AES\nAES.new(key, AES.MODE_CBC, iv)",
        "import cryptography",
        "crypt_helper = object()\ncrypt_helper.encrypt(data)",
        "import cryptography\ncryptography.unrecognized(data)",
        "other.CryptEncrypt(key, data)",
    ],
)
def test_crypto_names_do_not_imply_windows_capi(text: str) -> None:
    assert all(row["subject_value"] != "windows-capi" for row in algorithms(text))


def test_exact_windows_cryptoapi_call_is_preserved() -> None:
    rows = algorithms("import ctypes\nctypes.windll.advapi32.CryptEncrypt(key, data)")
    assert [row["subject_value"] for row in rows] == ["windows-capi"]
