"""Synthetic PE exports only: no real DLL is committed or executed."""

import asyncio
import re
import shutil
import struct
import subprocess
from io import BytesIO
from pathlib import Path

import pytest

from qrypton.scanners.binary.formats import _parse_pe, parse_binary
from qrypton.scanners.binary.scanner import LocalBinaryScanner
from tests.scanners.test_binary_scanner import _request

EXPECTED = ("AES_encrypt", "RSA_public_encrypt")


def image(*, pe64: bool = False) -> bytearray:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if pe64 else 224
    struct.pack_into("<HH", data, 0x84, 0x8664 if pe64 else 0x14C, 1)
    struct.pack_into("<HH", data, 0x94, optional_size, 0x210E)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1200)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + (108 if pe64 else 92), 16)
    directory = optional + (112 if pe64 else 96)
    struct.pack_into("<II", data, directory, 0x1000, 0x200)
    section = optional + optional_size
    struct.pack_into("<8sIIII", data, section, b".edata", 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    # IMAGE_EXPORT_DIRECTORY: functions/names counts, and three distinct tables.
    struct.pack_into("<IIIIII", data, 0x210, 1, 2, 2, 0x1040, 0x1050, 0x1060)
    struct.pack_into("<II", data, 0x240, 0x1200, 0x1220)
    struct.pack_into("<II", data, 0x250, 0x1080, 0x10A0)
    struct.pack_into("<HH", data, 0x260, 0, 1)
    data[0x280:0x293] = b"RSA_public_encrypt\0"
    data[0x2A0:0x2AC] = b"AES_encrypt\0"
    data[0x400:0x413] = b"\x90RSA_machine_code\xff\0"
    data[0x420:0x433] = b"\x90AES_machine_code\xff\0"
    return data


@pytest.mark.parametrize("pe64", [False, True])
def test_export_names_come_from_name_pointer_table(tmp_path: Path, pe64: bool) -> None:
    path = tmp_path / "synthetic.dll"
    path.write_bytes(image(pe64=pe64))
    assert parse_binary(path).exports == EXPECTED


@pytest.mark.parametrize(
    "damage", ["names_rva", "ordinals_rva", "name_rva", "ordinal", "nonascii", "identifier",
               "unterminated", "huge_count", "padding"]
)
def test_corrupt_exports_are_bounded_and_report_partial(tmp_path: Path, damage: str) -> None:
    data = image()
    if damage == "names_rva":
        struct.pack_into("<I", data, 0x220, 0xFFFFFFFF)
    elif damage == "ordinals_rva":
        struct.pack_into("<I", data, 0x224, 0xFFFFFFFF)
    elif damage == "name_rva":
        struct.pack_into("<I", data, 0x250, 0xFFFFFFFF)
    elif damage == "ordinal":
        struct.pack_into("<H", data, 0x260, 2)
    elif damage == "nonascii":
        data[0x280] = 0xFF
    elif damage == "identifier":
        data[0x281] = ord(" ")
    elif damage == "unterminated":
        data[0x280:] = b"A" * (len(data) - 0x280)
    elif damage == "huge_count":
        struct.pack_into("<I", data, 0x218, 0xFFFFFFFF)
    elif damage == "padding":
        struct.pack_into("<I", data, 0x180, 0xA00)  # VirtualSize exceeds raw bytes.
        struct.pack_into("<I", data, 0x250, 0x1700)
        data.extend(b"\0" * 0x100 + b"RSA_overlay\0" + b"\0" * 1024)
    path = tmp_path / "corrupt.dll"
    path.write_bytes(data)
    parsed = parse_binary(path)
    assert set(parsed.exports) <= set(EXPECTED)
    assert parsed.partial and parsed.warnings


def test_name_near_eof_is_read_with_a_bounded_length(tmp_path: Path) -> None:
    data = image()
    struct.pack_into("<I", data, 0x250, 0x15E0)
    data[0x7E0:0x7F3] = b"RSA_public_encrypt\0"
    path = tmp_path / "tail.dll"
    path.write_bytes(data)
    assert parse_binary(path).exports == EXPECTED


@pytest.mark.parametrize("length", [0, 1, 63, 0x81, 0x120, 0x180, 0x210, 0x280])
def test_truncated_pe_has_a_controlled_result(tmp_path: Path, length: int) -> None:
    path = tmp_path / "truncated.dll"
    path.write_bytes(image()[:length])
    try:
        parsed = parse_binary(path)
    except ValueError as error:
        assert str(error)
    else:
        assert parsed.partial and parsed.warnings
        assert set(parsed.exports) <= set(EXPECTED)


def test_huge_name_count_has_a_file_bounded_read_budget() -> None:
    class CountingStream(BytesIO):
        reads = 0

        def read(self, size: int | None = -1) -> bytes:
            self.reads += 1
            return super().read(size)

    data = image()
    struct.pack_into("<I", data, 0x218, 0xFFFFFFFF)
    stream = CountingStream(data)
    parsed = _parse_pe(stream, len(data))
    assert stream.reads < 2000
    assert parsed.partial


def test_export_parser_agrees_with_objdump(tmp_path: Path) -> None:
    executable = shutil.which("objdump")
    if executable is None:
        pytest.skip("objdump unavailable; no new development dependency installed")
    path = tmp_path / "crosscheck.dll"
    path.write_bytes(image())
    result = subprocess.run(
        [executable, "-p", str(path)], capture_output=True, text=True, check=True, timeout=10
    )
    names = set(re.findall(r"^\s*\[\s*\d+\]\s+(\S+)\s*$", result.stdout, re.MULTILINE))
    assert names == set(EXPECTED)
    assert set(parse_binary(path).exports) == names


def test_scanner_propagates_partial_export_evidence(tmp_path: Path) -> None:
    data = image()
    struct.pack_into("<I", data, 0x250, 0xFFFFFFFF)
    path = tmp_path / "partial.dll"
    path.write_bytes(data)
    scanner = LocalBinaryScanner(allowed_root=tmp_path)
    request = _request(path, max_file_bytes=len(data))

    async def collect() -> None:
        async for observation in scanner.scan(request):
            if observation.detector_type == "export":
                assert observation.attributes["subject_value"] in EXPECTED

    asyncio.run(collect())
    assert scanner.partial and scanner.warnings
