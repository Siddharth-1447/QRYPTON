"""Small, defensive parsers for metadata needed by executable crypto discovery."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal


@dataclass(frozen=True, slots=True)
class BinarySection:
    name: str
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class ParsedBinary:
    format: Literal["elf", "pe", "mach_o"]
    imports: tuple[str, ...]
    exports: tuple[str, ...]
    libraries: tuple[str, ...]
    sections: tuple[BinarySection, ...]


def _read_at(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
        return b""
    stream.seek(offset)
    return stream.read(size)


def _cstr(blob: bytes, offset: int, *, limit: int = 1024) -> str:
    if not 0 <= offset < len(blob):
        return ""
    value = blob[offset : offset + limit].split(b"\0", 1)[0]
    return value.decode("ascii", errors="ignore")


def parse_binary(path: Path) -> ParsedBinary:
    """Identify and parse a regular executable image; reject malformed layouts safely."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        magic = _read_at(stream, 0, 4, size)
        if magic == b"\x7fELF":
            return _parse_elf(stream, size)
        if magic[:2] == b"MZ":
            return _parse_pe(stream, size)
        if magic in {
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce",
        }:
            return _parse_macho(stream, size)
    raise ValueError("unsupported executable format")


def _parse_elf(stream: BinaryIO, size: int) -> ParsedBinary:
    ident = _read_at(stream, 0, 16, size)
    if len(ident) != 16 or ident[4] not in (1, 2) or ident[5] not in (1, 2):
        raise ValueError("invalid ELF header")
    endian = "<" if ident[5] == 1 else ">"
    is64 = ident[4] == 2
    header_fmt = endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    header = _read_at(stream, 16, struct.calcsize(header_fmt), size)
    if len(header) != struct.calcsize(header_fmt):
        raise ValueError("truncated ELF header")
    fields = struct.unpack(header_fmt, header)
    shoff, shentsize, shnum, shstrndx = (
        (fields[5], fields[10], fields[11], fields[12])
        if is64
        else (fields[5], fields[10], fields[11], fields[12])
    )
    if shnum > 4096 or shentsize < (64 if is64 else 40) or shoff > size:
        raise ValueError("invalid ELF section table")
    raw_headers = _read_at(stream, shoff, shentsize * shnum, size)
    if len(raw_headers) != shentsize * shnum:
        raise ValueError("truncated ELF section table")
    fmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    parsed = [
        struct.unpack(
            fmt, raw_headers[index * shentsize : index * shentsize + struct.calcsize(fmt)]
        )
        for index in range(shnum)
    ]
    names = (
        _read_at(stream, parsed[shstrndx][4], parsed[shstrndx][5], size)
        if shstrndx < shnum
        else b""
    )
    sections = tuple(
        BinarySection(_cstr(names, item[0]), item[4], item[5])
        for item in parsed
        if item[4] <= size and item[5] <= size - item[4]
    )
    imports: list[str] = []
    exports: list[str] = []
    libraries: list[str] = []
    for item in parsed:
        typ, offset, length, link, entsize = item[1], item[4], item[5], item[6], item[9]
        if typ not in (2, 11) or not entsize or link >= shnum:
            continue
        strings = _read_at(stream, parsed[link][4], parsed[link][5], size)
        table = _read_at(stream, offset, length, size)
        name_width = 4
        for position in range(0, len(table) - entsize + 1, entsize):
            name_offset = struct.unpack(endian + "I", table[position : position + name_width])[0]
            name = _cstr(strings, name_offset)
            if name:
                shndx_offset = 6 if is64 else 14
                shndx = struct.unpack(
                    endian + "H", table[position + shndx_offset : position + shndx_offset + 2]
                )[0]
                (imports if shndx == 0 else exports).append(name)
    for item in parsed:
        if item[1] != 6 or item[6] >= shnum:  # SHT_DYNAMIC
            continue
        strings = _read_at(stream, parsed[item[6]][4], parsed[item[6]][5], size)
        width = 16 if is64 else 8
        table = _read_at(stream, item[4], item[5], size)
        for position in range(0, len(table) - width + 1, width):
            tag, value = struct.unpack(
                endian + ("qQ" if is64 else "iI"), table[position : position + width]
            )
            if tag == 1:
                name = _cstr(strings, value)
                if name:
                    libraries.append(name)
    return ParsedBinary("elf", tuple(imports), tuple(exports), tuple(libraries), sections)


def _parse_pe(stream: BinaryIO, size: int) -> ParsedBinary:
    dos = _read_at(stream, 0, 64, size)
    if len(dos) < 64:
        raise ValueError("truncated DOS header")
    pe_offset = struct.unpack_from("<I", dos, 60)[0]
    header = _read_at(stream, pe_offset, 24, size)
    if header[:4] != b"PE\0\0" or len(header) != 24:
        raise ValueError("invalid PE header")
    section_count, optional_size = struct.unpack_from("<HH", header, 6)
    if section_count > 4096:
        raise ValueError("invalid PE section count")
    optional = _read_at(stream, pe_offset + 24, optional_size, size)
    if len(optional) < 2:
        raise ValueError("truncated PE optional header")
    magic = struct.unpack_from("<H", optional)[0]
    directory_offset = 112 if magic == 0x20B else 96
    directories = optional[directory_offset : directory_offset + 16]
    sections_raw = _read_at(stream, pe_offset + 24 + optional_size, section_count * 40, size)
    sections: list[BinarySection] = []
    mappings: list[tuple[int, int, int]] = []
    for position in range(0, len(sections_raw), 40):
        name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<8sIIII", sections_raw, position
        )
        sections.append(BinarySection(_cstr(name, 0, limit=8), raw_offset, raw_size))
        mappings.append((virtual_address, max(virtual_size, raw_size), raw_offset))

    def rva_to_offset(rva: int) -> int | None:
        for start, length, offset in mappings:
            if start <= rva < start + length:
                candidate = offset + rva - start
                return candidate if candidate < size else None
        return rva if rva < size else None

    imports: list[str] = []
    exports: list[str] = []
    libraries: list[str] = []
    if len(directories) >= 16:
        import_rva, _ = struct.unpack_from("<II", directories, 8)
        import_offset = rva_to_offset(import_rva)
        if import_offset is not None:
            for index in range(4096):
                entry = _read_at(stream, import_offset + index * 20, 20, size)
                if len(entry) != 20 or entry == b"\0" * 20:
                    break
                thunk, _, _, name_rva, first_thunk = struct.unpack("<IIIII", entry)
                name_offset = rva_to_offset(name_rva)
                library = _cstr(_read_at(stream, name_offset or size, 1024, size), 0)
                if library:
                    libraries.append(library)
                thunk_offset = rva_to_offset(thunk or first_thunk)
                if thunk_offset is None:
                    continue
                width, ordinal_mask = (8, 1 << 63) if magic == 0x20B else (4, 1 << 31)
                for item_index in range(65536):
                    data = _read_at(stream, thunk_offset + item_index * width, width, size)
                    if len(data) != width:
                        break
                    value = int.from_bytes(data, "little")
                    if value == 0:
                        break
                    if value & ordinal_mask:
                        continue
                    symbol_offset = rva_to_offset(value)
                    symbol = _cstr(_read_at(stream, (symbol_offset or size) + 2, 1024, size), 0)
                    if symbol:
                        imports.append(symbol)
        export_rva, _ = struct.unpack_from("<II", directories, 0)
        export_offset = rva_to_offset(export_rva)
        export_directory = _read_at(stream, export_offset or size, 40, size)
        if len(export_directory) == 40:
            name_count, names_rva = struct.unpack_from("<II", export_directory, 24)
            names_offset = rva_to_offset(names_rva)
            if names_offset is not None:
                for index in range(min(name_count, 1_000_000)):
                    name_rva_blob = _read_at(stream, names_offset + index * 4, 4, size)
                    if len(name_rva_blob) != 4:
                        break
                    name_offset = rva_to_offset(struct.unpack("<I", name_rva_blob)[0])
                    name = _cstr(_read_at(stream, name_offset or size, 1024, size), 0)
                    if name:
                        exports.append(name)
    return ParsedBinary("pe", tuple(imports), tuple(exports), tuple(libraries), tuple(sections))


def _parse_macho(stream: BinaryIO, size: int) -> ParsedBinary:
    magic = _read_at(stream, 0, 4, size)
    endian = ">" if magic in {b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"} else "<"
    is64 = magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}
    header_size = 32 if is64 else 28
    header = _read_at(stream, 0, header_size, size)
    if len(header) != header_size:
        raise ValueError("truncated Mach-O header")
    command_count, command_bytes = struct.unpack_from(endian + "II", header, 16)
    if command_count > 4096 or command_bytes > size - header_size:
        raise ValueError("invalid Mach-O load commands")
    cursor, end = header_size, header_size + command_bytes
    libraries: list[str] = []
    imports: list[str] = []
    exports: list[str] = []
    sections: list[BinarySection] = []
    symtab: tuple[int, int, int, int] | None = None
    for _ in range(command_count):
        command = _read_at(stream, cursor, 8, size)
        if len(command) != 8:
            break
        kind, length = struct.unpack(endian + "II", command)
        if length < 8 or cursor + length > end:
            raise ValueError("invalid Mach-O command")
        payload = _read_at(stream, cursor, length, size)
        if kind in {0xC, 0x18, 0x8000001C} and len(payload) >= 24:
            name_offset = struct.unpack_from(endian + "I", payload, 8)[0]
            name = _cstr(payload, name_offset)
            if name:
                libraries.append(name)
        elif kind == 0x2 and len(payload) >= 24:
            symtab = struct.unpack_from(endian + "IIII", payload, 8)
        elif kind in {0x1, 0x19}:  # LC_SEGMENT[_64]
            section_offset = 72 if kind == 0x19 else 56
            section_size = 80 if kind == 0x19 else 68
            count = struct.unpack_from(endian + "I", payload, 64 if kind == 0x19 else 48)[0]
            for index in range(count):
                start = section_offset + index * section_size
                if start + section_size > len(payload):
                    break
                name = _cstr(payload[start : start + 16], 0, limit=16)
                offset = struct.unpack_from(
                    endian + "I", payload, start + (48 if kind == 0x19 else 40)
                )[0]
                section_length = struct.unpack_from(
                    endian + ("Q" if kind == 0x19 else "I"), payload, start + 32
                )[0]
                sections.append(BinarySection(name, offset, section_length))
        cursor += length
    if symtab is not None:
        symbol_offset, symbol_count, string_offset, string_size = symtab
        strings = _read_at(stream, string_offset, string_size, size)
        width = 16 if is64 else 12
        for index in range(min(symbol_count, 1_000_000)):
            entry = _read_at(stream, symbol_offset + index * width, width, size)
            if len(entry) != width:
                break
            name = _cstr(strings, struct.unpack_from(endian + "I", entry)[0])
            if name:
                n_type = entry[4]
                (imports if n_type & 0x0E == 0 else exports).append(name.lstrip("_"))
    return ParsedBinary("mach_o", tuple(imports), tuple(exports), tuple(libraries), tuple(sections))
