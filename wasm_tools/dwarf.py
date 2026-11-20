"""DWARF line-table parsing for wasm modules (phase 1: function-level source
mapping).

Wasm embeds DWARF as custom sections named like the ELF sections
(`` .debug_line``, ``.debug_info`` and friends), with one format deviation
that matters here: code addresses are offsets into the code section
(tool-conventions Dwarf.md), so mapping a function to source is a lookup of
the function's code-relative start address in the line program rows.

Phase 1 implements the line-program state machine for DWARF versions 2
through 5: special opcodes, the standard opcodes, the extended opcodes
(end_sequence, set_address, define_file), and the v5 directory and file
entry formats (inline strings, ``DW_FORM_line_strp`` into
``.debug_line_str``, and udata forms). 64-bit DWARF initial lengths, and
the exotic v5 forms (strp into .debug_str for line tables is resolved from
.debug_str when the payload is supplied), degrade gracefully: anything the
subset cannot parse yields ``None`` plus an error string rather than a
wrong mapping.

Every mapping asserts against the parsed rows; when the rows are absent,
malformed, or do not cover a function's address, no source is emitted for
that function. A wrong mapping is worse than none.
"""

from __future__ import annotations

import bisect
from typing import Any, Optional

# Total retained DWARF payload budget per module (unstripped builds ship
# multi-megabyte DWARF; retention past this cap stops with a note rather
# than ballooning the report process).
MAX_DWARF_RETENTION = 8 * 1024 * 1024



class _DwarfParseError(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)
        self.offset = 0

    def ensure(self, n: int) -> None:
        if self.offset + n > self.size:
            raise _DwarfParseError("unexpected end of DWARF payload")

    def read_u8(self) -> int:
        self.ensure(1)
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u16(self) -> int:
        self.ensure(2)
        value = int.from_bytes(self.data[self.offset : self.offset + 2], "little")
        self.offset += 2
        return value

    def read_u32(self) -> int:
        self.ensure(4)
        value = int.from_bytes(self.data[self.offset : self.offset + 4], "little")
        self.offset += 4
        return value

    def read_s8(self) -> int:
        value = self.read_u8()
        return value - 256 if value >= 128 else value

    def read_uleb(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if shift > 63:
                raise _DwarfParseError("LEB128 exceeds maximum length")
            if not (byte & 0x80):
                return result

    def read_sleb(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                if byte & 0x40 and shift < 64:
                    result -= 1 << shift
                return result

    def read_cstr(self) -> str:
        end = self.data.find(b"\x00", self.offset)
        if end < 0:
            raise _DwarfParseError("unterminated string")
        raw = self.data[self.offset : end]
        self.offset = end + 1
        return raw.decode("utf-8", errors="replace")

    def read_initial_length(self) -> tuple[int, int]:
        """Return (length, offset_after_length_field); handles 64-bit DWARF."""
        value = self.read_u32()
        if value == 0xFFFFFFFF:
            return self._read_u64(), self.offset
        if value >= 0xFFFFFFF0:
            raise _DwarfParseError("reserved initial length")
        return value, self.offset

    def read_offset(self, size: int) -> int:
        """A section offset or length field: 4 bytes, or 8 in 64-bit DWARF."""
        self.ensure(size)
        value = int.from_bytes(self.data[self.offset : self.offset + size], "little")
        self.offset += size
        return value

    def _read_u64(self) -> int:
        self.ensure(8)
        value = int.from_bytes(self.data[self.offset : self.offset + 8], "little")
        self.offset += 8
        return value


#: Most line rows kept per module; a hostile or huge table stops here and
#: the result says ``truncated``.
MAX_LINE_ROWS = 500_000

# DW_LNCT content types and DW_FORM codes used by v5 entry formats.
_LNCT_PATH = 0x1
_LNCT_DIRECTORY_INDEX = 0x2
_FORM_BLOCK = 0x09
_FORM_DATA1 = 0x0B
_FORM_DATA2 = 0x05
_FORM_DATA4 = 0x06
_FORM_DATA8 = 0x07
_FORM_DATA16 = 0x1E
_FORM_LINE_STRP = 0x1F
_FORM_STRING = 0x08
_FORM_STRP = 0x0E
_FORM_UDATA = 0x0F


def parse_line_program(
    payload: bytes,
    line_str: Optional[bytes] = None,
    debug_str: Optional[bytes] = None,
    max_rows: int = MAX_LINE_ROWS,
) -> Optional[dict[str, Any]]:
    """Parse every line-program unit of a ``.debug_line`` payload.

    Returns ``{"version": v, "units": n, "files": [{"unit", "index",
    "path"}], "rows": [{"address", "file", "line"}], "truncated": bool}``
    or None when the first unit does not parse. ``version`` is the first
    unit's. Row ``file`` is the resolved path, since file indices are only
    meaningful inside their unit; the row that closes a sequence carries
    ``"end_sequence": True`` and marks the first address past it. A later
    unit that fails to parse ends the walk and keeps the rows before it.
    Wasm has no VLIW bundles, so ``maximum_operations_per_instruction`` is
    treated as one.
    """
    reader = _Reader(payload)
    result: dict[str, Any] = {
        "version": None,
        "units": 0,
        "files": [],
        "rows": [],
        "truncated": False,
    }
    while reader.offset < reader.size:
        try:
            unit = _parse_unit(reader, line_str, debug_str, result, max_rows)
        except _DwarfParseError:
            if result["units"] == 0:
                return None
            break
        if unit is None:
            break
        result["units"] += 1
        if result["version"] is None:
            result["version"] = unit
        if result["truncated"]:
            break
    if result["units"] == 0:
        return None
    return result


def _parse_unit(
    reader: _Reader,
    line_str: Optional[bytes],
    debug_str: Optional[bytes],
    result: dict[str, Any],
    max_rows: int,
) -> Optional[int]:
    """Parse one unit at ``reader.offset``, appending its files and rows to
    ``result``; returns the unit's version, None for a zero-length tail."""
    unit_start = reader.offset
    unit_length, after_length = reader.read_initial_length()
    if unit_length == 0:
        return None
    # 64-bit DWARF: a 12-byte initial length, and 8-byte offset fields.
    offset_size = 8 if after_length - unit_start == 12 else 4
    program_end = after_length + unit_length
    if program_end > reader.size:
        raise _DwarfParseError("unit length exceeds payload")
    unit_index = result["units"]
    version = reader.read_u16()
    if version < 2 or version > 5:
        raise _DwarfParseError(f"unsupported DWARF version {version}")
    if version >= 5:
        reader.read_u8()  # address_size
        reader.read_u8()  # segment_selector_size
    header_length = reader.read_offset(offset_size)
    # header_length counts from just after the field to the program start.
    program_start = reader.offset + header_length
    if program_start > program_end:
        raise _DwarfParseError("header length exceeds unit")
    minimum_instruction_length = reader.read_u8()
    if version >= 4:
        reader.read_u8()  # maximum_operations_per_instruction
    reader.read_u8()  # default_is_stmt
    line_base = reader.read_s8()
    line_range = reader.read_u8()
    opcode_base = reader.read_u8()
    if opcode_base < 1:
        raise _DwarfParseError("opcode base must be positive")
    if line_range == 0:
        raise _DwarfParseError("line range must be positive")
    standard_lengths = [reader.read_u8() for _ in range(opcode_base - 1)]

    paths: dict[int, str] = {}
    if version <= 4:
        # v2-v4: directory 0 and file 0 are implicit; tables are 1-based.
        directories: list[str] = []
        while True:
            directory = reader.read_cstr()
            if directory == "":
                break
            directories.append(directory)
        file_index = 1
        while True:
            name = reader.read_cstr()
            if name == "":
                break
            directory_index = reader.read_uleb()
            reader.read_uleb()  # mtime
            reader.read_uleb()  # length
            paths[file_index] = _join_path(_v4_directory(directories, directory_index), name)
            file_index += 1
    else:
        # v5: directory 0 is the compilation directory and file indices are
        # zero-based; both tables are described by entry format lists.
        dir_formats = _read_formats(reader)
        directories = [
            str(_read_v5_entry(reader, dir_formats, line_str, debug_str, offset_size).get(_LNCT_PATH, ""))
            for _ in range(reader.read_uleb())
        ]
        file_formats = _read_formats(reader)
        for index in range(reader.read_uleb()):
            entry = _read_v5_entry(reader, file_formats, line_str, debug_str, offset_size)
            name = str(entry.get(_LNCT_PATH, ""))
            directory_index = entry.get(_LNCT_DIRECTORY_INDEX, 0)
            directory = (
                directories[directory_index]
                if isinstance(directory_index, int) and 0 <= directory_index < len(directories)
                else ""
            )
            paths[index] = _join_path(directory, name)
    for index, path in paths.items():
        result["files"].append({"unit": unit_index, "index": index, "path": path})

    rows = result["rows"]
    reader.offset = program_start
    address = 0
    file_index = 1
    line = 1

    def emit(end_sequence: bool = False) -> None:
        if len(rows) >= max_rows:
            result["truncated"] = True
            raise _StopProgram
        row: dict[str, Any] = {"address": address, "file": paths.get(file_index, ""), "line": line}
        if end_sequence:
            row["end_sequence"] = True
        rows.append(row)

    try:
        while reader.offset < program_end:
            opcode = reader.read_u8()
            if opcode >= opcode_base:
                adjusted = opcode - opcode_base
                address += minimum_instruction_length * (adjusted // line_range)
                line += line_base + (adjusted % line_range)
                emit()
            elif opcode == 0x00:
                length = reader.read_uleb()
                extended_end = reader.offset + length
                if length == 0 or extended_end > program_end:
                    raise _DwarfParseError("extended opcode exceeds program")
                sub_opcode = reader.read_u8()
                if sub_opcode == 0x01:  # end_sequence
                    emit(end_sequence=True)
                    address = 0
                    file_index = 1
                    line = 1
                elif sub_opcode == 0x02:  # set_address
                    address = int.from_bytes(reader.data[reader.offset : extended_end], "little")
                elif sub_opcode == 0x03 and version <= 4:  # define_file
                    name = reader.read_cstr()
                    directory_index = reader.read_uleb()
                    new_index = max(paths, default=0) + 1
                    paths[new_index] = _join_path(_v4_directory(directories, directory_index), name)
                    result["files"].append({"unit": unit_index, "index": new_index, "path": paths[new_index]})
                reader.offset = extended_end
            elif opcode == 0x01:  # copy
                emit()
            elif opcode == 0x02:  # advance_pc
                address += reader.read_uleb() * minimum_instruction_length
            elif opcode == 0x03:  # advance_line
                line += reader.read_sleb()
            elif opcode == 0x04:  # set_file
                file_index = reader.read_uleb()
            elif opcode == 0x08:  # const_add_pc
                address += minimum_instruction_length * ((255 - opcode_base) // line_range)
            elif opcode == 0x09:  # fixed_advance_pc
                address += reader.read_u16()
            else:
                # set_column, negate_stmt, set_basic_block, prologue_end,
                # epilogue_begin, set_isa and any later standard opcode:
                # skip the ULEB operands the header declares for it.
                for _ in range(standard_lengths[opcode - 1]):
                    reader.read_uleb()
    except _StopProgram:
        pass
    reader.offset = program_end
    return version


class _StopProgram(Exception):
    """Raised by the row emitter when the row cap is reached."""


def _read_formats(reader: _Reader) -> list[tuple[int, int]]:
    return [(reader.read_uleb(), reader.read_uleb()) for _ in range(reader.read_u8())]


def _read_v5_entry(
    reader: _Reader,
    formats: list[tuple[int, int]],
    line_str: Optional[bytes],
    debug_str: Optional[bytes],
    offset_size: int,
) -> dict[int, Any]:
    """Read one v5 directory or file entry: ``{content type: value}``."""
    values: dict[int, Any] = {}
    for content_type, form in formats:
        if form == _FORM_STRING:
            value: Any = reader.read_cstr()
        elif form == _FORM_LINE_STRP:
            value = _string_at(line_str, reader.read_offset(offset_size))
        elif form == _FORM_STRP:
            value = _string_at(debug_str, reader.read_offset(offset_size))
        elif form == _FORM_UDATA:
            value = reader.read_uleb()
        elif form == _FORM_DATA1:
            value = reader.read_u8()
        elif form == _FORM_DATA2:
            value = reader.read_u16()
        elif form == _FORM_DATA4:
            value = reader.read_u32()
        elif form == _FORM_DATA8:
            value = reader.read_offset(8)
        elif form == _FORM_DATA16:
            reader.ensure(16)
            reader.offset += 16
            value = None
        elif form == _FORM_BLOCK:
            length = reader.read_uleb()
            reader.ensure(length)
            reader.offset += length
            value = None
        else:
            raise _DwarfParseError(f"unsupported v5 form {form:#x}")
        values[content_type] = value
    return values


def _string_at(payload: Optional[bytes], offset: int) -> str:
    if payload is None or offset >= len(payload):
        return ""
    end = payload.find(b"\x00", offset)
    if end < 0:
        end = len(payload)
    return payload[offset:end].decode("utf-8", errors="replace")


def _v4_directory(directories: list[str], directory_index: int) -> str:
    # Index 0 is the compilation directory, which the v4 header does not
    # name, so such a file keeps its bare name.
    if 1 <= directory_index <= len(directories):
        return directories[directory_index - 1]
    return ""


def _join_path(directory: str, name: str) -> str:
    if not name:
        return ""
    if not directory or name.startswith("/"):
        return name
    return f"{directory.rstrip('/')}/{name}"


def map_function_sources(
    line_table: dict[str, Any],
    function_addresses: list[tuple[int, int]],
) -> dict[int, dict[str, Any]]:
    """Map (function index, code-relative address) pairs to source locations.

    Rows are split into sequences at their end_sequence rows. A function maps
    only when its address lies inside a sequence (at or after its first row
    and before its end row), to the last row at or before the address. An
    address outside every sequence, or whose row names no file, gets no
    mapping. Sequences are indexed once, so the cost is
    O((rows + functions) log rows).
    """
    sequences: list[tuple[int, int, list[int], list[dict[str, Any]]]] = []
    current: list[dict[str, Any]] = []
    for row in line_table.get("rows") or []:
        if row.get("end_sequence"):
            if current:
                addresses = [r["address"] for r in current]
                if addresses == sorted(addresses):
                    sequences.append((addresses[0], row["address"], addresses, current))
            current = []
        else:
            current.append(row)
    sequences.sort(key=lambda seq: seq[0])
    starts = [seq[0] for seq in sequences]

    sources: dict[int, dict[str, Any]] = {}
    for function_index, code_address in function_addresses:
        position = bisect.bisect_right(starts, code_address) - 1
        # Sequences may overlap; walk back over those that start at or
        # before the address until one contains it.
        while position >= 0:
            start, end, addresses, seq_rows = sequences[position]
            if start <= code_address < end:
                row = seq_rows[bisect.bisect_right(addresses, code_address) - 1]
                if row["file"]:
                    sources[function_index] = {"file": row["file"], "line": row["line"]}
                break
            position -= 1
    return sources


def parse_debug_info_units(payload: bytes) -> Optional[list[dict[str, Any]]]:
    """Parse ``.debug_info`` unit headers only (no DIE tree decode).

    Returns unit version and payload offset per unit, which is enough for
    the compilation-units summary without abbrev parsing.
    """
    try:
        reader = _Reader(payload)
        units: list[dict[str, Any]] = []
        while reader.offset < reader.size:
            unit_length, after_length = reader.read_initial_length()
            if unit_length <= 4 or after_length + unit_length > reader.size:
                break
            version = reader.read_u16()
            units.append(
                {
                    "offset": after_length - 4,
                    "version": version,
                    "size": unit_length,
                }
            )
            reader.offset = after_length + unit_length
        return units
    except _DwarfParseError:
        return None
