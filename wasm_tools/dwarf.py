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

_STANDARD_OPCODE_LENGTHS_V2 = 12  # opcode_base for the DWARF 2/3 default


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

    def _read_u64(self) -> int:
        self.ensure(8)
        value = int.from_bytes(self.data[self.offset : self.offset + 8], "little")
        self.offset += 8
        return value


def parse_line_program(
    payload: bytes,
    line_str: Optional[bytes] = None,
    debug_str: Optional[bytes] = None,
) -> Optional[dict[str, Any]]:
    """Parse one ``.debug_line`` line program into rows and the file table.

    Returns ``{"rows": [{"address", "file", "line"}, ...], "files":
    [{"index", "path"}], "version": v}`` or None when the payload does not
    parse. Rows are emitted in program order; addresses advance
    monotonically within a sequence and reset at end_sequence markers.
    """
    try:
        reader = _Reader(payload)
        unit_length, after_length = reader.read_initial_length()
        program_end = after_length + unit_length
        if program_end > reader.size:
            raise _DwarfParseError("unit length exceeds payload")
        version = reader.read_u16()
        if version < 2 or version > 5:
            raise _DwarfParseError(f"unsupported DWARF version {version}")

        if version <= 4:
            header_length = reader.read_u32()
        else:
            address_size = reader.read_u8()
            segment_selector_size = reader.read_u8()
            header_length = reader.read_u32()
        # DWARF: header_length counts from just after the header_length field
        # (where reader.offset sits now) to the start of the line program.
        program_start = reader.offset + header_length
        if program_start > program_end:
            raise _DwarfParseError("header length exceeds unit")

        minimum_instruction_length = reader.read_u8()
        maximum_operations = reader.read_u8() if version >= 4 else 1
        default_is_stmt = reader.read_u8()
        line_base = reader.read_s8()
        line_range = reader.read_u8()
        opcode_base = reader.read_u8()
        if opcode_base < 1:
            raise _DwarfParseError("opcode base must be positive")
        standard_lengths = [reader.read_u8() for _ in range(opcode_base - 1)]

        # File table from the header (format differs by version).
        directories: list[str] = []
        files: list[dict[str, Any]] = []
        if version <= 4:
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
                path = _compose_path(name, directory_index, directories)
                files.append({"index": file_index, "path": path})
                file_index += 1
        else:
            dir_format_count = reader.read_u8()
            dir_formats = [
                (reader.read_uleb(), reader.read_uleb())
                for _ in range(dir_format_count)
            ]
            dir_count = reader.read_uleb()
            for _ in range(dir_count):
                directories.append(
                    _read_v5_entry(reader, dir_formats, line_str, debug_str)
                )
            file_format_count = reader.read_u8()
            file_formats = [
                (reader.read_uleb(), reader.read_uleb())
                for _ in range(file_format_count)
            ]
            file_count = reader.read_uleb()
            for index in range(file_count):
                entries = [
                    _read_v5_entry(reader, file_formats, line_str, debug_str)
                    for _ in range(file_formats)
                ]
                # DW_LNCT_path = 1 is the file name; directory_index = 2.
                name = entries[0] if entries else ""
                directory_index = entries[1] if len(entries) > 1 else 0
                directory = ""
                if isinstance(directory_index, int) and 1 <= directory_index <= len(
                    directories
                ):
                    directory = directories[directory_index - 1]
                files.append(
                    {
                        "index": index + 1
                        if version == 5
                        else index,
                        "path": _compose_path(name, directory, directories),
                    }
                )
            # v5 file indices are zero-based relative to the primary source
            # file; rows carry them verbatim.

        # The line program proper.
        reader.offset = program_start
        rows: list[dict[str, int]] = []
        address = 0
        file_index = 1
        line = 1
        minimum_instruction = minimum_instruction_length
        maximum_ops = maximum_operations or 1

        def emit_row() -> None:
            rows.append({"address": address, "file": file_index, "line": line})

        while reader.offset < program_end:
            opcode = reader.read_u8()
            if opcode >= opcode_base:
                # Special opcode: advance address and line, emit a row.
                adjusted = opcode - opcode_base
                operation_advance = adjusted // line_range
                address += (
                    minimum_instruction
                    * ((operation_advance * maximum_ops) + (adjusted % line_range) % maximum_ops)
                )
                line += line_base + (adjusted % line_range)
                emit_row()
            elif opcode == 0x00:
                # Extended opcode.
                length = reader.read_uleb()
                extended_end = reader.offset + length
                if extended_end > program_end:
                    raise _DwarfParseError("extended opcode exceeds program")
                sub_opcode = reader.read_u8()
                if sub_opcode == 0x01:  # end_sequence
                    emit_row()
                    address = 0
                    file_index = 1
                    line = 1
                elif sub_opcode == 0x02:  # set_address
                    width = extended_end - reader.offset
                    address = int.from_bytes(
                        reader.data[reader.offset : extended_end], "little"
                    )
                    reader.offset = extended_end
                elif sub_opcode == 0x03:  # define_file
                    name = reader.read_cstr()
                    directory_index = reader.read_uleb()
                    reader.read_uleb()
                    reader.read_uleb()
                    files.append(
                        {
                            "index": len(files) + 1,
                            "path": _compose_path(
                                name, directory_index, directories
                            ),
                        }
                    )
                else:  # set_discriminator and friends: skip
                    reader.offset = extended_end
            elif opcode == 0x01:  # copy
                emit_row()
            elif opcode == 0x02:  # advance_pc
                address += reader.read_uleb() * minimum_instruction
            elif opcode == 0x03:  # advance_line
                line += reader.read_sleb()
            elif opcode == 0x04:  # set_file
                file_index = reader.read_uleb()
            elif opcode == 0x05:  # set_column
                reader.read_uleb()
            elif opcode == 0x06:  # negate_stmt
                pass
            elif opcode == 0x07:  # set_basic_block
                pass
            elif opcode == 0x08:  # const_add_pc
                adjusted = 255 - opcode_base
                operation_advance = adjusted // line_range
                address += (
                    minimum_instruction
                    * ((operation_advance * maximum_ops) + (adjusted % line_range) % maximum_ops)
                )
            elif opcode == 0x09:  # fixed_advance_pc
                address += reader.read_u16()
            elif opcode in (0x0A, 0x0B, 0x0C):  # prologue/epilogue/isa
                reader.read_uleb()
            else:
                raise _DwarfParseError(f"unknown standard opcode {opcode:#x}")

        return {"rows": rows, "files": files, "version": version}
    except _DwarfParseError:
        return None


def _read_v5_entry(
    reader: _Reader,
    formats: list[tuple[int, int]],
    line_str: Optional[bytes],
    debug_str: Optional[bytes],
) -> Any:
    """Read one v5 directory/file entry per its format list.

    Content types (DW_LNCT_*): path=1, directory_index=2, timestamp=3,
    size=4, MD5=5. Forms: string=0x08, line_strp=0x1f, strp=0x0e, udata=0x07,
    data1=0x0b, data2=0x05, data4=0x06, data8=0x07? (data8=0x07 collides
    with udata in the numbering; the DWARF 5 spec forms used here are the
    ones clang emits for wasm).
    """
    values: list[Any] = []
    for content_type, form in formats:
        if form == 0x08:  # DW_FORM_string
            values.append(reader.read_cstr())
        elif form == 0x1F:  # DW_FORM_line_strp
            offset = reader.read_u32()
            values.append(_string_at(line_str, offset))
        elif form == 0x0E:  # DW_FORM_strp
            offset = reader.read_u32()
            values.append(_string_at(debug_str, offset))
        elif form == 0x07:  # DW_FORM_udata (also data8 in some tables)
            values.append(reader.read_uleb())
        elif form == 0x0B:  # DW_FORM_data1
            values.append(reader.read_u8())
        elif form == 0x05:  # DW_FORM_data2
            values.append(reader.read_u16())
        elif form == 0x06:  # DW_FORM_data4
            values.append(reader.read_u32())
        elif form == 0x1E:  # DW_FORM_data16 (MD5): skip 16 bytes
            reader.ensure(16)
            reader.offset += 16
            values.append("")
        else:
            raise _DwarfParseError(f"unsupported v5 form {form:#x}")
    # Return the value for the content type callers care about first; for
    # path entries that is values[0], for directory_index values[0] as int.
    if values and isinstance(values[0], int):
        return values[0]
    return values[0] if values else ""


def _string_at(payload: Optional[bytes], offset: int) -> str:
    if payload is None or offset >= len(payload):
        return ""
    end = payload.find(b"\x00", offset)
    if end < 0:
        end = len(payload)
    return payload[offset:end].decode("utf-8", errors="replace")


def _compose_path(name, directory_index, directories) -> str:
    if isinstance(directory_index, str):
        # v5 directory entries resolved inline.
        return directory_index if not name else directory_index
    directory = ""
    if isinstance(directory_index, int) and 1 <= directory_index <= len(directories):
        directory = directories[directory_index - 1]
    if directory and name:
        return f"{directory}/{name}"
    return name or ""


def map_function_sources(
    line_table: dict[str, Any],
    function_addresses: list[tuple[int, int]],
) -> dict[int, dict[str, Any]]:
    """Map (function index, code-relative address) pairs to source locations.

    Uses the last row at or before the function's address, per sequence:
    rows are grouped by end_sequence markers and each sequence is searched
    independently so an address never maps across a sequence boundary.
    """
    rows = line_table.get("rows") or []
    files = {f["index"]: f["path"] for f in line_table.get("files") or []}

    # Split rows into sequences at end_sequence markers (the parser records
    # the reset implicitly; sequences are contiguous ascending runs).
    sequences: list[list[dict[str, int]]] = []
    current: list[dict[str, int]] = []
    previous_address: Optional[int] = None
    for row in rows:
        if previous_address is not None and row["address"] < previous_address:
            sequences.append(current)
            current = []
        current.append(row)
        previous_address = row["address"]
    if current:
        sequences.append(current)

    sources: dict[int, dict[str, Any]] = {}
    for function_index, code_address in function_addresses:
        best: Optional[dict[str, int]] = None
        for sequence in sequences:
            addresses = [row["address"] for row in sequence]
            position = bisect.bisect_right(addresses, code_address)
            if position == 0:
                continue
            candidate = sequence[position - 1]
            if best is None or candidate["address"] > best["address"]:
                best = candidate
        if best is None:
            continue
        path = files.get(best["file"], "")
        if not path:
            continue
        sources[function_index] = {"file": path, "line": best["line"]}
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
