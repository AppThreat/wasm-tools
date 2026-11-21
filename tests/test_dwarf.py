# tests/test_dwarf.py
"""Tests for DWARF line-table parsing and function-level source mapping.

The corpus bz2.wasm ships full DWARF sections, but its .debug_line carries
headers and file tables with no line programs (the fixture was
post-processed), so the line-program state machine is validated against a
hand-built DWARF 4 table constructed from the spec's grammar (DWARF 4
section 6.2.4: header fields, include directories, file entries, and the
special/standard/extended opcode encoding). Expected rows are derived by
hand from the constructed opcode stream, not from the code under test.
"""

import os

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.dwarf import (
    map_function_sources,
    parse_debug_info_units,
    parse_line_program,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _leb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _sleb(n: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def _cstr(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _build_v4_line_table() -> bytes:
    """A DWARF 4 line program built from the spec grammar.

    Header: min_inst=1, max_ops=1, default_is_stmt=1, line_base=-5,
    line_range=14, opcode_base=13, then the standard opcode lengths. One
    directory, two files (benchmark.c, helper.c). The program:
      - set_address to 0 (extended, 5 bytes payload)
      - advance_line +10, set_file 2
      - advance_pc 100, copy -> row (100, file 2, line 11)
      - special opcode for line +1 address +1 -> row (101, 2, 12)
      - advance_line -20, set_file 1, advance_pc 50, copy -> row (150, 1, -8... clamped below 1? spec allows any)
      - end_sequence -> row at 200
    """
    line_base = -5
    line_range = 14
    opcode_base = 13

    program = bytearray()
    # Extended: set_address, payload = 4-byte address 0, then an immediate
    # copy so the first row lands at address 0 (set_address alone emits no
    # row).
    program += b"\x00" + _leb(5) + b"\x02" + (0).to_bytes(4, "little")
    program += b"\x01"  # copy -> row (0, file 1, line 1)
    # Standard: advance_line +10, set_file 2
    program += b"\x03" + _sleb(10)
    program += b"\x04" + _leb(2)
    # Standard: advance_pc 100 (uleb, multiplied by min_inst)
    program += b"\x02" + _leb(100)
    # copy -> row (100, 2, 11)
    program += b"\x01"
    # Special opcode: address += 1, line += 1.
    # adjusted = opcode - opcode_base; line advance = line_base + adjusted % line_range.
    # Want line advance +1: adjusted % 14 = 6 (=-5+6=1). Want address advance 1:
    # address advance = min_inst * (op_advance * max_ops + (adjusted % range) % max_ops)
    # = (op_advance * 1 + 6 % 1) = op_advance -> op_advance = 1.
    # adjusted = 1 * 14 + 6 = 20 -> opcode = 13 + 20 = 33.
    program += bytes([opcode_base + 20])
    # advance_line -20 (line 12-20 = -8), set_file 1, advance_pc 50, copy
    program += b"\x03" + _sleb(-20)
    program += b"\x04" + _leb(1)
    program += b"\x02" + _leb(50)
    program += b"\x01"
    # Extended: end_sequence (address set to 200 first via advance_pc 50)
    program += b"\x02" + _leb(50)
    program += b"\x00" + _leb(1) + b"\x01"

    header = bytearray()
    header += (0x0C).to_bytes(2, "little")  # version 4? no: version first
    # Correct order: version(2), header_length(4), then fields.
    # Header body: everything from the version to the file-table terminator.
    # Layout: version(2), header_length(4, patched), fields(6), std(12),
    # include dirs, file entries, terminator.
    body = bytearray()
    body += bytes([1, 1, 1])  # min_inst, max_ops, default_is_stmt
    body += bytes([line_base & 0xFF, line_range, opcode_base])
    body += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])  # 12 std lengths
    body += _cstr("/src") + b"\x00"  # include dirs, terminated by empty
    body += _cstr("benchmark.c") + _leb(1) + _leb(0) + _leb(100)
    body += _cstr("helper.c") + _leb(1) + _leb(0) + _leb(200)
    body += b"\x00"  # file table terminator
    # header_length counts from just after the header_length field (the
    # first body byte) to the program start, which is exactly the body size.
    header_length = len(body)
    header = (
        (4).to_bytes(2, "little")  # version
        + header_length.to_bytes(4, "little")
        + bytes(body)
    )

    # unit_length covers everything after the unit_length field itself:
    # the header (which starts with the version) plus the program.
    unit_length = len(header) + len(program)
    return (
        unit_length.to_bytes(4, "little")
        + bytes(header)
        + bytes(program)
    )


def test_parse_v4_line_table_rows():
    table = parse_line_program(_build_v4_line_table())
    assert table is not None
    assert table["version"] == 4
    assert [f["path"] for f in table["files"]] == [
        "/src/benchmark.c",
        "/src/helper.c",
    ]
    rows = table["rows"]
    # Hand-derived: the initial copy row at address 0, then (100, file 2,
    # line 11), (101, 2, 12), (151, 1, -8), and the end_sequence row at
    # (201, 1, -8). Rows carry the resolved path.
    assert rows[0] == {"address": 0, "file": "/src/benchmark.c", "line": 1}
    assert rows[1] == {"address": 100, "file": "/src/helper.c", "line": 11}
    assert rows[2] == {"address": 101, "file": "/src/helper.c", "line": 12}
    assert rows[3] == {"address": 151, "file": "/src/benchmark.c", "line": -8}
    assert rows[-1] == {
        "address": 201,
        "file": "/src/benchmark.c",
        "line": -8,
        "end_sequence": True,
    }


def test_map_function_sources():
    table = parse_line_program(_build_v4_line_table())
    sources = map_function_sources(
        table,
        [(0, 90), (1, 100), (2, 120), (3, 152), (4, 250)],
    )
    assert sources[0] == {"file": "/src/benchmark.c", "line": 1}
    assert sources[1] == {"file": "/src/helper.c", "line": 11}
    assert sources[2] == {"file": "/src/helper.c", "line": 12}
    assert sources[3] == {"file": "/src/benchmark.c", "line": -8}
    # 250 lies past the sequence's end (201), so it maps to nothing rather
    # than to the last row before the end.
    assert 4 not in sources


def test_line_program_truncated_returns_none():
    table_bytes = _build_v4_line_table()
    assert parse_line_program(table_bytes[:-8]) is None
    assert parse_line_program(b"") is None


def test_bz2_file_table_parses_without_programs():
    # The corpus fixture's .debug_line carries headers and file tables only
    # (the fixture was post-processed); parsing must not crash and must not
    # invent mappings.
    from wasm_tools.parser import BinaryReader
    from wasm_tools.models import ObjdumpState, ObjdumpOptions, ObjdumpMode
    from wasm_tools.visitor import BinaryReaderObjdumpPrepass

    data_path = os.path.join(FIXTURES_DIR, "corpus", "bz2.wasm")
    data = open(data_path, "rb").read()
    state = ObjdumpState()
    BinaryReader(
        data, BinaryReaderObjdumpPrepass(data, ObjdumpOptions(mode=ObjdumpMode.PREPASS), state)
    ).read_module()
    payloads = state.debug_payloads
    assert ".debug_line" in payloads
    table = parse_line_program(
        payloads[".debug_line"], payloads.get(".debug_line_str"), state.debug_str_payload
    )
    assert table is not None
    assert table["version"] == 4
    file_paths = [f["path"] for f in table["files"]]
    assert "benchmark.c" in file_paths
    # No programs in this fixture: no rows, so no function gains a source.
    if not table["rows"]:
        report = parse_wasm_bytes(data, "bz2.wasm")
        assert all("source" not in fn for fn in report["functions"])


def test_debug_info_units_parsed():
    from wasm_tools.parser import BinaryReader
    from wasm_tools.models import ObjdumpState, ObjdumpOptions, ObjdumpMode
    from wasm_tools.visitor import BinaryReaderObjdumpPrepass

    data_path = os.path.join(FIXTURES_DIR, "corpus", "bz2.wasm")
    data = open(data_path, "rb").read()
    state = ObjdumpState()
    BinaryReader(
        data, BinaryReaderObjdumpPrepass(data, ObjdumpOptions(mode=ObjdumpMode.PREPASS), state)
    ).read_module()
    payloads = state.debug_payloads
    assert ".debug_info" in payloads
    units = parse_debug_info_units(payloads[".debug_info"])
    assert units
    assert all(u["version"] == 4 for u in units), "clang 11 emits DWARF 4 units"
    assert all(u["size"] > 4 for u in units)


def test_end_to_end_function_source_mapping():
    # A module whose .debug_line maps its single function's code-relative
    # address: set_address names the function's start, so the function gains
    # a source entry pointing at the mapped file and line.
    def _leb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _name(s):
        raw = s.encode()
        return _leb(len(raw)) + raw

    body = _leb(0) + b"\x0b"
    code = _leb(1) + _leb(len(body)) + body
    module_body = (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1]) + _leb(4) + _leb(1) + b"\x60\x00\x00"
        + bytes([3]) + _leb(2) + _leb(1) + _leb(0)
        + bytes([10]) + _leb(len(code)) + code
    )
    # The report's section offsets are payload offsets, so the function's
    # code-relative address is its file offset minus the code section's
    # payload offset; this module places the function exactly at the code
    # section start, i.e. address 0, which the built table's set_address
    # already names.
    code_section_payload_offset = len(module_body) - len(code)
    function_code_address = 0
    assert code_section_payload_offset == 20
    table = _build_v4_line_table()
    debug_section = (
        bytes([0]) + _leb(len(_name(".debug_line")) + len(table))
        + _name(".debug_line") + table
    )
    report = parse_wasm_bytes(module_body + debug_section, "mapped.wasm")
    assert report["errors"] == []
    fn = report["functions"][0]
    # The function's code-relative address is 0, which the table's first
    # row (the post-set_address copy) maps to benchmark.c line 1.
    assert fn.get("source") == {"file": "/src/benchmark.c", "line": 1}


def _clang_sources(name):
    report = parse_wasm_bytes(open(os.path.join(FIXTURES_DIR, name), "rb").read(), name)
    assert report["errors"] == []
    return {fn["name"]: fn.get("source") for fn in report["functions"]}


def test_clang_dwarf4_two_units_map_to_their_own_files():
    # dwarf_v4_two_units.wasm: a.c and b.c (kept here as dwarf_a.c and
    # dwarf_b.c) built with
    # `clang --target=wasm32 -g -gdwarf-4 -O0 -nostdlib -fdebug-prefix-map=$PWD=/src -Wl,--no-entry
    # -Wl,--export-all`. Expected lines are llvm-dwarfdump's DW_AT_decl_line
    # and line rows at each DW_AT_low_pc: add a.c:1, mul a.c:3, sq b.c:2.
    # The second unit (b.c) is only reachable by walking every unit, and
    # clang's prologue_end opcodes take no operands, so a parser that reads
    # one would desynchronise and get these wrong.
    sources = _clang_sources("dwarf_v4_two_units.wasm")
    assert sources["add"]["line"] == 1 and sources["add"]["file"].endswith("a.c")
    assert sources["mul"]["line"] == 3 and sources["mul"]["file"].endswith("a.c")
    assert sources["sq"]["line"] == 2 and sources["sq"]["file"].endswith("b.c")


def test_clang_dwarf5_two_units_map_to_their_own_files():
    # The same sources with -gdwarf-5: zero-based file indices, directory 0
    # as the compilation directory, and line_strp entry forms.
    sources = _clang_sources("dwarf_v5_two_units.wasm")
    assert sources["add"]["line"] == 1 and sources["add"]["file"].endswith("a.c")
    assert sources["mul"]["line"] == 3 and sources["mul"]["file"].endswith("a.c")
    assert sources["sq"]["line"] == 2 and sources["sq"]["file"].endswith("b.c")


def test_line_range_zero_is_rejected_not_divided_by():
    table = bytearray(_build_v4_line_table())
    # line_range is the byte after line_base in the v4 header: unit_length
    # (4), version (2), header_length (4), min_inst, max_ops,
    # default_is_stmt, line_base, then line_range at offset 14.
    table[14] = 0
    assert parse_line_program(bytes(table)) is None


def test_row_cap_truncates():
    table = parse_line_program(_build_v4_line_table(), max_rows=2)
    assert table["truncated"] is True
    assert len(table["rows"]) == 2
