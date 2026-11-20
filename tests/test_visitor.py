# tests/test_visitor.py
"""Tests for visitor behaviors: prepass state, offset bookkeeping, name maps."""

import io
import os
from contextlib import redirect_stdout

from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import (
    BinaryReaderObjdumpBase,
    BinaryReaderObjdumpHeaders,
    BinaryReaderObjdumpPrepass,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as fixture_file:
        return fixture_file.read()


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


def _name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _leb(len(raw)) + raw


def _run_prepass(data: bytes) -> ObjdumpState:
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    return state


# A minimal module: type (i32 -> i32), one function (local.get 0, end),
# plus the optional name custom section to exercise the prepass maps.
_FUNCTION_BODY = _leb(0) + b"\x20\x00\x0b"
_CODE_SECTION = bytes([10]) + _leb(len(_leb(1) + _leb(len(_FUNCTION_BODY)) + _FUNCTION_BODY)) + _leb(1) + _leb(len(_FUNCTION_BODY)) + _FUNCTION_BODY
_TYPE_SECTION = bytes([1]) + _leb(6) + _leb(1) + b"\x60\x01\x7f\x01\x7f"
_FUNCTION_SECTION = bytes([3]) + _leb(2) + _leb(1) + _leb(0)
_NAMED_MODULE = (
    b"\x00asm\x01\x00\x00\x00"
    + _TYPE_SECTION
    + _FUNCTION_SECTION
    + _CODE_SECTION
)


def _module_with_name_section() -> bytes:
    # name custom section: function-name subsection (id 1) with one entry
    # mapping function 0 to "answer". Subsection layout is id, size, then
    # the entry vector.
    entries = _leb(1) + _leb(0) + _name("answer")
    payload = _name("name") + _leb(1) + _leb(len(entries)) + entries
    return _NAMED_MODULE + bytes([0]) + _leb(len(payload)) + payload


def test_prepass_populates_function_names_and_types():
    state = _run_prepass(_module_with_name_section())
    assert state.function_names.get(0) == "answer"
    assert state.function_types.get(0) == 0
    assert state.types, "type section should populate types"


def test_prepass_populates_rich_section_data():
    state = _run_prepass(_fixture_bytes("globals_imports.wasm"))
    assert state.imports, "import section should populate ImportEntry list"
    assert state.globals, "global section should populate GlobalEntry list"
    assert state.types, "type section should populate types"


def test_prepass_records_custom_section_names():
    state = _run_prepass(_module_with_name_section())
    # Custom sections record their name under the section index.
    assert any(name == "name" for name in state.section_names.values())


def test_prepass_records_branch_hints_section():
    # A module carrying metadata.code.branch_hint: the prepass records the
    # decoded summary (CodeMetadata.md: funcidx, then vec(offset, 0x01
    # size, hint)).
    payload = _leb(1) + _leb(0) + _leb(1) + b"\x04\x01\x01"
    hint_section = (
        bytes([0])
        + _leb(len(_name("metadata.code.branch_hint") + payload))
        + _name("metadata.code.branch_hint")
        + payload
    )
    core = b"\x00asm\x01\x00\x00\x00" + hint_section
    state = _run_prepass(core)
    assert state.branch_hints["name"] == "metadata.code.branch_hint"
    assert state.branch_hints["hinted_function_count"] == 1
    assert state.branch_hints["hint_count"] == 1
    assert state.branch_hints["functions"] == [
        {"function": 0, "hints": [{"offset": 4, "hint": "likely"}]}
    ]


def test_base_offset_bookkeeping_starts_at_zero():
    options = ObjdumpOptions(mode=ObjdumpMode.HEADERS)
    state = ObjdumpState()
    visitor = BinaryReaderObjdumpBase(b"\x00asm\x01\x00\x00\x00", options, state)
    assert visitor.get_print_offset(0) == 0


def test_headers_visitor_prints_section_table():
    data = _fixture_bytes("simple_add.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.HEADERS)
    state = _run_prepass(data)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        BinaryReader(data, BinaryReaderObjdumpHeaders(data, options, state)).read_module()
    out = buffer.getvalue()
    assert "Sections:" in out
    assert "Type" in out and "Code" in out
