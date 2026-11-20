# tests/test_customsections.py
"""Tests for the tool-conventions custom section catalog (dylink, linking,
branch hints, component-type, coredump)."""

import os

import pytest

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.customsections import (
    parse_branch_hints,
    parse_dylink,
    parse_dylink_legacy,
    parse_linking,
    name_precedence_names,
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


def _name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _leb(len(raw)) + raw


def _sub(sub_type: int, payload: bytes) -> bytes:
    return bytes([sub_type]) + _leb(len(payload)) + payload


def _core_module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def _custom_section(name: str, payload: bytes) -> bytes:
    return _section(0, _name(name) + payload)


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _leb(len(payload)) + payload


# ─── dylink.0 ────────────────────────────────────────────────────────────────


def test_dylink_full_decode():
    payload = (
        _sub(1, _leb(2) + _leb(4) + _leb(3) + _leb(0))  # MEM_INFO
        + _sub(2, _leb(2) + _name("libside.wasm") + _name("libc.so"))  # NEEDED
        + _sub(3, _leb(1) + _name("bar") + _leb(2))  # EXPORT_INFO
        + _sub(4, _leb(1) + _name("env") + _name("foo") + _leb(1))  # IMPORT_INFO
        + _sub(5, _leb(1) + _name("/usr/lib"))  # RUNTIME_PATH (vec)
        + _sub(6, _name("x86-64"))  # TARGET_ARCH
    )
    info = parse_dylink(payload)
    assert info is not None
    assert info["legacy"] is False
    assert info["mem_info"] == {
        "memory_size": 2,
        "memory_alignment": 4,
        "table_size": 3,
        "table_alignment": 0,
    }
    assert info["needed"] == ["libside.wasm", "libc.so"]
    assert info["export_info"] == [{"name": "bar", "flags": 2}]
    assert info["import_info"] == [
        {"module": "env", "field": "foo", "flags": 1}
    ]
    assert info["runtime_path"] == ["/usr/lib"]
    assert info["target_arch"] == "x86-64"


def test_dylink_truncated_payload_returns_none():
    assert parse_dylink(b"\x01\x40") is None
    assert parse_dylink(b"") is None  # no subsections at all


def test_dylink_legacy_flat_layout():
    payload = _leb(16) + _leb(4) + _leb(2) + _leb(0) + _leb(1) + _name("libm.so")
    info = parse_dylink_legacy(payload)
    assert info is not None
    assert info["legacy"] is True
    assert info["mem_info"] == {
        "memory_size": 16,
        "memory_alignment": 4,
        "table_size": 2,
        "table_alignment": 0,
    }
    assert info["needed"] == ["libm.so"]


def test_dylink_end_to_end_report():
    payload = (
        _sub(1, _leb(2) + _leb(4) + _leb(3) + _leb(0))
        + _sub(2, _leb(1) + _name("libside.wasm"))
        + _sub(6, _name("wasm32"))
    )
    module = _core_module(_custom_section("dylink.0", payload))
    report = parse_wasm_bytes(module, "side.wasm")
    assert report["errors"] == []
    assert report["dylink"]["needed"] == ["libside.wasm"]
    assert report["dylink"]["target_arch"] == "wasm32"


# ─── linking ─────────────────────────────────────────────────────────────────


def test_linking_symbol_table_decode():
    # Version 2, symbol table with: defined func with explicit name
    # (flags 0x40), undefined data symbol (flags 0x10), defined global
    # without a name.
    # Per Linking.md, defined func/global/tag/table symbols carry a name;
    # only imports omit it (unless the explicit-name flag is set).
    symbols = (
        _leb(3)
        + bytes([0]) + _leb(0x40) + _leb(4) + _name("mylib_hash")  # func
        + bytes([1]) + _leb(0x10) + _name("external_data")  # data (undefined)
        + bytes([2]) + _leb(0x00) + _leb(0) + _name("cfg_global")  # global
    )
    payload = _leb(2) + _sub(8, symbols)
    info = parse_linking(payload)
    assert info is not None
    assert info["version"] == 2
    assert info["symbol_count"] == 3
    func_sym = info["symbols"][0]
    assert func_sym["kind"] == "func"
    assert func_sym["index"] == 4
    assert func_sym["name"] == "mylib_hash"
    assert func_sym["explicit_name"] is True
    data_sym = info["symbols"][1]
    assert data_sym["kind"] == "data"
    assert data_sym["name"] == "external_data"
    assert data_sym["undefined"] is True
    global_sym = info["symbols"][2]
    assert global_sym["kind"] == "global"
    assert global_sym["name"] == "cfg_global"


def test_linking_data_symbol_with_segment_fields():
    # Defined data symbol: name, segment index, offset, size.
    symbol = bytes([1]) + _leb(0x00) + _name("buf") + _leb(0) + _leb(16) + _leb(32)
    payload = _leb(2) + _sub(8, _leb(1) + symbol)
    info = parse_linking(payload)
    assert info["symbols"][0]["segment_index"] == 0
    assert info["symbols"][0]["offset"] == 16
    assert info["symbols"][0]["size"] == 32


def test_absolute_data_symbol_keeps_the_table_in_step():
    # A defined absolute data symbol (flags 0x200) still carries segment,
    # offset and size; skipping them misframed every later symbol.
    absolute = bytes([1]) + _leb(0x200) + _name("a") + _leb(0) + _leb(4) + _leb(8)
    func = bytes([0]) + _leb(0x00) + _leb(1) + _name("foo")
    info = parse_linking(_leb(2) + _sub(8, _leb(2) + absolute + func))
    assert info["symbols"][0]["absolute"] is True
    assert info["symbols"][0]["size"] == 8
    assert (info["symbols"][1]["kind"], info["symbols"][1]["name"], info["symbols"][1]["index"]) == (
        "func",
        "foo",
        1,
    )


def test_huge_symbol_table_keeps_only_the_capped_entries():
    from wasm_tools.customsections import DEFAULT_MAX_LINKING_SYMBOLS

    count = DEFAULT_MAX_LINKING_SYMBOLS * 20
    symbol = bytes([1]) + _leb(0x10) + _name("x")
    info = parse_linking(_leb(2) + _sub(8, _leb(count) + symbol * count))
    assert info["symbol_count"] == count
    assert len(info["symbols"]) == DEFAULT_MAX_LINKING_SYMBOLS
    assert info["symbols_truncated"] is True


def test_linking_segment_info_and_target_arch():
    payload = (
        _leb(2)
        + _sub(5, _leb(2) + _name(".rodata") + _leb(4) + _leb(0) + _name("__em_js") + _leb(0) + _leb(0))
        + _sub(9, _name("wasm32"))
    )
    info = parse_linking(payload)
    assert info["segment_names"] == [".rodata", "__em_js"]
    assert info["target_arch"] == "wasm32"


def test_linking_truncated_returns_none():
    assert parse_linking(b"\x02\x08\x05\x20") is None


def test_linking_names_fill_missing_function_names():
    # An object-file-shaped module: no name section, a code section with one
    # function, and a linking section naming function 0 via an explicit-name
    # symbol. The report and the call graph use the linking name.
    body = _leb(0) + b"\x0b"
    type_section = _section(1, _leb(1) + b"\x60\x00\x00")
    func_section = _section(3, _leb(1) + _leb(0))
    code_section = _section(10, _leb(1) + _leb(len(body)) + body)
    linking_payload = _leb(2) + _sub(
        8, _leb(1) + bytes([0]) + _leb(0x40) + _leb(0) + _name("exported_fn")
    )
    module = _core_module(
        type_section,
        func_section,
        code_section,
        _custom_section("linking", linking_payload),
    )
    report = parse_wasm_bytes(module, "object.wasm")
    assert report["errors"] == []
    assert report["functions"][0]["name"] == "exported_fn"
    assert report["linking"]["symbol_count"] == 1
    assert report["call_graph"]["nodes"][0]["name"] == "exported_fn"


def test_name_section_wins_over_linking_names():
    body = _leb(0) + b"\x0b"
    type_section = _section(1, _leb(1) + b"\x60\x00\x00")
    func_section = _section(3, _leb(1) + _leb(0))
    code_section = _section(10, _leb(1) + _leb(len(body)) + body)
    entries = _leb(1) + _leb(0) + _name("name_section_fn")
    name_section = _custom_section("name", _leb(1) + _leb(len(entries)) + entries)
    linking_payload = _leb(2) + _sub(
        8, _leb(1) + bytes([0]) + _leb(0x40) + _leb(0) + _name("linking_fn")
    )
    module = _core_module(
        type_section,
        func_section,
        code_section,
        name_section,
        _custom_section("linking", linking_payload),
    )
    report = parse_wasm_bytes(module, "both.wasm")
    assert report["functions"][0]["name"] == "name_section_fn"


def test_em_js_segment_counted_from_segment_info():
    payload = _leb(2) + _sub(
        5, _leb(2) + _name(".data") + _leb(0) + _leb(0) + _name("__em_js") + _leb(0) + _leb(0)
    )
    module = _core_module(_custom_section("linking", payload))
    report = parse_wasm_bytes(module, "emjs.wasm")
    assert report["linking"]["em_js_segments"] == 1


# ─── component-type and coredump ─────────────────────────────────────────────


@pytest.mark.parametrize("name", ["component-type", "component-type:wit-bindgen:0.41.0:a:b:w"])
def test_component_type_section_summarized(name):
    # The payload is a component binary (version 0x0d, layer 1); wit-bindgen
    # suffixes the section name.
    payload = b"\x00asm\x0d\x00\x01\x00" + b"\x00" * 4
    module = _core_module(_custom_section(name, payload))
    report = parse_wasm_bytes(module, "ct.wasm")
    assert report["component_type"]["version"] == 0x0D
    assert report["component_type"]["payload_size"] == len(payload)


def test_coredump_section_recorded():
    module = _core_module(_custom_section("core", b"\x00"))
    report = parse_wasm_bytes(module, "cd.wasm")
    assert report["coredump"] is True


def test_malformed_linking_degrades_to_error_string():
    module = _core_module(_custom_section("linking", b"\x02\x08\x99\x99"))
    report = parse_wasm_bytes(module, "bad.wasm")
    assert any("linking" in err for err in report["errors"])
    assert "linking" not in report


def test_branch_hint_decoder_direct():
    payload = (
        _leb(2)
        + _leb(7) + _leb(2) + b"\x00\x01\x00" + b"\x0a\x01\x01"
        + _leb(9) + _leb(1) + b"\x04\x01\x00"
    )
    info = parse_branch_hints(payload)
    assert info["hinted_function_count"] == 2
    assert info["hint_count"] == 3
    assert info["functions"] == [
        {
            "function": 7,
            "hints": [
                {"offset": 0, "hint": "unlikely"},
                {"offset": 10, "hint": "likely"},
            ],
        },
        {"function": 9, "hints": [{"offset": 4, "hint": "unlikely"}]},
    ]


def test_branch_hint_decoder_truncated_returns_none():
    assert parse_branch_hints(_leb(1) + _leb(0) + _leb(1) + b"\x04") is None


def test_name_precedence_map_only_explicit_names():
    linking = {
        "symbols": [
            {"kind": "func", "name": "kept", "index": 1},
            {"kind": "func", "name": None, "index": 2},
            {"kind": "data", "name": "ignored", "index": 3},
        ]
    }
    assert name_precedence_names(linking) == {1: "kept"}
    assert name_precedence_names(None) == {}
