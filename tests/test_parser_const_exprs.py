"""Parser checks for constant expressions, table initializers, reference
block types and compact imports.

The fixtures in fixtures/const_exprs were assembled from the WAT next to
each one with the Rust wasm-tools (`wasm-tools parse x.wat -o x.wasm`) and
checked with `wasm-tools validate --features all`. Each case below decoded
wrongly without an error before the fix: the section desynchronised, so the
entries after the affected one were wrong or missing.
"""

from pathlib import Path

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.parser import BinaryReader

_FIXTURES = Path(__file__).parent / "fixtures" / "const_exprs"


def _parse(name: str) -> dict:
    data = (_FIXTURES / f"{name}.wasm").read_bytes()
    return parse_wasm_bytes(data, name)


def _module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def _section(section_id: int, payload: bytes) -> bytes:
    assert len(payload) < 0x80
    return bytes([section_id, len(payload)]) + payload


def test_extended_const_and_gc_globals_keep_the_section_in_sync():
    report = _parse("extended_const")
    assert report["errors"] == []
    assert [g["init"] for g in report["globals"]] == [
        "i32=5",
        "i32.const 1 global.get 0 i32.add",
        "i64.const 3 i64.const 10 i64.const 4 i64.sub i64.mul",
        "i32.const 1 i32.const 2 struct.new 0",
        "i32.const 7 i32.const 8 i32.const 9 array.new_fixed 1 3",
        "i32.const 42 ref.i31",
        "i32=99",
    ]
    assert [g["valtype"] for g in report["globals"]][-1] == "i32"


def test_extended_const_data_offset_has_no_numeric_value():
    report = _parse("extended_const")
    segments = report["data_segments"]
    assert [(s["offset"], s["offset_value"]) for s in segments] == [
        ("i32.const 16 global.get 0 i32.add", None),
        ("i32=32", 32),
    ]
    assert [s["size"] for s in segments] == [2, 2]


def test_element_flags_6_offset_is_text():
    report = _parse("element_flags6")
    assert report["errors"] == []
    active = report["elements"][0]
    assert active["mode"] == "active"
    assert active["table_index"] == 2
    assert active["offset"] == "i32=1"
    assert report["elements"][1]["mode"] == "declarative"


def test_table_with_initializer_is_decoded():
    report = _parse("element_flags6")
    tables = [(t["ref_type"], t["limits"]["min"]) for t in report["tables"]]
    assert tables == [("func", 1), ("(ref null type[0])", 2), ("func", 3)]
    assert [e["name"] for e in report["exports"]] == ["t2"]


def test_table_initializer_reaches_delegates_that_accept_it():
    seen = []

    class Delegate:
        def begin_module(self, version):
            pass

        def begin_section(self, index, section_id, size):
            pass

        def on_table(self, index, ref_type, mn, mx, is64, init_expr=None, **kw):
            seen.append((index, ref_type, mn, init_expr))

    data = (_FIXTURES / "element_flags6.wasm").read_bytes()
    BinaryReader(data, Delegate()).read_module()
    assert seen == [
        (0, "func", 1, None),
        (1, "(ref null type[0])", 2, "ref.func=0"),
        (2, "func", 3, None),
    ]


def test_reference_block_types_consume_the_heap_type():
    report = _parse("blocktype_ref")
    assert report["errors"] == []
    run = report["functions"][1]["instructions"]
    assert [i["opcode"] for i in run] == [
        "block",
        "ref.func",
        "end",
        "drop",
        "block",
        "try_table",
        "ref.func",
        "end",
        "drop",
        "end",
        "ref.null",
        "end",
    ]
    assert run[0]["immediates"] == [-29]
    assert run[5]["catches"] == [[2, 0]]


def test_reference_block_type_names_reach_delegates_that_accept_them():
    seen = []

    class Delegate:
        def begin_module(self, version):
            pass

        def begin_section(self, index, section_id, size):
            pass

        def on_opcode_block_sig(self, sig, ref_type=None):
            seen.append(("block", sig, ref_type))

        def on_opcode_try_table(self, sig, catches, ref_type=None):
            seen.append(("try_table", sig, ref_type))

    data = (_FIXTURES / "blocktype_ref.wasm").read_bytes()
    BinaryReader(data, Delegate()).read_module()
    assert seen == [
        ("block", -29, "(ref null type[0])"),
        ("block", -64, None),
        ("try_table", -28, "(ref type[0])"),
    ]


def test_compact_import_groups_are_flattened():
    report = _parse("compact_imports")
    assert report["errors"] == []
    imports = [
        (i["index"], i["module"], i["name"], i["kind"]) for i in report["imports"]
    ]
    assert imports == [
        (0, "env", "f1", "func"),
        (1, "env", "f2", "func"),
        (2, "env", "g1", "global"),
        (3, "env", "g2", "global"),
        (4, "host", "mem", "memory"),
    ]
    assert [i.get("type_index") for i in report["imports"][:2]] == [0, 1]
    assert all(i["valtype"] == "i32" for i in report["imports"][2:4])
    # The defined function follows the two imported ones.
    assert report["functions"][0]["index"] == 2
    ops = [i["opcode"] for i in report["functions"][0]["instructions"]]
    assert ops == ["global.get", "call", "end"]


def test_unterminated_constant_expression_is_reported():
    # A global whose i32.const has no end, followed by an export section.
    # The old reader took the export section's id byte as the end and
    # carried on silently.
    module = _module(
        _section(6, b"\x01\x7f\x00\x41\x01"),
        _section(7, b"\x00"),
    )
    report = parse_wasm_bytes(module, "unterminated")
    assert report["errors"]
    assert "not terminated" in report["errors"][0]


def test_unknown_opcode_in_constant_expression_is_reported():
    module = _module(_section(6, b"\x01\x7f\x00\x41\x01\xff\x0b"))
    report = parse_wasm_bytes(module, "unknown-op")
    assert report["errors"]
    assert "constant expression" in report["errors"][0]
