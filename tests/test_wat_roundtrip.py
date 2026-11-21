# tests/test_wat_roundtrip.py
"""WAT emitter tests: regression cases for hostile and edge-case input, and
the round-trip conformance harness.

The harness emits WAT for every core fixture and every vendored corpus
binary, reassembles it with each available assembler (WABT's wat2wasm and
the Rust wasm-tools), and compares the decoded modules: instruction streams
with their immediates and try_table catch clauses, types, imports with their
limits and mutability, globals with their exact initializers, tables,
memories, exports, element segments, data segments with their payload
bytes, tags, the start function and function names. Floats compare by bit
pattern, so NaN payloads and signs count. Each assembler is skipped when it
is not installed.
"""

import functools
import os
import shutil
import struct
import subprocess
import tempfile

import pytest

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.parser import BinaryReader
from wasm_tools.wat import _SourceSections, emit_wat

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
CORPUS_DIR = os.path.join(FIXTURES_DIR, "corpus")

_WAT2WASM = shutil.which("wat2wasm")
_WAT2WASM_FEATURES = [
    "--enable-threads",
    "--enable-function-references",
    "--enable-gc",
    "--enable-custom-page-sizes",
    "--enable-wide-arithmetic",
]


@functools.cache
def _rust_wasm_tools():
    """The Rust wasm-tools binary; this package's own CLI shares the name.

    Both print "wasm-tools X.Y.Z" for --version, so the probe asks for the
    help of the Rust tool's ``parse`` subcommand, which this package's CLI
    rejects with a usage error.
    """
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, "wasm-tools")
        if not os.access(candidate, os.X_OK):
            continue
        try:
            probe = subprocess.run(
                [candidate, "parse", "--help"], capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0 and "WebAssembly text format" in probe.stdout:
            return candidate
    return None


def _assemble(assembler: str, wat_text: str):
    """Assemble WAT text; returns (returncode, stderr, wasm bytes or None)."""
    with tempfile.TemporaryDirectory() as tmp:
        wat_path = os.path.join(tmp, "module.wat")
        wasm_path = os.path.join(tmp, "module.wasm")
        with open(wat_path, "w", encoding="utf-8") as out:
            out.write(wat_text)
        if assembler == "wat2wasm":
            # --debug-names keeps $ids as a name section, which the harness
            # compares. Every off-by-default proposal is enabled except
            # compact imports (in --enable-all), which changes the import
            # section encoding.
            cmd = [_WAT2WASM, *_WAT2WASM_FEATURES, "--debug-names", wat_path, "-o", wasm_path]
        else:
            cmd = [_rust_wasm_tools(), "parse", wat_path, "-o", wasm_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return result.returncode, result.stderr, None
        with open(wasm_path, "rb") as handle:
            return 0, "", handle.read()


def _assemblers():
    found = []
    if _WAT2WASM:
        found.append("wat2wasm")
    if _rust_wasm_tools():
        found.append("wasm-tools")
    return found


# ─── Module comparison ──────────────────────────────────────────────────────


class _DataCapture:
    """Parser delegate that keeps data segment payload bytes."""

    def __init__(self):
        self.payloads = {}
        self.offset = 0

    def begin_module(self, version):
        pass

    def begin_section(self, index, section_id, size):
        pass

    def begin_custom_section(self, index, size, name):
        pass

    def on_data(self, index, mode, mem_idx, offset_expr, size, data, offset_value=None):
        self.payloads[index] = bytes(data)


def _data_payloads(raw: bytes) -> dict:
    capture = _DataCapture()
    BinaryReader(raw, capture).read_module()
    return capture.payloads


def _float_bits(raw: bytes, ins: dict):
    """Exact float bits of an f32/f64.const, read from the binary itself.

    The parser widens floats to Python doubles (quieting signalling NaNs),
    and NaN never compares equal, so the harness compares bit patterns.
    """
    offset = ins["offset"]
    if ins["opcode"] == "f32.const":
        return ("f32", struct.unpack_from("<I", raw, offset + 1)[0])
    return ("f64", struct.unpack_from("<Q", raw, offset + 1)[0])


_INLINE_BLOCK_TYPES = {
    "i32": -1,
    "i64": -2,
    "f32": -3,
    "f64": -4,
    "v128": -5,
    "funcref": -16,
    "externref": -17,
    "exnref": -23,
}


def _block_sig(sig, types: dict):
    """Block type in the shortest encoding.

    A type index whose function type is ``[] -> []`` or ``[] -> [t]`` for a
    single value type means the same as the inline form, and wat2wasm
    writes the inline form for it while wasm-tools keeps the index.
    """
    t = types.get(sig) if isinstance(sig, int) and sig >= 0 else None
    if t is None or t.get("kind") != "func" or t.get("params"):
        return sig
    results = t.get("results") or []
    if not results:
        return -64
    if len(results) == 1 and results[0] in _INLINE_BLOCK_TYPES:
        return _INLINE_BLOCK_TYPES[results[0]]
    return sig


def _instructions(raw: bytes, fn: dict, types: dict) -> list:
    out = []
    for ins in fn.get("instructions") or []:
        if ins["opcode"] in ("f32.const", "f64.const"):
            immediates = (_float_bits(raw, ins),)
        elif ins["opcode"] in ("block", "loop", "if", "try", "try_table"):
            immediates = (_block_sig(ins["immediates"][0], types),) + tuple(
                ins["immediates"][1:]
            )
        else:
            immediates = tuple(
                ("float", struct.pack("<d", v)) if isinstance(v, float) else v
                for v in ins["immediates"]
            )
        catches = tuple(tuple(c) for c in ins.get("catches") or ())
        out.append((ins["opcode"], immediates, catches, ins.get("block_type")))
    return out


def _local_runs(decls) -> list:
    """Local types as runs: assemblers regroup adjacent same-type locals."""
    runs: list = []
    for count, ltype in decls or ():
        if not count:
            continue
        if runs and runs[-1][1] == ltype:
            runs[-1][0] += count
        else:
            runs.append([count, ltype])
    return runs


def _strip(entries: list, *drop: str) -> list:
    return [{k: v for k, v in e.items() if k not in drop} for e in entries]


def _element_view(entry: dict) -> dict:
    """Report element entry without encoding artifacts.

    Assemblers pick different segment flags for the same segment (an
    explicit ``(table 0)`` or not), and for flags 6 the parser reports the
    offset as a (text, value) tuple and the element type by its heap-type
    name, so those two fields are normalised before comparing.
    """
    entry = dict(entry)
    if isinstance(entry.get("offset"), tuple):
        entry["offset"] = entry["offset"][0]
    if entry.get("ref_type") == "func":
        entry["ref_type"] = "funcref"
    return entry


def _module_view(raw: bytes, report: dict) -> dict:
    types = {t["index"]: t for t in report["types"]}
    names = {}
    for fn in report["functions"]:
        if fn.get("name") and fn["name"] not in names.values():
            names[fn["index"]] = fn["name"]
    sections = _SourceSections(raw)
    return {
        "types": _strip(report["types"], "index"),
        "imports": _strip(report["imports"], "index"),
        "functions": [
            (fn["signature_index"], _local_runs(fn.get("local_decls")), _instructions(raw, fn, types))
            for fn in report["functions"]
        ],
        "names": names,
        "tables": report["tables"],
        "memories": report["memories"],
        "globals": report["globals"],
        "global_decls": sections.globals,
        "exports": _strip(report["exports"], "index"),
        "elements": [_element_view(e) for e in report["elements"]],
        "element_items": [
            {k: v for k, v in e.items() if k != "flags"} for e in sections.elements or []
        ],
        "data_segments": report["data_segments"],
        "data_payloads": _data_payloads(raw),
        "tags": report["tags"],
        "start": report.get("start_function"),
    }


# ─── Round-trip harness ─────────────────────────────────────────────────────

# Fixtures whose emission is legitimately incomplete, so there is nothing to
# reassemble. Every other fixture must emit complete text that both
# assemblers accept and that decodes back to the same module.
_INCOMPLETE_BY_DESIGN = {
    # The report carries no struct or array field types, so GC type
    # definitions cannot be written out; the emitter marks them incomplete.
    "gc_ops.wasm": "struct and array types are not emitted",
    "gc_rec_group.wasm": "struct and array types are not emitted",
    "extended_const.wasm": "struct and array types are not emitted",
}

# (fixture, assembler) pairs the assembler itself cannot take.
_ASSEMBLER_GAPS = {
    # Neither WABT 1.0.42 nor the Rust wasm-tools 1.263 text parser knows
    # the f16x8 (half-precision SIMD) instruction keywords; the fixture is
    # hand-assembled bytes for that reason.
    ("f16x8_binary.wasm", "wat2wasm"): "wat2wasm has no f16x8 instructions",
    ("f16x8_binary.wasm", "wasm-tools"): "wasm-tools parse has no f16x8 instructions",
}


def _corpus_names():
    fixtures = sorted(n for n in os.listdir(FIXTURES_DIR) if n.endswith(".wasm"))
    corpus = sorted(
        os.path.join("corpus", n) for n in os.listdir(CORPUS_DIR) if n.endswith(".wasm")
    )
    # Constant expressions, element flags, reference block types and
    # compact imports, built with wasm-tools.
    const_dir = os.path.join(FIXTURES_DIR, "const_exprs")
    const_exprs = sorted(
        os.path.join("const_exprs", n) for n in os.listdir(const_dir) if n.endswith(".wasm")
    )
    return fixtures + corpus + const_exprs


def _roundtrip(name: str, assembler: str) -> None:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as handle:
        raw = handle.read()
    report = parse_wasm_bytes(raw, name)
    if report.get("is_component"):
        pytest.skip("components emit per-core-module WAT")
    wat_text = emit_wat(report, source=raw)
    base = os.path.basename(name)
    if base in _INCOMPLETE_BY_DESIGN:
        assert ";; emission incomplete" in wat_text
        pytest.skip(_INCOMPLETE_BY_DESIGN[base])
    assert ";; emission incomplete" not in wat_text, (
        f"{name}: emission incomplete:\n"
        + "\n".join(line for line in wat_text.splitlines() if ";;" in line)[:2000]
    )
    if (base, assembler) in _ASSEMBLER_GAPS:
        pytest.skip(_ASSEMBLER_GAPS[(base, assembler)])

    code, stderr, rebuilt = _assemble(assembler, wat_text)
    assert code == 0, f"{name}: {assembler} rejected the emitted WAT:\n{stderr[:1500]}"
    recompiled = parse_wasm_bytes(rebuilt, name)
    assert recompiled["errors"] == [], f"{name}: recompiled module has errors"

    original = _module_view(raw, report)
    again = _module_view(rebuilt, recompiled)
    for key in original:
        assert original[key] == again[key], f"{name}: {key} diverged across the round trip"


@pytest.mark.parametrize("assembler", ["wat2wasm", "wasm-tools"])
@pytest.mark.parametrize("name", _corpus_names())
def test_roundtrip(name, assembler):
    if assembler not in _assemblers():
        pytest.skip(f"{assembler} not installed")
    _roundtrip(name, assembler)


# ─── Golden files: wording changes become reviewable diffs ───────────────────


@pytest.mark.parametrize(
    "name", ["simple_add.wasm", "call_indirect.wasm", "exceptions_basic.wasm"]
)
def test_golden_emission(name):
    raw = open(os.path.join(FIXTURES_DIR, name), "rb").read()
    report = parse_wasm_bytes(raw, name)
    emitted = emit_wat(report, source=raw)
    golden_path = os.path.join(FIXTURES_DIR, "golden", name.replace(".wasm", ".wat"))
    golden = open(golden_path, encoding="utf-8").read()
    assert emitted == golden, (
        f"{name}: emitted WAT drifted from the golden file; regenerate with "
        f"`wasm-tools {name} --print-wat > tests/fixtures/golden/{name[:-5]}.wat` "
        "and review the diff"
    )


# ─── Hand-built modules for emitter regressions ─────────────────────────────


def _leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _name(text: bytes) -> bytes:
    return _leb(len(text)) + text


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _leb(len(payload)) + payload


def _vec(entries: list) -> bytes:
    return _leb(len(entries)) + b"".join(entries)


_HEADER = b"\x00asm\x01\x00\x00\x00"
# One type: (func), plus one with (param i32) for block-type tests.
_TYPES = _section(1, _vec([b"\x60\x00\x00", b"\x60\x01\x7f\x00"]))


def _func_module(code: bytes, locals_: bytes = b"\x00", before=(), after=()) -> bytes:
    """A module with one (func) whose body is ``code`` (end appended)."""
    body = locals_ + code + b"\x0b"
    return (
        _HEADER
        + _TYPES
        + b"".join(before)
        + _section(3, _vec([b"\x00"]))
        + b"".join(after[:1])
        + _section(10, _vec([_leb(len(body)) + body]))
        + b"".join(after[1:])
    )


def _emit(raw: bytes) -> str:
    return emit_wat(parse_wasm_bytes(raw, "test.wasm"), source=raw)


def _body_lines(text: str) -> list:
    return [line.strip() for line in text.splitlines() if line.startswith("    ")]


def _assert_reparses(text: str) -> None:
    """Syntax check with the Rust wasm-tools (parse does not validate)."""
    if _rust_wasm_tools() is None:
        return
    code, stderr, _ = _assemble("wasm-tools", text)
    assert code == 0, stderr


def test_local_group_bomb_is_bounded():
    # One local group declaring 0xFFFFFFFF i32 locals in six bytes once
    # made the emitter build a 17 GB string.
    raw = _func_module(b"", locals_=_leb(1) + _leb(0xFFFFFFFF) + b"\x7f")
    text = _emit(raw)
    assert len(text) < 10_000
    assert "(local i32" not in text
    assert "not expanded" in text
    assert ";; emission incomplete" in text
    _assert_reparses(text)


def test_local_groups_expand_in_order():
    raw = _func_module(b"", locals_=_leb(2) + b"\x03\x7f\x01\x7e")
    text = _emit(raw)
    assert "(local i32 i32 i32)" in text
    assert "(local i64)" in text
    assert ";; emission incomplete" not in text


def test_local_budget_is_module_wide():
    # Many functions each declaring the per-function maximum stay within a
    # budget linear in the code size.
    body = _leb(1) + _leb(50_000) + b"\x7f" + b"\x0b"
    count = 200
    raw = (
        _HEADER
        + _TYPES
        + _section(3, _vec([b"\x00"] * count))
        + _section(10, _vec([_leb(len(body)) + body] * count))
    )
    text = _emit(raw)
    assert len(text) < 5_000_000
    assert ";; emission incomplete" in text


def test_data_offset_expression_and_memory_index():
    memories = _section(5, _vec([b"\x00\x01"] * 130))
    data = _section(
        11,
        _vec(
            [
                b"\x00" + b"\x41" + _sleb(11) + b"\x0b" + _name(b"abc"),
                # flags 2: memory index 129 is a two-byte LEB.
                b"\x02" + _leb(129) + b"\x41" + _sleb(5) + b"\x0b" + _name(b"xy"),
                b"\x01" + _name(b"\x00\xff\"\\"),
            ]
        ),
    )
    raw = _HEADER + memories + data
    text = _emit(raw)
    assert '(data (;0;) (i32.const 11) "abc")' in text
    assert '(data (;1;) (memory 129) (i32.const 5) "xy")' in text
    assert '(data (;2;) "\\00\\ff\\"\\\\")' in text
    _assert_reparses(text)


def test_data_extended_const_offset():
    data = _section(
        11,
        _vec([b"\x00\x41\x01\x41\x02\x6a\x0b" + _name(b"z")]),
    )
    text = _emit(_HEADER + _section(5, _vec([b"\x00\x01"])) + data)
    assert '(data (;0;) (offset i32.const 1 i32.const 2 i32.add) "z")' in text


def test_memarg_offset_precedes_align():
    # i32.load align=1 (log2 0) offset=4
    text = _emit(_func_module(b"\x41\x00\x28\x00\x04\x1a", before=[]))
    assert "i32.load offset=4 align=1" in _body_lines(text)
    # Multi-memory: memory index, then offset, then alignment.
    text = _emit(_func_module(b"\x41\x00\x28\x40\x01\x08\x1a"))
    assert "i32.load 1 offset=8 align=1" in _body_lines(text)


def test_lane_memarg_keeps_memory_index():
    # v128.load8_lane with the multi-memory bit: memory 1, offset 4, lane 3.
    # Whether the collector records [mem, align, offset, lane] or only
    # [align, offset, lane], the memory index must reach the text.
    code = b"\x41\x00\xfd\x0c" + bytes(16) + b"\xfd\x54\x40\x01\x04\x03\x1a"
    memories = _section(5, _vec([b"\x00\x01", b"\x00\x01"]))
    text = _emit(_func_module(code, before=[], after=[memories]))
    assert "v128.load8_lane 1 offset=4 3" in _body_lines(text)
    # A 4-value lane record renders the same way.
    raw = _func_module(b"\x41\x00\xfd\x0c" + bytes(16) + b"\xfd\x55\x00\x08\x02\x1a")
    report = parse_wasm_bytes(raw, "test.wasm")
    for ins in report["functions"][0]["instructions"]:
        if ins["opcode"] == "v128.load16_lane":
            ins["immediates"] = [2, 0, 8, 2]
    lines = _body_lines(emit_wat(report, source=raw))
    assert "v128.load16_lane 2 offset=8 align=1 2" in lines


def test_v128_memarg_natural_widths():
    # v128.load8x8_s with its natural 8-byte alignment renders bare.
    text = _emit(_func_module(b"\x41\x00\xfd\x01\x03\x00\x1a"))
    assert "v128.load8x8_s" in _body_lines(text)


def test_mutable_global_import():
    imports = _section(
        2, _vec([_name(b"m") + _name(b"g") + b"\x03\x7f\x01"])
    )
    text = _emit(_HEADER + imports)
    assert '(import "m" "g" (global (;0;) (mut i32)))' in text
    _assert_reparses(text)


def test_memory_and_table_import_limits():
    imports = _section(
        2,
        _vec(
            [
                # memory: flags has-max | shared | i64, min 1, max 5
                _name(b"m") + _name(b"mem") + b"\x02\x07\x01\x05",
                # table: externref, flags has-max | i64, min 1, max 3
                _name(b"m") + _name(b"tab") + b"\x01\x6f\x05\x01\x03",
            ]
        ),
    )
    text = _emit(_HEADER + imports)
    assert '(import "m" "mem" (memory (;0;) i64 1 5 shared))' in text
    assert '(import "m" "tab" (table (;0;) i64 1 3 externref))' in text
    _assert_reparses(text)


def test_float_constants_keep_nan_payload_and_sign():
    code = (
        b"\x43" + struct.pack("<I", 0x7FA00000) + b"\x1a"  # nan:0x200000 (signalling)
        + b"\x43" + struct.pack("<I", 0xFFC00000) + b"\x1a"  # -nan
        + b"\x44" + struct.pack("<Q", 0x7FF0000000000001) + b"\x1a"
        + b"\x43" + struct.pack("<I", 0x80000001) + b"\x1a"  # -0x1p-149
        + b"\x44" + struct.pack("<d", 0.1) + b"\x1a"
        + b"\x43" + struct.pack("<I", 0xFF800000) + b"\x1a"  # -inf
    )
    lines = _body_lines(_emit(_func_module(code)))
    assert "f32.const nan:0x200000" in lines
    assert "f32.const -nan:0x400000" in lines
    assert "f64.const nan:0x1" in lines
    assert "f32.const -0x1p-149" in lines
    assert "f64.const 0x1.999999999999ap-4" in lines
    assert "f32.const -inf" in lines


def test_global_initializers_are_exact():
    globals_ = _section(
        6,
        _vec(
            [
                b"\x7d\x00\x43" + struct.pack("<f", 3.14159265) + b"\x0b",
                b"\x7f\x00\x41\x01\x41\x02\x6a\x0b",
            ]
        ),
    )
    text = _emit(_HEADER + globals_)
    assert "(global (;0;) f32 (f32.const 0x1.921fb6p+1))" in text
    assert "(global (;1;) i32 i32.const 1 i32.const 2 i32.add)" in text
    _assert_reparses(text)


def test_try_table_catch_clauses_and_block_types():
    tags = _section(13, _vec([b"\x00\x00"]))
    code = (
        # try_table (type 1) (catch_all_ref 0) (catch 0 1) end
        b"\x1f\x01\x02\x03\x00\x00\x00\x01\x0b"
        # try_table (result externref) end
        + b"\x1f\x6f\x00\x0b"
    )
    lines = _body_lines(_emit(_func_module(code, after=[tags])))
    assert "try_table (type 1) (catch_all_ref 0) (catch 0 1)" in lines
    assert "try_table (result externref)" in lines


def test_legacy_try_keeps_block_type_and_catch_tag():
    tags = _section(13, _vec([b"\x00\x00"]))
    # try (result i32) i32.const 1 catch 0 i32.const 2 catch_all i32.const 3
    # end drop; try delegate 0
    code = (
        b"\x06\x7f\x41\x01\x07\x00\x41\x02\x19\x41\x03\x0b\x1a"
        + b"\x06\x40\x18\x00"
        + b"\x06\x40\x07\x00\x09\x00\x0b"
    )
    lines = _body_lines(_emit(_func_module(code, after=[tags])))
    assert "try (result i32)" in lines
    assert "catch 0" in lines
    assert "catch_all" in lines
    assert "delegate 0" in lines
    assert "rethrow 0" in lines


def test_immediates_are_never_dropped():
    code = (
        b"\xd0\x70\xd5\x00\x1a"  # ref.null func; br_on_null 0; drop
        + b"\xd0\x70\xd6\x00"  # br_on_non_null 0
        + b"\xfd\x0c" + bytes(16)  # v128.const
        + b"\xfd\x15\x03\x1a"  # i8x16.extract_lane_s 3
        + b"\xfd\x0c" + bytes(16) + b"\xfd\x1b\x02\x1a"  # i32x4.extract_lane 2
        + b"\xfd\x0c" + bytes(16) + b"\xfd\x0c" + bytes(16)
        + b"\xfd\x0d" + bytes(range(16)) + b"\x1a"  # i8x16.shuffle
        + b"\x00\xfb\x02\x00\x01"  # struct.get 0 1
        + b"\x00\xfb\x08\x00\x03"  # array.new_fixed 0 3
        + b"\x3f\x01\x1a"  # memory.size 1
        + b"\x41\x00\x40\x02\x1a"  # memory.grow 2
        + b"\x00\xfb\x17\x6e"  # ref.cast (ref null any)
        + b"\x00\xfb\x18\x02\x00\x6e\x00"  # br_on_cast 0 (ref any) (ref null 0)
        + b"\x41\x00\x41\x00\x41\x00\xfc\x08\x02\x01"  # memory.init 1 2
    )
    text = _emit(_func_module(code))
    lines = _body_lines(text)
    for expected in (
        "br_on_null 0",
        "br_on_non_null 0",
        "i8x16.extract_lane_s 3",
        "i32x4.extract_lane 2",
        "i8x16.shuffle " + " ".join(str(i) for i in range(16)),
        "struct.get 0 1",
        "array.new_fixed 0 3",
        "memory.size 1",
        "memory.grow 2",
        "ref.cast (ref null any)",
        "br_on_cast 0 (ref any) (ref null 0)",
        "memory.init 1 2",
    ):
        assert expected in lines, expected
    _assert_reparses(text)


def test_unrenderable_instruction_marks_emission_incomplete():
    raw = _func_module(b"\x41\x00\x1a")
    report = parse_wasm_bytes(raw, "test.wasm")
    instructions = report["functions"][0]["instructions"]
    instructions[0]["immediates"] = []  # i32.const without its value
    instructions.insert(1, {"offset": 0, "opcode": "unknown_fb_99", "immediates": []})
    text = emit_wat(report, source=raw)
    assert "i32.const\n" not in text
    assert ";; unrenderable instruction i32.const" in text
    assert ";; unrenderable instruction unknown_fb_99" in text
    assert ";; emission incomplete" in text


def test_hostile_names_are_escaped():
    hostile = b'a"b\\c\n\t\x00\xe5\x8a\xa0) (func $evil'
    exports = _section(7, _vec([_name(hostile) + b"\x00\x00"]))
    imports = _section(2, _vec([_name(b'm"') + _name(b"n\\") + b"\x00\x00"]))
    names = _section(
        0, _name(b"name") + b"\x01" + _name(_vec([_leb(1) + _name(b'f" (x')]))
    )
    raw = (
        _HEADER
        + _TYPES
        + imports
        + _section(3, _vec([b"\x00"]))
        + exports
        + _section(10, _vec([b"\x02\x00\x0b"]))
        + names
    )
    text = _emit(raw)
    assert '(export "a\\"b\\\\c\\n\\t\\00\\e5\\8a\\a0) (func $evil" (func 0))' in text
    assert '(import "m\\"" "n\\\\" (func (;0;) (type 0)))' in text
    assert '(func $"f\\" (x" (;1;) (type 0)' in text
    if _rust_wasm_tools():
        code, stderr, rebuilt = _assemble("wasm-tools", text)
        assert code == 0, stderr
        again = parse_wasm_bytes(rebuilt, "rebuilt.wasm")
        assert again["exports"][0]["name"] == hostile.decode("utf-8")
        assert again["functions"][0]["name"] == 'f" (x'


def test_element_expression_segments():
    table = _section(4, _vec([b"\x70\x00\x02"]))
    elements = _section(
        9,
        _vec(
            [
                # flags 4: offset, funcref expressions
                b"\x04\x41\x00\x0b" + _vec([b"\xd2\x00\x0b", b"\xd0\x70\x0b"]),
                # flags 7: declarative, reftype, expressions
                b"\x07\x70" + _vec([b"\xd2\x00\x0b"]),
                # flags 2: explicit table, elemkind, indices
                b"\x02\x00\x41\x01\x0b\x00" + _vec([b"\x00"]),
            ]
        ),
    )
    text = _emit(_func_module(b"", before=[table], after=[elements]))
    assert "(elem (;0;) (i32.const 0) funcref (item ref.func 0) (item ref.null func))" in text
    assert "(elem (;1;) declare funcref (item ref.func 0))" in text
    assert "(elem (;2;) (table 0) (i32.const 1) func 0)" in text
    _assert_reparses(text)


def test_without_source_payloads_are_marked_incomplete():
    data = _section(11, _vec([b"\x01" + _name(b"abc")]))
    raw = _HEADER + _section(5, _vec([b"\x00\x01"])) + data
    text = emit_wat(parse_wasm_bytes(raw, "test.wasm"))
    assert "payload not emitted" in text
    assert ";; emission incomplete" in text
