# tests/test_extended_ops.py
"""Tests for extended opcode families: SIMD, atomics, GC, exceptions, table-bulk, sat-trunc."""

import os
import struct

import pytest

from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.opcodes import OPCODES, ImmType
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import BinaryReaderObjdumpDisassemble, BinaryReaderObjdumpPrepass

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> bytes:
    path = os.path.join(FIXTURES_DIR, name)
    if not os.path.exists(path):
        pytest.skip(f"fixture {name} not found (run tests/fixtures/build.py)")
    with open(path, "rb") as f:
        return f.read()


def _disassemble(data: bytes) -> str:
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        BinaryReader(data, BinaryReaderObjdumpDisassemble(data, options, state)).read_module()
    return buf.getvalue()


# ─── Opcode table completeness ────────────────────────────────────────────────

def test_core_i32_arithmetic_in_table():
    for code, name in [
        (0x6A, "i32.add"), (0x6B, "i32.sub"), (0x6C, "i32.mul"),
        (0x67, "i32.clz"), (0x68, "i32.ctz"), (0x69, "i32.popcnt"),
        (0x74, "i32.shl"), (0x75, "i32.shr_s"), (0x76, "i32.shr_u"),
    ]:
        assert (0, code) in OPCODES, f"Missing (0, {code:#x}) = {name}"
        assert OPCODES[(0, code)][0] == name


def test_core_i64_arithmetic_in_table():
    for code, name in [
        (0x7C, "i64.add"), (0x7D, "i64.sub"), (0x7E, "i64.mul"),
        (0x86, "i64.shl"), (0x87, "i64.shr_s"), (0x88, "i64.shr_u"),
    ]:
        assert (0, code) in OPCODES, f"Missing (0, {code:#x}) = {name}"
        assert OPCODES[(0, code)][0] == name


def test_core_f32_f64_arithmetic_in_table():
    for code, name in [
        (0x92, "f32.add"), (0x93, "f32.sub"), (0x94, "f32.mul"), (0x95, "f32.div"),
        (0xA0, "f64.add"), (0xA1, "f64.sub"), (0xA2, "f64.mul"), (0xA3, "f64.div"),
    ]:
        assert (0, code) in OPCODES, f"Missing (0, {code:#x}) = {name}"


def test_sign_extension_in_table():
    for code, name in [
        (0xC0, "i32.extend8_s"), (0xC1, "i32.extend16_s"),
        (0xC2, "i64.extend8_s"), (0xC3, "i64.extend16_s"), (0xC4, "i64.extend32_s"),
    ]:
        assert (0, code) in OPCODES
        assert OPCODES[(0, code)][0] == name


def test_conversions_in_table():
    assert OPCODES[(0, 0xA7)][0] == "i32.wrap_i64"
    assert OPCODES[(0, 0xAC)][0] == "i64.extend_i32_s"
    assert OPCODES[(0, 0xAD)][0] == "i64.extend_i32_u"
    assert OPCODES[(0, 0xBB)][0] == "f64.promote_f32"


def test_reference_types_in_table():
    assert OPCODES[(0, 0xD0)][1] == ImmType.HEAP_TYPE   # ref.null
    assert OPCODES[(0, 0xD1)][0] == "ref.is_null"
    assert OPCODES[(0, 0xD2)][0] == "ref.func"
    assert OPCODES[(0, 0xD3)][0] == "ref.eq"
    assert OPCODES[(0, 0xD5)][0] == "br_on_null"
    assert OPCODES[(0, 0xD6)][0] == "br_on_non_null"


def test_saturating_trunc_in_table():
    for i, name in enumerate([
        "i32.trunc_sat_f32_s", "i32.trunc_sat_f32_u",
        "i32.trunc_sat_f64_s", "i32.trunc_sat_f64_u",
        "i64.trunc_sat_f32_s", "i64.trunc_sat_f32_u",
        "i64.trunc_sat_f64_s", "i64.trunc_sat_f64_u",
    ]):
        assert (0xFC, i) in OPCODES
        assert OPCODES[(0xFC, i)][0] == name


def test_bulk_memory_in_table():
    assert OPCODES[(0xFC, 8)][0] == "memory.init"
    assert OPCODES[(0xFC, 9)][0] == "data.drop"
    assert OPCODES[(0xFC, 10)][0] == "memory.copy"
    assert OPCODES[(0xFC, 11)][0] == "memory.fill"


def test_table_bulk_in_table():
    assert OPCODES[(0xFC, 12)][0] == "table.init"
    assert OPCODES[(0xFC, 13)][0] == "elem.drop"
    assert OPCODES[(0xFC, 14)][0] == "table.copy"
    assert OPCODES[(0xFC, 15)][0] == "table.grow"
    assert OPCODES[(0xFC, 16)][0] == "table.size"
    assert OPCODES[(0xFC, 17)][0] == "table.fill"


def test_gc_opcodes_in_table():
    assert OPCODES[(0xFB, 0)][0] == "struct.new"
    assert OPCODES[(0xFB, 6)][0] == "array.new"
    assert OPCODES[(0xFB, 15)][0] == "array.len"
    assert OPCODES[(0xFB, 20)][0] == "ref.test"
    assert OPCODES[(0xFB, 22)][0] == "ref.cast"
    assert OPCODES[(0xFB, 24)][1] == ImmType.BR_ON_CAST
    assert OPCODES[(0xFB, 28)][0] == "ref.i31"


def test_exception_opcodes_in_table():
    assert OPCODES[(0, 0x08)][0] == "throw"
    assert OPCODES[(0, 0x0A)][0] == "throw_ref"
    assert OPCODES[(0, 0x1F)][1] == ImmType.TRY_TABLE_BLOCK


def test_return_call_opcodes_in_table():
    assert OPCODES[(0, 0x12)][0] == "return_call"
    assert OPCODES[(0, 0x13)][0] == "return_call_indirect"
    assert OPCODES[(0, 0x14)][0] == "call_ref"
    assert OPCODES[(0, 0x15)][0] == "return_call_ref"


def test_simd_memory_ops_in_table():
    assert OPCODES[(0xFD, 0)][0] == "v128.load"
    assert OPCODES[(0xFD, 0)][1] == ImmType.MEMARG
    assert OPCODES[(0xFD, 11)][0] == "v128.store"
    assert OPCODES[(0xFD, 12)][1] == ImmType.V128_CONST
    assert OPCODES[(0xFD, 13)][1] == ImmType.V128_SHUFFLE


def test_simd_lane_ops_in_table():
    assert OPCODES[(0xFD, 21)][0] == "i8x16.extract_lane_s"
    assert OPCODES[(0xFD, 21)][1] == ImmType.LANE_IDX
    assert OPCODES[(0xFD, 84)][1] == ImmType.MEMARG_LANE
    assert OPCODES[(0xFD, 84)][0] == "v128.load8_lane"


def test_simd_arithmetic_in_table():
    assert OPCODES[(0xFD, 174)][0] == "i32x4.add"
    assert OPCODES[(0xFD, 228)][0] == "f32x4.add"
    assert OPCODES[(0xFD, 240)][0] == "f64x2.add"


def test_threads_memarg_ops_in_table():
    assert OPCODES[(0xFE, 0x00)][0] == "memory.atomic.notify"
    assert OPCODES[(0xFE, 0x00)][1] == ImmType.MEMARG
    assert OPCODES[(0xFE, 0x1E)][0] == "i32.atomic.rmw.add"
    assert OPCODES[(0xFE, 0x03)][1] == ImmType.ATOMIC_FENCE


# ─── ImmType dispatch (synthetic modules) ────────────────────────────────────

def _leb(v: int) -> bytes:
    """Encode unsigned LEB128."""
    out = []
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            b |= 0x80
        out.append(b)
        if not v:
            break
    return bytes(out)


def _make_module(body: bytes) -> bytes:
    """Minimal module with one function body."""
    header = b"\x00asm\x01\x00\x00\x00"
    func_sec = b"\x03\x02\x01\x00"  # section 3, size 2, count 1, sig 0
    code_payload = b"\x01" + _leb(len(body)) + body
    code_sec = bytes([0x0A, len(code_payload)]) + code_payload
    return header + func_sec + code_sec


def test_dispatch_br_table(capsys):
    # br_table with 2 targets + default
    body = bytes([0x00]) + bytes([0x0E]) + _leb(2) + _leb(0) + _leb(1) + _leb(0) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "br_table" in out


def test_dispatch_select_t(capsys):
    # select t (0x1C) with type vec [i32]
    body = bytes([0x00, 0x1C, 0x01, 0x7F, 0x0B])
    out = _disassemble(_make_module(body))
    assert "select" in out


def test_dispatch_table_ops(capsys):
    # table.size (0xFC 16) table_idx=0
    body = bytes([0x00, 0xFC]) + _leb(16) + _leb(0) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "table.size" in out


def test_dispatch_table_copy(capsys):
    # table.copy (0xFC 14) dst=0 src=0
    body = bytes([0x00, 0xFC]) + _leb(14) + _leb(0) + _leb(0) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "table.copy" in out


def test_dispatch_sat_trunc(capsys):
    # i32.trunc_sat_f32_s (0xFC 0)
    body = bytes([0x00, 0xFC, 0x00, 0x0B])
    out = _disassemble(_make_module(body))
    assert "i32.trunc_sat_f32_s" in out


def test_dispatch_v128_const(capsys):
    # v128.const (0xFD 12) + 16 bytes
    body = bytes([0x00]) + bytes([0xFD]) + _leb(12) + bytes(16) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "v128.const" in out


def test_dispatch_i8x16_shuffle(capsys):
    # i8x16.shuffle (0xFD 13) + 16 lane bytes
    body = bytes([0x00]) + bytes([0xFD]) + _leb(13) + bytes(range(16)) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "i8x16.shuffle" in out


def test_dispatch_lane_extract(capsys):
    # i32x4.extract_lane (0xFD 27) lane=0
    body = bytes([0x00, 0xFD]) + _leb(27) + bytes([0]) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "i32x4.extract_lane" in out


def test_dispatch_v128_load_bare(capsys):
    # v128.load (0xFD 0) memarg align=0 offset=0
    body = bytes([0x00, 0xFD]) + _leb(0) + _leb(0) + _leb(0) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "v128.load" in out


def test_dispatch_gc_array_len(capsys):
    # array.len (0xFB 15)
    body = bytes([0x00, 0xFB]) + _leb(15) + bytes([0x0B])
    out = _disassemble(_make_module(body))
    assert "array.len" in out


def test_dispatch_throw(capsys):
    # throw (0x08) tag=0
    body = bytes([0x00, 0x08, 0x00, 0x0B])
    out = _disassemble(_make_module(body))
    assert "throw" in out


# ─── Fixture-based tests ──────────────────────────────────────────────────────

def test_simd_basic_fixture_disassembly(capsys):
    data = _fixture("simd_basic.wasm")
    out = _disassemble(data)
    assert "v128.load" in out or "v128.const" in out or "i32x4" in out


def test_exceptions_basic_fixture_disassembly(capsys):
    data = _fixture("exceptions_basic.wasm")
    out = _disassemble(data)
    assert "throw" in out or "try_table" in out


def test_threads_basic_fixture_disassembly(capsys):
    data = _fixture("threads_basic.wasm")
    out = _disassemble(data)
    assert "atomic" in out

