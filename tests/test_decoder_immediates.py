"""Decoder checks for SIMD lane memargs, try_table catch kinds and f16x8.

The module bytes here were produced by the Rust wasm-tools 1.263
(`wasm-tools parse`) and checked with `wasm-tools validate --features all`;
the WAT source sits next to each blob so the bytes can be regenerated. The
f16x8 expectations are written out from the half-precision proposal's
Overview.md rather than read from wasm_tools.opcodes, so a wrong table entry
fails here instead of agreeing with itself.
"""

from pathlib import Path

from wasm_tools.api import parse_wasm_bytes

_FIXTURES = Path(__file__).parent / "fixtures"

# (module
#   (memory $a 1)
#   (memory $b 1)
#   (func (export "f") (param v128) (result v128)
#     i32.const 0  local.get 0  v128.load8_lane 1 offset=4 3
#     i32.const 0  local.get 0  v128.load16_lane $b offset=8 2
#     drop)
#   (func (export "g") (param v128)
#     i32.const 0  local.get 0  v128.store32_lane $b 1
#     i32.const 0  local.get 0  v128.store64_lane 1))
_MULTI_MEMORY_LANES = bytes.fromhex(
    "0061736d01000000010a0260017b017b60017b0003030200010505020001000107090201"
    "660000016700010a2f02170041002000fd544001040341002000fd55410108021a0b1500"
    "41002000fd5a4201000141002000fd5b0300010b000e046e616d65060702000161010162"
)

# (module
#   (tag $e)
#   (func (export "f") (result i32)
#     (block $h (try_table (catch_all $h) throw $e))
#     i32.const 7))
_TRY_TABLE_CATCH_ALL = bytes.fromhex(
    "0061736d010000000108026000006000017f030201010d03010000070501016600000a11"
    "010f0002401f4001020008000b0b41070b0013046e616d6503060100010001680b040100"
    "0165"
)


def _ops(report, fn_pos=0):
    return [
        (ins["opcode"], ins["immediates"])
        for ins in report["functions"][fn_pos]["instructions"]
    ]


def test_lane_memarg_honours_multi_memory_bit():
    report = parse_wasm_bytes(_MULTI_MEMORY_LANES, "lanes.wasm")
    assert report["errors"] == []
    f_ops = _ops(report, 0)
    g_ops = _ops(report, 1)
    # Before the fix the memory index byte was read as the offset, the
    # offset as the lane, and the real lane byte as a bogus opcode.
    assert [op for op, _ in f_ops] == [
        "i32.const", "local.get", "v128.load8_lane",
        "i32.const", "local.get", "v128.load16_lane",
        "drop", "end",
    ]
    assert [op for op, _ in g_ops] == [
        "i32.const", "local.get", "v128.store32_lane",
        "i32.const", "local.get", "v128.store64_lane",
        "end",
    ]
    load8 = dict(f_ops)["v128.load8_lane"]
    load16 = dict(f_ops)["v128.load16_lane"]
    store32 = dict(g_ops)["v128.store32_lane"]
    # align, offset and lane survive with the multi-memory flag cleared.
    assert load8[-3:] == [0, 4, 3]
    assert load16[-3:] == [1, 8, 2]
    assert store32[-3:] == [2, 0, 1]
    assert dict(g_ops)["v128.store64_lane"][-3:] == [3, 0, 1]
    assert report["analysis"]["summary"]["unknown_opcode_count"] == 0


def test_lane_memarg_passes_memory_index_to_delegates_that_take_it():
    from wasm_tools.parser import BinaryReader
    from wasm_tools.visitor import BinaryReaderNop

    class Recorder(BinaryReaderNop):
        def __init__(self):
            super().__init__()
            self.lanes = []

        def on_opcode_memarg_lane(self, align, mem_offset, lane, mem_idx=None):
            self.lanes.append((align, mem_offset, lane, mem_idx))

    recorder = Recorder()
    BinaryReader(_MULTI_MEMORY_LANES, recorder).read_module()
    assert recorder.lanes == [
        (0, 4, 3, 1),
        (1, 8, 2, 1),
        (2, 0, 1, 1),
        (3, 0, 1, None),
    ]


def test_try_table_known_catch_kind_decodes():
    report = parse_wasm_bytes(_TRY_TABLE_CATCH_ALL, "tt.wasm")
    assert report["errors"] == []
    assert ("try_table", [-64, 2, 0]) in _ops(report)


def test_try_table_unknown_catch_kind_is_a_parse_error():
    marker = bytes.fromhex("1f40010200")  # try_table, 1 catch, catch_all 0
    at = _TRY_TABLE_CATCH_ALL.index(marker)
    for kind in (0x04, 0x05, 0xFF):
        bad = bytearray(_TRY_TABLE_CATCH_ALL)
        bad[at + 3] = kind
        report = parse_wasm_bytes(bytes(bad), "bad-tt.wasm")
        assert any("catch kind" in str(err) for err in report["errors"]), kind
        decoded = [
            ins["opcode"] for fn in report["functions"] for ins in fn["instructions"]
        ]
        assert "throw" not in decoded, "decoding must stop at the malformed clause"


# Half-precision proposal, Overview.md "Binary format" and the typing rules
# in its Instructions section: (opcode, mnemonic, operand types, result).
_F16_SPEC = {
    (0xFC, 0x30): ("f32.load_f16", ["i32"], ["f32"]),
    (0xFC, 0x31): ("f32.store_f16", ["i32", "f32"], []),
    (0xFD, 0x120): ("f16x8.splat", ["f32"], ["v128"]),
    (0xFD, 0x121): ("f16x8.extract_lane", ["v128"], ["f32"]),
    (0xFD, 0x122): ("f16x8.replace_lane", ["v128", "f32"], ["v128"]),
    **{
        (0xFD, code): (name, ["v128"], ["v128"])
        for code, name in (
            (0x130, "f16x8.abs"),
            (0x131, "f16x8.neg"),
            (0x132, "f16x8.sqrt"),
            (0x133, "f16x8.ceil"),
            (0x134, "f16x8.floor"),
            (0x135, "f16x8.trunc"),
            (0x136, "f16x8.nearest"),
            (0x145, "i16x8.trunc_sat_f16x8_s"),
            (0x146, "i16x8.trunc_sat_f16x8_u"),
            (0x147, "f16x8.convert_i16x8_s"),
            (0x148, "f16x8.convert_i16x8_u"),
            (0x149, "f16x8.demote_f32x4_zero"),
            (0x14A, "f16x8.demote_f64x2_zero"),
            (0x14B, "f32x4.promote_low_f16x8"),
            (0x14C, "i16x8.trunc_f16x8_s"),
            (0x14D, "i16x8.trunc_f16x8_u"),
        )
    },
    **{
        (0xFD, code): (name, ["v128", "v128"], ["v128"])
        for code, name in (
            (0x137, "f16x8.eq"),
            (0x138, "f16x8.ne"),
            (0x139, "f16x8.lt"),
            (0x13A, "f16x8.gt"),
            (0x13B, "f16x8.le"),
            (0x13C, "f16x8.ge"),
            (0x13D, "f16x8.add"),
            (0x13E, "f16x8.sub"),
            (0x13F, "f16x8.mul"),
            (0x140, "f16x8.div"),
            (0x141, "f16x8.min"),
            (0x142, "f16x8.max"),
            (0x143, "f16x8.pmin"),
            (0x144, "f16x8.pmax"),
        )
    },
    (0xFD, 0x14E): ("f16x8.madd", ["v128", "v128", "v128"], ["v128"]),
    (0xFD, 0x14F): ("f16x8.nmadd", ["v128", "v128", "v128"], ["v128"]),
}


def _encode_leb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def test_f16_opcodes_decode_to_proposal_names():
    for (prefix, code), (name, _params, _results) in _F16_SPEC.items():
        if prefix == 0xFC:
            imm = b"\x01\x00"  # memarg: align 1, offset 0
        elif code in (0x121, 0x122):
            imm = b"\x00"  # lane index
        else:
            imm = b""
        body = bytes([prefix]) + _encode_leb(code) + imm + b"\x0b"
        module = (
            b"\x00asm\x01\x00\x00\x00"
            + b"\x01\x04\x01\x60\x00\x00"  # type () -> ()
            + b"\x03\x02\x01\x00"  # one function
            + b"\x05\x03\x01\x00\x01"  # one memory
            + b"\x0a"
            + _encode_leb(len(body) + 2)
            + b"\x01"
            + _encode_leb(len(body) + 1)
            + b"\x00"
            + body
        )
        report = parse_wasm_bytes(module, "op.wasm")
        decoded = [i["opcode"] for i in report["functions"][0]["instructions"]]
        assert decoded[0] == name, (hex(code), decoded)
        assert decoded[1:] == ["end"], (hex(code), decoded)


def test_f16x8_fixture_uses_every_opcode_and_is_well_typed():
    data = (_FIXTURES / "f16x8_binary.wasm").read_bytes()
    report = parse_wasm_bytes(data, "f16x8_binary.wasm")
    assert report["errors"] == []
    instructions = report["functions"][0]["instructions"]
    names = {spec[0]: spec for spec in _F16_SPEC.values()}
    used = {ins["opcode"] for ins in instructions if ins["opcode"] in names}
    assert used == set(names), sorted(set(names) - used)

    # No assembler accepts f16 yet, so type-check the one function by hand
    # against the proposal's signatures: params are three v128 values, the
    # result is one v128, and only the handful of core opcodes the builder
    # uses appear besides the f16 ones.
    core = {
        "local.get": ([], ["v128"]),
        "i32.const": ([], ["i32"]),
        "drop": (["any"], []),
    }
    stack = []
    for ins in instructions[:-1]:
        op = ins["opcode"]
        if op in names:
            _name, params, results = names[op]
        else:
            assert op in core, op
            params, results = core[op]
        for want in reversed(params):
            assert stack, f"{op} at {ins['offset']} pops an empty stack"
            got = stack.pop()
            assert want in ("any", got), f"{op} wanted {want}, got {got}"
        stack.extend(results)
    assert instructions[-1]["opcode"] == "end"
    assert stack == ["v128"]
