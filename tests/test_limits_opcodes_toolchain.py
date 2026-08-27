"""Tests for post-3.0 limits flags, opcodes, and toolchain custom sections."""

from pathlib import Path

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.opcodes import OPCODES, ImmType
from wasm_tools.parser import BinaryReader

_FIXTURES = Path(__file__).parent / "fixtures"


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


def _core_module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _leb(len(payload)) + payload


def _name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _leb(len(raw)) + raw


class _Collector:
    def __init__(self) -> None:
        self.offset = 0
        self.ops: list[tuple[str, list]] = []

    def begin_module(self, version: int) -> None:
        pass

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        pass

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        pass

    def on_opcode(self, opcode) -> None:
        self.ops.append([opcode.name, []])

    def on_opcode_bare(self) -> None:
        pass

    def on_end_expr(self) -> None:
        pass

    def on_opcode_uint32_uint32(self, a, b) -> None:
        self.ops[-1][1].extend([a, b])

    def on_opcode_lane_idx(self, lane) -> None:
        self.ops[-1][1].append(lane)


def _decode_body(body: bytes) -> list[tuple[str, list]]:
    """Wrap opcodes in a minimal code body and decode them."""
    # code section: 1 function, body = locals(0) + body
    body_bytes = _leb(0) + body
    code = _section(10, _leb(1) + _leb(len(body_bytes)) + body_bytes)
    module = _core_module(code)
    collector = _Collector()
    BinaryReader(module, collector).read_module()
    return collector.ops


# ─── limits flags ───────────────────────────────────────────────────────────


def test_memory_section_custom_page_size_decodes():
    # flag 0x08: no max, i32, page_size_log2=0 (1-byte pages)
    payload = _leb(1) + b"\x08" + _leb(1) + _leb(0)
    report = parse_wasm_bytes(_core_module(_section(5, payload)))
    assert report["errors"] == []
    limits = report["memories"][0]["limits"]
    assert limits == {
        "min": 1,
        "max": None,
        "is_64": False,
        "shared": False,
        "page_size_log2": 0,
    }


def test_memory_section_max_plus_custom_page_size_decodes():
    # flag 0x09: has max + page size; page exponent read after the max
    payload = _leb(1) + b"\x09" + _leb(2) + _leb(4) + _leb(16)
    report = parse_wasm_bytes(_core_module(_section(5, payload)))
    assert report["errors"] == []
    limits = report["memories"][0]["limits"]
    assert limits["min"] == 2
    assert limits["max"] == 4
    assert limits["page_size_log2"] == 16


def test_shared_flag_visible_in_report():
    # flag 0x03: has max + shared
    payload = _leb(1) + b"\x03" + _leb(1) + _leb(2)
    report = parse_wasm_bytes(_core_module(_section(5, payload)))
    assert report["errors"] == []
    assert report["memories"][0]["limits"]["shared"] is True


# ─── wide arithmetic ─────────────────────────────────────────────────────────


def test_wide_arithmetic_opcodes_in_table():
    assert OPCODES[(0xFC, 19)] == ("i64.add128", ImmType.NONE)
    assert OPCODES[(0xFC, 20)] == ("i64.sub128", ImmType.NONE)
    assert OPCODES[(0xFC, 21)] == ("i64.mul_wide_s", ImmType.NONE)
    assert OPCODES[(0xFC, 22)] == ("i64.mul_wide_u", ImmType.NONE)


def test_wide_arithmetic_dispatch():
    ops = _decode_body(b"\xFC\x13\xFC\x14\x0B")
    assert ops[0] == ["i64.add128", []]
    assert ops[1] == ["i64.sub128", []]


# ─── half precision ──────────────────────────────────────────────────────────


def test_f16_scalar_memory_ops_in_table():
    assert OPCODES[(0xFC, 48)] == ("f32.load_f16", ImmType.MEMARG)
    assert OPCODES[(0xFC, 49)] == ("f32.store_f16", ImmType.MEMARG)


def test_f16x8_simd_ops_in_table():
    assert OPCODES[(0xFD, 288)] == ("f16x8.splat", ImmType.NONE)
    assert OPCODES[(0xFD, 289)] == ("f16x8.extract_lane", ImmType.LANE_IDX)
    assert OPCODES[(0xFD, 290)] == ("f16x8.replace_lane", ImmType.LANE_IDX)
    for code, name in (
        (304, "f16x8.abs"),
        (305, "f16x8.neg"),
        (306, "f16x8.sqrt"),
        (307, "f16x8.ceil"),
        (308, "f16x8.floor"),
        (309, "f16x8.trunc"),
        (310, "f16x8.nearest"),
        (311, "f16x8.eq"),
        (312, "f16x8.ne"),
        (313, "f16x8.lt"),
        (314, "f16x8.gt"),
        (315, "f16x8.le"),
        (316, "f16x8.ge"),
    ):
        assert OPCODES[(0xFD, code)] == (name, ImmType.NONE)


def test_f16_dispatch():
    # 0xFC 0x30 = f32.load_f16 with memarg align=2 offset=0
    ops = _decode_body(b"\xFC\x30\x02\x00\x0B")
    assert ops[0] == ["f32.load_f16", [2, 0]]
    # 0xFD 288 (0x120) = f16x8.splat; 289 = extract_lane 3
    ops = _decode_body(b"\xFD\xA0\x02\xFD\xA1\x02\x03\x0B")
    assert ops[0] == ["f16x8.splat", []]
    assert ops[1] == ["f16x8.extract_lane", [3]]


# ─── producers / target_features custom sections ────────────────────────────


def _producers_section() -> bytes:
    # 1 field: "language" with 1 entry ("Rust", "1.80.1")
    payload = _name("producers") + _leb(1)
    payload += _name("language") + _leb(1) + _name("Rust") + _name("1.80.1")
    return _section(0, payload)


def _target_features_section() -> bytes:
    payload = (
        _name("target_features")
        + _leb(2)
        + b"\x2B"
        + _name("simd128")  # '+' enabled
        + b"\x2D"
        + _name("atomics")  # '-' disabled
    )
    return _section(0, payload)


def test_producers_section_decodes_into_toolchain():
    report = parse_wasm_bytes(_core_module(_producers_section()))
    assert report["errors"] == []
    toolchain = report["toolchain"]
    assert toolchain["languages"] == ["Rust"]
    assert toolchain["processed_by"] == []


def test_producers_processed_by_entries_decode():
    payload = _name("producers") + _leb(1)
    payload += (
        _name("processed-by")
        + _leb(2)
        + _name("clang")
        + _name("18.0.0")
        + _name("wasm-bindgen")
        + _name("0.2.92")
    )
    report = parse_wasm_bytes(_core_module(_section(0, payload)))
    toolchain = report["toolchain"]
    assert toolchain["processed_by"] == [
        {"name": "clang", "version": "18.0.0"},
        {"name": "wasm-bindgen", "version": "0.2.92"},
    ]


def test_target_features_section_decodes():
    report = parse_wasm_bytes(
        _core_module(_producers_section(), _target_features_section())
    )
    assert report["errors"] == []
    features = report["toolchain"]["target_features"]
    assert {"enabled": True, "name": "simd128"} in features
    assert {"enabled": False, "name": "atomics"} in features


def test_malformed_producers_section_does_not_break_module():
    # Truncated producers payload must not abort parsing later sections.
    bad = _section(0, _name("producers") + b"\x01" + _name("language"))
    mem = _section(5, _leb(1) + b"\x00" + _leb(1))
    report = parse_wasm_bytes(_core_module(bad, mem))
    assert report["errors"] == []
    assert report["toolchain"]["languages"] == []
    assert report["memories"][0]["limits"]["min"] == 1


# ─── data segment offset values ──────────────────────────────────────────────


def test_data_segment_offset_value_captured():
    report = parse_wasm_bytes((_FIXTURES / "memory_data.wasm").read_bytes())
    assert report["errors"] == []
    assert all(
        isinstance(seg.get("offset_value"), int) or seg["mode"] == "passive"
        for seg in report["data_segments"]
    )


# ─── unknown opcode telemetry ────────────────────────────────────────────────


def test_unknown_opcode_summary_counts():
    # 0xC5 0x06 is not a mapped opcode in the current table.
    ops_guard = _decode_body(b"\xC5\x0B")
    assert ops_guard[0][0].startswith("unknown_")

    body = _leb(0) + b"\xC5\x0B"
    code = _section(10, _leb(1) + _leb(len(body)) + body)
    report = parse_wasm_bytes(_core_module(code))
    summary = report["analysis"]["summary"]
    assert summary["unknown_opcode_count"] >= 1
    assert any(op.startswith("unknown_") for op in summary["unknown_opcodes"])
