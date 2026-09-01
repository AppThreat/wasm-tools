import math
import struct

import pytest

from wasm_tools.parser import BinaryReader, WasmParseError


class DummyDelegate:
    """Mock delegate to capture output for tests."""

    def __init__(self):
        self.errors = []

    def begin_module(self, version):
        pass

    def begin_section(self, section_index, section_code, size):
        pass

    def on_error(self, message):
        self.errors.append(message)


class NoErrorDelegate:
    """Delegate variant without an on_error callback."""

    def begin_module(self, version):
        pass

    def begin_section(self, section_index, section_code, size):
        pass


def test_read_u8_and_u32():
    data = b"\x01\x02\x00\x00\x00"
    reader = BinaryReader(data, DummyDelegate())

    assert reader.read_u8() == 1
    assert reader.read_u32() == 2  # Little endian 0x00000002


def test_leb128_unsigned():
    # 624485 encoded as LEB128
    data = b"\xe5\x8e\x26"
    reader = BinaryReader(data, DummyDelegate())
    assert reader.read_leb128(signed=False) == 624485


def test_leb128_signed():
    # -624485 encoded as signed LEB128
    data = b"\x9b\xf1\x59"
    reader = BinaryReader(data, DummyDelegate())
    assert reader.read_leb128(signed=True) == -624485


def test_leb128_infinite_loop_protection():
    # A malformed LEB128 integer where the continuation bit is always set
    data = b"\xff" * 20
    reader = BinaryReader(data, DummyDelegate())
    with pytest.raises(WasmParseError, match="LEB128 exceeds maximum allowed length"):
        reader.read_leb128()


def test_fuzzer_truncated_file():
    # File is too small to even contain magic bytes
    data = b"\x00asm"
    delegate = DummyDelegate()
    reader = BinaryReader(data, delegate)
    reader.read_module()

    assert len(delegate.errors) == 1
    assert "File too small" in delegate.errors[0]


def test_fuzzer_truncated_section():
    # Valid magic, valid version, but section size extends past file end
    # Section ID 1 (Type), Size 100, but no actual data follows.
    data = b"\x00asm\x01\x00\x00\x00\x01\x64"
    delegate = DummyDelegate()
    reader = BinaryReader(data, delegate)
    reader.read_module()

    assert len(delegate.errors) == 1
    assert "Section length extends beyond file boundary" in delegate.errors[0]


def test_fuzzer_bad_magic():
    # Invalid magic bytes
    data = b"\x01asm\x01\x00\x00\x00"
    delegate = DummyDelegate()
    reader = BinaryReader(data, delegate)
    reader.read_module()

    assert len(delegate.errors) == 1
    assert "Bad magic value" in delegate.errors[0]


def test_read_f32_f64():
    # Test float 32 (1.5) -> Hex: 0x3FC00000 -> Little endian: 00 00 C0 3F
    data_f32 = b"\x00\x00\xc0\x3f"
    reader_f32 = BinaryReader(data_f32, DummyDelegate())
    assert reader_f32.read_f32() == 1.5

    # Test float 64 (3.14159)
    # Hex: 0x400921F9F01B866E -> Little endian: 6e 86 1b f0 f9 21 09 40
    data_f64 = b"\x6e\x86\x1b\xf0\xf9\x21\x09\x40"
    reader_f64 = BinaryReader(data_f64, DummyDelegate())
    assert math.isclose(reader_f64.read_f64(), 3.14159, rel_tol=1e-5)


def test_read_string_valid():
    # Length 5, "hello"
    data = b"\x05hello"
    reader = BinaryReader(data, DummyDelegate())
    assert reader.read_string() == "hello"


def test_read_string_utf8_multibyte():
    # Length 8 bytes: "π世界"
    data = b"\x08\xcf\x80\xe4\xb8\x96\xe7\x95\x8c"
    reader = BinaryReader(data, DummyDelegate())
    assert reader.read_string() == "π世界"


def test_read_string_invalid_utf8_fuzzer_safe():
    # Length 4, with invalid UTF-8 bytes (\xff)
    data = b"\x04h\xffll"
    reader = BinaryReader(data, DummyDelegate())
    # Should not crash, should replace bad characters
    result = reader.read_string()
    assert len(result) == 4
    assert result.startswith("h")


def test_leb128_negative_edges():
    # -1 encoded as LEB128 (0x7F)
    reader = BinaryReader(b"\x7f", DummyDelegate())
    assert reader.read_leb128(signed=True, max_bits=7) == -1

    # -128 encoded as LEB128 (0x80 0x7F)
    reader = BinaryReader(b"\x80\x7f", DummyDelegate())
    assert reader.read_leb128(signed=True, max_bits=14) == -128


def test_read_module_without_on_error_does_not_raise():
    # Bad magic should be swallowed when delegate does not define on_error.
    data = b"\x01asm\x01\x00\x00\x00"
    reader = BinaryReader(data, NoErrorDelegate())
    reader.read_module()


def test_read_limits_shared_with_max_flag03():
    # flag=0x03 => has max + shared, i32 index type
    reader = BinaryReader(b"\x03\x01\x02", DummyDelegate())
    mn, mx, is64, shared, ps_log2 = reader.read_limits()
    assert (mn, mx, is64, shared, ps_log2) == (1, 2, False, True, None)


def test_read_limits_shared_memory64_with_max_flag07():
    # flag=0x07 => has max + shared + i64 index type
    reader = BinaryReader(b"\x07\x01\x03", DummyDelegate())
    mn, mx, is64, shared, ps_log2 = reader.read_limits()
    assert (mn, mx, is64, shared, ps_log2) == (1, 3, True, True, None)


def test_read_limits_custom_page_size_flag08():
    # flag=0x08 => no max, i32, custom page size exponent 0 (1-byte pages)
    reader = BinaryReader(b"\x08\x01\x00", DummyDelegate())
    mn, mx, is64, shared, ps_log2 = reader.read_limits()
    assert (mn, mx, is64, shared, ps_log2) == (1, None, False, False, 0)


def test_read_limits_max_plus_custom_page_size_flag09():
    # flag=0x09 => has max + custom page size; page_size_log2 follows the max
    reader = BinaryReader(b"\x09\x01\x02\x10", DummyDelegate())
    mn, mx, is64, shared, ps_log2 = reader.read_limits()
    assert (mn, mx, is64, shared, ps_log2) == (1, 2, False, False, 16)


def test_read_limits_shared64_custom_page_size_flag0f():
    # flag=0x0f => has max + shared + i64 + custom page size
    reader = BinaryReader(b"\x0f\x01\x03\x10", DummyDelegate())
    mn, mx, is64, shared, ps_log2 = reader.read_limits()
    assert (mn, mx, is64, shared, ps_log2) == (1, 3, True, True, 16)


# ─── GC rec groups and composite type kinds ─────────────────────────────────


class _TypeCaptureDelegate(DummyDelegate):
    """Capture on_type / on_type_kind emissions in order."""

    def __init__(self):
        super().__init__()
        self.types = []
        self.kinds = {}

    def on_type(self, index, params, results):
        self.types.append((index, params, results))

    def on_type_kind(self, index, kind):
        self.kinds[index] = kind


def _leb(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def _section(sid, payload):
    return bytes([sid]) + _leb(len(payload)) + payload


def test_rec_group_members_get_their_own_type_indices():
    # One outer entry: rec { struct{i32}, struct{i64} } => indices 0 and 1.
    payload = _leb(1) + b"\x4E\x02" + b"\x5F\x01\x7F\x00" + b"\x5F\x01\x7E\x00"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    delegate = reader.delegate
    assert [t[0] for t in delegate.types] == [0, 1]
    assert delegate.kinds == {0: "struct", 1: "struct"}


def test_types_after_rec_group_keep_correct_indices():
    # struct, rec { struct, struct }, func => four type indices, func at 3.
    t0 = b"\x5F\x01\x7F\x00"
    rec = b"\x4E\x02" + b"\x5F\x01\x7F\x00" + b"\x5F\x01\x7E\x00"
    t3 = b"\x60\x01\x7F\x01\x7F"
    payload = _leb(3) + t0 + rec + t3
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    delegate = reader.delegate
    assert [t[0] for t in delegate.types] == [0, 1, 2, 3]
    assert delegate.types[3] == (3, ["i32"], ["i32"])
    assert delegate.kinds == {0: "struct", 1: "struct", 2: "struct", 3: "func"}


def test_sub_wrapped_func_type_decodes():
    # sub (open) with one supertype wrapping (func (i32) -> (i32)).
    payload = _leb(1) + b"\x50\x01\x00" + b"\x60\x01\x7F\x01\x7F"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    delegate = reader.delegate
    assert delegate.types == [(0, ["i32"], ["i32"])]
    assert delegate.kinds == {0: "func"}


def test_array_type_reports_array_kind():
    payload = _leb(1) + b"\x5E\x7F\x01"  # array of mutable i32
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    assert reader.delegate.kinds == {0: "array"}


def test_unknown_comptype_tag_reports_error_and_skips_rest_of_section():
    # 0x5D is the stack-switching `cont` form: unknown here, and its payload
    # length is unknowable, so the rest of the type section must be abandoned
    # with an error instead of decoded from a desynchronized offset.
    payload = _leb(2) + b"\x60\x00\x00" + b"\x5D\x00\x00" + b"\x60\x01\x7F\x00"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    delegate = reader.delegate
    assert delegate.types == [(0, [], [])]  # entries before the unknown tag
    assert len(delegate.errors) == 1
    assert "type section" in delegate.errors[0]


def test_unknown_comptype_tag_still_parses_later_sections():
    bad_types = _section(1, _leb(1) + b"\x5D\x00")
    memory = _section(5, _leb(1) + b"\x00\x01")

    class _MemoryDelegate(_TypeCaptureDelegate):
        def __init__(self):
            super().__init__()
            self.memories = []

        def on_memory(self, index, mn, mx, is64, shared=False, page_size_log2=None):
            self.memories.append((index, mn))

    reader = BinaryReader(
        b"\x00asm\x01\x00\x00\x00" + bad_types + memory, _MemoryDelegate()
    )
    reader.read_module()
    assert reader.delegate.memories == [(0, 1)]
    assert reader.delegate.errors


def test_truncated_type_section_reports_error():
    payload = _leb(2) + b"\x60\x01\x7F"  # second entry claims results that never come
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    assert reader.delegate.errors


def test_type_count_beyond_section_payload_reports_error():
    # count claims two entries but only one is present, and the section ends
    # exactly on the entry boundary: the peek must fail as a parse error, not
    # as an IndexError that the per-section handler swallows silently.
    payload = _leb(2) + b"\x60\x00\x00"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    delegate = reader.delegate
    assert [t[0] for t in delegate.types] == [0]
    assert delegate.errors and "type section" in delegate.errors[0]


def test_truncated_rec_group_reports_error():
    # rec announces two members but the payload ends after the first.
    payload = _leb(1) + b"\x4E\x02" + b"\x5F\x01\x7F\x00"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    assert reader.delegate.errors
    assert "rec group" in reader.delegate.errors[0]


def test_nested_rec_groups_are_rejected_without_recursing():
    # Rec groups do not nest per the GC spec. A crafted chain of rec tags must
    # report a parse error instead of recursing once per tag (which raised
    # RecursionError before, silently discarding the whole section).
    payload = _leb(1) + b"\x4E\x01" * 20000 + b"\x60\x00\x00"
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00" + _section(1, payload),
                          _TypeCaptureDelegate())
    reader.read_module()
    assert reader.delegate.types == []
    assert reader.delegate.errors
    assert "0x4e" in reader.delegate.errors[0]


def test_peek_u8_raises_at_end_of_data():
    reader = BinaryReader(b"\x00asm\x01\x00\x00\x00", _TypeCaptureDelegate())
    reader.offset = reader.size
    with pytest.raises(WasmParseError):
        reader.peek_u8()
