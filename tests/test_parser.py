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
    mn, mx, is64 = reader.read_limits()
    assert (mn, mx, is64) == (1, 2, False)


def test_read_limits_shared_memory64_with_max_flag07():
    # flag=0x07 => has max + shared + i64 index type
    reader = BinaryReader(b"\x07\x01\x03", DummyDelegate())
    mn, mx, is64 = reader.read_limits()
    assert (mn, mx, is64) == (1, 3, True)
