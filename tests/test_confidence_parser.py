import io
from contextlib import redirect_stdout

from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import (
    BinaryReaderObjdumpDisassemble,
    BinaryReaderObjdumpPrepass,
)


class ErrorDelegate:
    def __init__(self):
        self.errors = []

    def begin_module(self, version):
        pass

    def begin_section(self, section_index, section_code, size):
        pass

    def on_error(self, message):
        self.errors.append(message)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id, len(payload)]) + payload


def _module_with_single_body(body: bytes) -> bytes:
    header = b"\x00asm\x01\x00\x00\x00"
    function_section = _section(3, b"\x01\x00")  # one function with signature index 0
    code_payload = b"\x01" + bytes([len(body)]) + body
    code_section = _section(10, code_payload)
    return header + function_section + code_section


def _disassemble_bytes(data: bytes) -> str:
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    out = io.StringIO()
    with redirect_stdout(out):
        BinaryReader(
            data, BinaryReaderObjdumpPrepass(data, options, state)
        ).read_module()
        options.mode = ObjdumpMode.DISASSEMBLE
        BinaryReader(
            data, BinaryReaderObjdumpDisassemble(data, options, state)
        ).read_module()

    return out.getvalue()


def test_parser_truncated_instruction_immediate_reports_error():
    # Body: local decl count=0, i32.const opcode, but missing its LEB immediate.
    data = _module_with_single_body(b"\x00\x41")
    delegate = ErrorDelegate()

    BinaryReader(data, delegate).read_module()

    assert delegate.errors
    assert "Unexpected end of file" in delegate.errors[0]


def test_disassembly_memory_copy_immediates_are_logged():
    # Body: memory.copy 0 0; end
    data = _module_with_single_body(b"\x00\xfc\x0a\x00\x00\x0b")

    stdout = _disassemble_bytes(data)

    assert "memory.copy 0 0" in stdout


def test_disassembly_memory_init_immediates_are_logged():
    # Body: memory.init 0 0; end
    data = _module_with_single_body(b"\x00\xfc\x08\x00\x00\x0b")

    stdout = _disassemble_bytes(data)

    assert "memory.init 0 0" in stdout


def test_disassembly_data_drop_and_memory_fill_are_logged():
    # Body: data.drop 0; memory.fill 0; end
    data = _module_with_single_body(b"\x00\xfc\x09\x00\xfc\x0b\x00\x0b")

    stdout = _disassemble_bytes(data)

    assert "data.drop 0" in stdout
    assert "memory.fill 0" in stdout


def test_disassembly_unknown_opcode_has_fallback_name():
    # 0xC5 is not in our opcode table and should be printed as unknown.
    # (0xC0-0xC4 are now sign-extension ops; pick 0xC5 which is undefined)
    data = _module_with_single_body(b"\x00\xc5\x0b")

    stdout = _disassemble_bytes(data)

    assert "unknown_00_c5" in stdout
