# tests/test_e2e.py
import os

import pytest

from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import (
    BinaryReaderObjdumpDisassemble,
    BinaryReaderObjdumpPrepass,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def get_wasm(filename: str) -> bytes:
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "rb") as f:
        return f.read()


def run_objdump(data: bytes, mode: int) -> str:
    """Helper to run the objdump pipeline and return stdout."""
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    # Pass 1
    prepass = BinaryReaderObjdumpPrepass(data, options, state)
    BinaryReader(data, prepass).read_module()

    # Pass 2
    options.mode = mode
    if mode == ObjdumpMode.DISASSEMBLE:
        dis_reader = BinaryReaderObjdumpDisassemble(data, options, state)
        BinaryReader(data, dis_reader).read_module()
    # (Other modes can be added here as we implement their specific visitors)

    return ""


def test_e2e_empty_module(capsys):
    data = get_wasm("empty.wasm")

    # Running Prepass should print the header format
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS, filename="empty.wasm")
    state = ObjdumpState()
    prepass = BinaryReaderObjdumpPrepass(data, options, state)
    BinaryReader(data, prepass).read_module()

    captured = capsys.readouterr()
    assert "empty.wasm:\tfile format wasm 0x1" in captured.out


def test_e2e_simple_add_disassembly(capsys):
    data = get_wasm("simple_add.wasm")

    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    # Setup state
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

    # Disassemble
    options.mode = ObjdumpMode.DISASSEMBLE
    dis_reader = BinaryReaderObjdumpDisassemble(data, options, state)
    BinaryReader(data, dis_reader).read_module()

    captured = capsys.readouterr()
    stdout = captured.out

    # Verify the disassembly output structure
    assert "Code Disassembly:" in stdout
    # Depending on how wat2wasm numbers functions, it should be func[0]
    assert "func[0]" in stdout
    assert "local.get" in stdout
    assert "i32.add" in stdout
    assert "end" in stdout


def test_e2e_control_flow(capsys):
    data = get_wasm("control_flow.wasm")

    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

    options.mode = ObjdumpMode.DISASSEMBLE
    dis_reader = BinaryReaderObjdumpDisassemble(data, options, state)
    BinaryReader(data, dis_reader).read_module()

    captured = capsys.readouterr()
    stdout = captured.out

    assert "block" in stdout
    assert "loop" in stdout
    assert "br_if" in stdout
    assert "br" in stdout


def test_e2e_memory_data(capsys):
    data = get_wasm("memory_data.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    # Assert Memory Operations
    assert "local.get 0" in stdout
    # i32.load8_u has an alignment and offset immediate.
    # Align 1 (which is 2^0 bytes) and Offset 2
    # Standard Wasm encodes align as power of 2 (0=8bit, 1=16bit, 2=32bit)
    # The output should show the raw LEB values read
    assert "i32.load8_u" in stdout


def test_e2e_globals_imports(capsys):
    data = get_wasm("globals_imports.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    # One imported function shifts the defined body to func[1].
    assert "func[1]:" in stdout
    assert "global.get 1" in stdout  # Import is global 0, internal global is 1
    assert "f64.const 1.5" in stdout
    assert "f64.add" in stdout
    assert "global.set 1" in stdout
    assert "call 0" in stdout  # Import func is func 0


def test_e2e_call_indirect(capsys):
    data = get_wasm("call_indirect.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    # Assert multiple function bodies exist
    assert "func[0]:" in stdout
    assert "func[1]:" in stdout
    assert "func[2]:" in stdout

    # Assert call indirect arguments (type index, table index)
    # Type index 0, Table index 0
    assert "call_indirect 0 0" in stdout


def test_e2e_complex_flow_fixture(capsys):
    data = get_wasm("complex_flow.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    # Exercise mixed instruction families in one function body.
    assert "Code Disassembly:" in stdout
    assert "call " in stdout
    assert "loop" in stdout
    assert "br_if" in stdout
    assert "i32.store" in stdout
    assert "i32.load" in stdout
    assert "call_indirect 0 0" in stdout


def test_e2e_unicode_fixture(capsys):
    data = get_wasm("unicode_names.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    assert "Code Disassembly:" in stdout
    assert "func[0]" in stdout
    assert "local.get 0" in stdout
    assert "local.get 1" in stdout
    assert "i32.add" in stdout


def test_e2e_adversarial_ops_fixture(capsys):
    data = get_wasm("adversarial_ops.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    # br_table and edge immediates are common parser stress points.
    assert "br_table" in stdout
    assert "i32.const -2147483648" in stdout
    assert "local.set 1" in stdout


def test_e2e_bulk_memory_fixture(capsys):
    data = get_wasm("bulk_memory.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()

    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DISASSEMBLE
    BinaryReader(
        data, BinaryReaderObjdumpDisassemble(data, options, state)
    ).read_module()

    stdout = capsys.readouterr().out

    assert "memory.init 0 0" in stdout
    assert "data.drop 0" in stdout
    assert "memory.fill 0" in stdout


