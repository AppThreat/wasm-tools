# tests/test_details.py
"""Dedicated tests for the -x (--details) output mode."""

import json
import os

import pytest

from wasm_tools import cli
from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import BinaryReaderObjdumpDetails, BinaryReaderObjdumpPrepass

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as f:
        return f.read()


def _run_details(data: bytes) -> str:
    """Run the two-pass pipeline in DETAILS mode and return stdout."""
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    options.mode = ObjdumpMode.DETAILS
    details = BinaryReaderObjdumpDetails(data, options, state)
    BinaryReader(data, details).read_module()


# ─── banner ───────────────────────────────────────────────────────────────────


def test_details_banner_empty_module(capsys):
    """Details mode prints the 'Section Details:' header."""
    data = b"\x00asm\x01\x00\x00\x00"
    _run_details(data)
    assert "Section Details:" in capsys.readouterr().out


# ─── type section ─────────────────────────────────────────────────────────────


def test_details_type_section_simple_add(capsys):
    data = _fixture("simple_add.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Type[" in out
    # simple_add has a (i32, i32) -> i32 signature
    assert "i32, i32" in out
    assert "-> (i32)" in out


# ─── export section ───────────────────────────────────────────────────────────


def test_details_export_section(capsys):
    data = _fixture("simple_add.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Export[" in out
    assert "func[" in out
    assert "->" in out


# ─── memory section ───────────────────────────────────────────────────────────


def test_details_memory_section(capsys):
    data = _fixture("bulk_memory.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Memory[" in out
    assert "initial=1" in out


# ─── data section ─────────────────────────────────────────────────────────────


def test_details_data_section(capsys):
    # bulk_memory.wasm has a passive data segment (no memory binding)
    data = _fixture("bulk_memory.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Data[" in out
    assert "segment[0]" in out
    assert "size=16" in out


# ─── import section ───────────────────────────────────────────────────────────


def test_details_import_section(capsys):
    data = _fixture("globals_imports.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Import[" in out
    assert "sig=" in out
    assert "func[0] sig=0" in out
    assert "Function[1]" in out
    assert "func[1]: sig=1" in out


# ─── function + code sections ─────────────────────────────────────────────────


def test_details_function_and_code_sections(capsys):
    data = _fixture("simple_add.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Function[1]" in out
    assert "func[0]" in out
    assert "Code[1]" in out


# ─── global section ───────────────────────────────────────────────────────────


def test_details_global_section(capsys):
    data = _fixture("globals_imports.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Global[" in out
    assert "i32" in out or "f64" in out


# ─── element + table sections ─────────────────────────────────────────────────


def test_details_element_and_table_sections(capsys):
    data = _fixture("call_indirect.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "Table[" in out
    assert "Element[" in out


# ─── CLI integration ─────────────────────────────────────────────────────────


def test_cli_details_flag(monkeypatch, capsys, tmp_path):
    """'-x' flag routes through BinaryReaderObjdumpDetails."""
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    dst = tmp_path / "simple_add.wasm"
    shutil.copy(src, dst)
    monkeypatch.setattr("sys.argv", ["wasm-tools", str(dst), "-x"])
    cli.main()
    out = capsys.readouterr().out
    assert "Section Details:" in out
    assert "Type[" in out
    assert "Export[" in out


def test_cli_details_default_mode(monkeypatch, capsys, tmp_path):
    """Running without a flag defaults to details mode."""
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    dst = tmp_path / "simple_add.wasm"
    shutil.copy(src, dst)
    monkeypatch.setattr("sys.argv", ["wasm-tools", str(dst)])
    cli.main()
    out = capsys.readouterr().out
    assert "Section Details:" in out


def test_cli_headers_single_sections_banner(monkeypatch, capsys, tmp_path):
    """--headers should print a single section banner/table header."""
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    dst = tmp_path / "simple_add.wasm"
    shutil.copy(src, dst)
    monkeypatch.setattr("sys.argv", ["wasm-tools", str(dst), "--headers"])
    cli.main()
    out = capsys.readouterr().out
    assert out.count("Sections:") == 1


def test_cli_json_out_writes_minified_report(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    wasm_path = tmp_path / "simple_add.wasm"
    out_path = tmp_path / "simple_add.json"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr(
        "sys.argv", ["wasm-tools", str(wasm_path), "--json-out", str(out_path)]
    )
    cli.main()

    stdout = capsys.readouterr().out
    assert stdout == ""
    text = out_path.read_text(encoding="utf-8")
    assert "\n" not in text
    assert ": " not in text
    assert ", " not in text
    parsed = json.loads(text)
    assert parsed["file"] == str(wasm_path)
    assert parsed["errors"] == []


def test_cli_json_prints_minified_report_to_stdout(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    wasm_path = tmp_path / "simple_add.wasm"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr("sys.argv", ["wasm-tools", str(wasm_path), "--json"])
    cli.main()

    stdout = capsys.readouterr().out.strip()
    assert "\n" not in stdout
    assert ": " not in stdout
    assert ", " not in stdout
    parsed = json.loads(stdout)
    assert parsed["file"] == str(wasm_path)
    assert parsed["errors"] == []


def test_cli_json_and_json_out_emit_both(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    wasm_path = tmp_path / "simple_add.wasm"
    out_path = tmp_path / "simple_add.json"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr(
        "sys.argv",
        ["wasm-tools", str(wasm_path), "--json", "--json-out", str(out_path)],
    )
    cli.main()

    stdout = capsys.readouterr().out.strip()
    parsed_stdout = json.loads(stdout)
    parsed_file = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed_stdout == parsed_file


def test_cli_json_analysis_only_prints_analysis_object(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "wasi_capabilities.wasm")
    wasm_path = tmp_path / "wasi_capabilities.wasm"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr(
        "sys.argv",
        ["wasm-tools", str(wasm_path), "--json", "--analysis-only"],
    )
    cli.main()

    stdout = capsys.readouterr().out.strip()
    parsed = json.loads(stdout)
    assert "summary" in parsed
    assert "findings" in parsed
    assert "capabilities" in parsed
    assert "file" not in parsed
    assert any(f["id"] == "WASM-CAP-001" for f in parsed["findings"])


def test_cli_json_analysis_only_can_write_file(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "dos_growth_loop.wasm")
    wasm_path = tmp_path / "dos_growth_loop.wasm"
    out_path = tmp_path / "analysis.json"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "wasm-tools",
            str(wasm_path),
            "--json-out",
            str(out_path),
            "--analysis-only",
        ],
    )
    cli.main()

    stdout = capsys.readouterr().out
    assert stdout == ""
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert "summary" in parsed
    assert "profiles" in parsed
    assert "functions" not in parsed
    assert any(f["id"] == "WASM-DOS-003" for f in parsed["findings"])


def test_cli_json_analysis_only_and_json_out_emit_same_payload(
    monkeypatch, capsys, tmp_path
):
    import shutil

    src = os.path.join(FIXTURES_DIR, "wasi_capabilities.wasm")
    wasm_path = tmp_path / "wasi_capabilities.wasm"
    out_path = tmp_path / "analysis.json"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "wasm-tools",
            str(wasm_path),
            "--json",
            "--json-out",
            str(out_path),
            "--analysis-only",
        ],
    )
    cli.main()

    stdout = capsys.readouterr().out.strip()
    parsed_stdout = json.loads(stdout)
    parsed_file = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed_stdout == parsed_file


def test_cli_analysis_only_without_json_mode_exits(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    wasm_path = tmp_path / "simple_add.wasm"
    shutil.copy(src, wasm_path)

    monkeypatch.setattr("sys.argv", ["wasm-tools", str(wasm_path), "--analysis-only"])
    with pytest.raises(SystemExit):
        cli.main()

    stderr = capsys.readouterr().err
    assert "--analysis-only requires --json and/or --json-out" in stderr


def test_cli_json_out_write_error_exits(monkeypatch, capsys, tmp_path):
    import shutil

    src = os.path.join(FIXTURES_DIR, "simple_add.wasm")
    wasm_path = tmp_path / "simple_add.wasm"
    shutil.copy(src, wasm_path)

    # Writing to a directory path should fail with a clear CLI error.
    monkeypatch.setattr(
        "sys.argv", ["wasm-tools", str(wasm_path), "--json-out", str(tmp_path)]
    )
    with pytest.raises(SystemExit):
        cli.main()

    stderr = capsys.readouterr().err
    assert "Error writing" in stderr


def test_details_datacount_section_includes_count(capsys):
    data = _fixture("bulk_memory.wasm")
    _run_details(data)
    out = capsys.readouterr().out
    assert "DataCount:" in out
    assert "data count: 1" in out


# ─── ObjdumpState richness ────────────────────────────────────────────────────


def test_prepass_populates_types():
    data = _fixture("simple_add.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    assert len(state.types) >= 1
    ft = state.types[0]
    assert ft.params == ["i32", "i32"]
    assert ft.results == ["i32"]


def test_prepass_populates_exports():
    data = _fixture("simple_add.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    assert len(state.exports) >= 1
    exp = state.exports[0]
    assert exp.kind == "func"
    assert exp.name == "add"


def test_prepass_populates_memories():
    data = _fixture("bulk_memory.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    assert len(state.memories) >= 1
    assert state.memories[0].limits.minimum == 1


def test_prepass_populates_data_segments():
    data = _fixture("bulk_memory.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    assert len(state.data_segments) >= 1
    seg = state.data_segments[0]
    assert seg.size == 16


def test_prepass_populates_globals():
    data = _fixture("globals_imports.wasm")
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()
    assert len(state.globals) >= 1


def test_api_report_includes_rich_sections():
    from wasm_tools.api import parse_wasm_file

    report = parse_wasm_file(os.path.join(FIXTURES_DIR, "simple_add.wasm"))
    assert report["types"]
    assert report["types"][0]["params"] == ["i32", "i32"]
    assert report["types"][0]["results"] == ["i32"]
    assert report["exports"]
    assert report["exports"][0]["name"] == "add"


def test_api_report_bulk_memory_data_segments():
    from wasm_tools.api import parse_wasm_file

    report = parse_wasm_file(os.path.join(FIXTURES_DIR, "bulk_memory.wasm"))
    assert report["data_segments"]
    seg = report["data_segments"][0]
    assert seg["size"] == 16


def test_api_report_memories():
    from wasm_tools.api import parse_wasm_file

    report = parse_wasm_file(os.path.join(FIXTURES_DIR, "bulk_memory.wasm"))
    assert report["memories"]
    assert report["memories"][0]["limits"]["min"] == 1
