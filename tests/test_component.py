"""Tests for WebAssembly Component Model binary parsing."""

import sys
from pathlib import Path

import pytest

from wasm_tools.api import parse_wasm_bytes, parse_wasm_file
from wasm_tools.cli import main as cli_main
from wasm_tools.component import detect_component, parse_component_bytes

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


def _name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _leb(len(raw)) + raw


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _leb(len(payload)) + payload


def _externname(s: str) -> bytes:
    # nameattributes kind 0x00 + externname (len-prefixed)
    return b"\x00" + _name(s)


def _import_entry(iface: str, kind_byte: int = 0x01, idx: int = 0) -> bytes:
    # nameattributes + externtype (func: 0x01 typeidx)
    return _externname(iface) + bytes([kind_byte]) + _leb(idx)


def _export_entry(name: str, sort: int = 0x01, idx: int = 0) -> bytes:
    # nameattributes + sortidx + absent externtype (0x00)
    return _externname(name) + bytes([sort]) + _leb(idx) + b"\x00"


def _component(sections: list[bytes], version: int = 0x0D) -> bytes:
    header = b"\x00asm" + bytes([version & 0xFF, (version >> 8) & 0xFF, 0x01, 0x00])
    return header + b"".join(sections)


def _core_fixture_bytes(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


# ─── detection ───────────────────────────────────────────────────────────────


def test_detect_component_preambles():
    assert detect_component(b"\x00asm\x0d\x00\x01\x00") == (0x0D, 1)
    assert detect_component(b"\x00asm\x0e\x00\x01\x00") == (0x0E, 1)  # bumped version
    assert detect_component(b"\x00asm\x01\x00\x00\x00") is None  # core module
    assert detect_component(b"\x00asm\x0d\x00\x00\x00") is None  # layer 0
    assert detect_component(b"garbage!!") is None


# ─── full report ─────────────────────────────────────────────────────────────


def _sample_component() -> bytes:
    imports = _section(10, _leb(1) + _import_entry("wasi:cli/run@0.2.0"))
    core_module = _section(1, _core_fixture_bytes("simple_add.wasm"))
    canon = _section(
        8,
        _leb(1) + b"\x00\x00" + _leb(0) + _leb(1) + b"\x06" + _leb(0),
    )
    exports = _section(11, _leb(1) + _export_entry("go"))
    return _component([imports, core_module, canon, exports])


def test_component_report_structure():
    report = parse_wasm_bytes(_sample_component(), "sample.wasm")

    assert report["is_component"] is True
    assert report["module_version"] == 0x01000D

    component = report["component"]
    assert component["component_version"] == 13
    assert component["layer_version"] == 1
    assert component["import_count"] == 1
    assert component["export_count"] == 1
    assert component["core_module_count"] == 1
    assert component["interfaces"] == ["wasi:cli/run@0.2.0"]
    assert component["interface_packages"] == ["wasi:cli/run"]
    assert component["imports"][0]["kind"] == "func"
    assert component["exports"][0] == {"name": "go", "kind": "func", "index": 0}
    assert component["canonical_options"]["async"] is True
    assert component["canonical_options"]["lift_count"] == 1
    assert report["errors"] == []


def test_component_nested_core_module_aggregates():
    report = parse_wasm_bytes(_sample_component(), "sample.wasm")

    # simple_add.wasm has one function; aggregation lifts it to the top level.
    assert report["function_count"] == 1
    fn = report["functions"][0]
    assert fn["core_module"] == 0
    assert fn["instruction_count"] > 0
    assert any(
        ins["opcode"] == "i32.add" for ins in fn["instructions"]
    )
    # Export list from the core module is preserved with a core_module tag.
    assert report["exports"], "expected aggregated core module exports"
    assert report["exports"][0]["core_module"] == 0


def test_component_format_and_wasi_detections():
    report = parse_wasm_bytes(_sample_component(), "sample.wasm")

    fmt = report["analysis"]["detections"]["format"]
    assert fmt["kind"] == "component"
    assert fmt["confidence"] == "high"
    assert "component_layer" in fmt["signals"]
    assert fmt["component_version"] == 13

    wasi = report["analysis"]["detections"]["wasi"]
    assert wasi["detected"] is True
    assert wasi["import_modules"] == ["wasi:cli/run@0.2.0"]
    assert wasi["variants"] == ["preview2"]
    # WASM-FMT-005 must NOT fire for a successfully parsed component.
    assert "WASM-FMT-005" not in [
        f["id"] for f in report["analysis"]["findings"]
    ]


def test_component_preview3_interface_variant():
    imports = _section(
        10,
        _leb(2)
        + _import_entry("wasi:cli/run@0.2.0")
        + _import_entry("wasi:http/types@0.3.0"),
    )
    report = parse_wasm_bytes(_component([imports]), "p3.wasm")
    wasi = report["analysis"]["detections"]["wasi"]
    assert wasi["variants"] == ["preview2", "preview3"]


def test_component_export_only_interface_counted():
    exports = _section(11, _leb(1) + _export_entry("wasi:cli/run@0.2.0"))
    report = parse_wasm_bytes(_component([exports]), "exp.wasm")
    wasi = report["analysis"]["detections"]["wasi"]
    assert "wasi:cli/run@0.2.0" in wasi["import_modules"]


def test_component_value_and_type_imports():
    imports = _section(
        10,
        _leb(3)
        + _import_entry("wasi:cli/exit@0.2.0", kind_byte=0x01)
        # value bound to a primitive valtype (0x02 0x01 0x79 = u32)
        + _externname("local:value") + b"\x02\x01\x79"
        # type bound by index (0x03 0x00 idx)
        + _externname("local:type") + b"\x03\x00" + _leb(0),
    )
    report = parse_wasm_bytes(_component([imports]), "kinds.wasm")
    kinds = sorted(i["kind"] for i in report["component"]["imports"])
    assert kinds == ["func", "type", "value"]
    assert report["errors"] == []


# ─── resilience ──────────────────────────────────────────────────────────────


def test_component_malformed_import_section_keeps_walking():
    # Garbage import payload after the count: section abandoned, walk resumes.
    bad_imports = _section(10, _leb(1) + b"\xff\xff\xff\xff\xff")
    exports = _section(11, _leb(1) + _export_entry("go"))
    report = parse_wasm_bytes(_component([bad_imports, exports]), "bad.wasm")
    assert report["component"]["import_count"] == 0
    assert report["component"]["export_count"] == 1
    assert any("Import" in err for err in report["errors"])


def test_component_truncated_section_reports_error():
    # Section size extends beyond the file.
    data = b"\x00asm\x0d\x00\x01\x00" + b"\x0a" + b"\xff\xff\xff\xff\x0f"
    report = parse_wasm_bytes(data, "trunc.wasm")
    assert report["errors"]
    assert report["is_component"] is True


def test_component_nested_component_recurses():
    inner = _component([_section(11, _leb(1) + _export_entry("inner-export"))])
    outer = _component(
        [
            _section(4, inner),  # nested component section
            _section(11, _leb(1) + _export_entry("outer-export")),
        ]
    )
    report = parse_wasm_bytes(outer, "nested.wasm")
    nested = report["component"].get("nested_components", [])
    assert len(nested) == 1
    assert nested[0]["exports"][0]["name"] == "inner-export"
    assert report["component"]["exports"][0]["name"] == "outer-export"


def test_component_custom_section_producers_decoded():
    payload = _name("producers") + _leb(1) + _name("language") + _leb(1) + _name("Rust") + _name("1.80.1")
    custom = _section(0, payload)
    report = parse_wasm_bytes(_component([custom]), "prod.wasm")
    assert report["toolchain"]["languages"] == ["Rust"]


def test_component_strings_from_core_module_data_segments():
    imports = _section(10, _leb(1) + _import_entry("wasi:cli/run@0.2.0"))
    core_module = _section(1, _core_fixture_bytes("strings_secrets.wasm"))
    report = parse_wasm_bytes(_component([imports, core_module]), "str.wasm")
    values = [entry["value"] for entry in report["strings"]]
    assert "https://evil.example.com/payload" in values
    assert report["strings"][0]["core_module"] == 0
    detection = report["analysis"]["detections"]["strings"]
    assert detection["detected"] is True
    assert "WASM-STR-007" in [f["id"] for f in report["analysis"]["findings"]]


def test_parse_component_bytes_without_core_parse_skips_modules():
    data = _sample_component()
    result = parse_component_bytes(data, core_parse=None)
    assert result["detected"] is True
    assert result["core_module_count"] == 0


# ─── file + CLI ──────────────────────────────────────────────────────────────


def test_parse_wasm_file_component(tmp_path):
    path = tmp_path / "sample.component.wasm"
    path.write_bytes(_sample_component())
    report = parse_wasm_file(str(path))
    assert report["is_component"] is True
    assert report["component"]["core_module_count"] == 1


def test_cli_component_details(capsys, monkeypatch, tmp_path):
    path = tmp_path / "sample.component.wasm"
    path.write_bytes(_sample_component())
    monkeypatch.setattr(sys, "argv", ["wasm-tools", str(path), "-x"])
    cli_main()
    out = capsys.readouterr().out
    assert "Component Details:" in out
    assert "wasi:cli/run@0.2.0" in out
    assert "core module[0]" in out


def test_cli_component_headers(capsys, monkeypatch, tmp_path):
    path = tmp_path / "sample.component.wasm"
    path.write_bytes(_sample_component())
    monkeypatch.setattr(sys, "argv", ["wasm-tools", str(path), "--headers"])
    cli_main()
    out = capsys.readouterr().out
    assert "Component sections:" in out
    assert "Import" in out
    assert "CoreModule" in out


def test_cli_component_disassemble(capsys, monkeypatch, tmp_path):
    path = tmp_path / "sample.component.wasm"
    path.write_bytes(_sample_component())
    monkeypatch.setattr(sys, "argv", ["wasm-tools", str(path), "-d"])
    cli_main()
    out = capsys.readouterr().out
    assert "Code Disassembly (core module[0]):" in out
    assert "i32.add" in out


def test_cli_component_json_roundtrip(capsys, monkeypatch, tmp_path):
    path = tmp_path / "sample.component.wasm"
    path.write_bytes(_sample_component())
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", str(path), "--json", "--analysis-only"]
    )
    cli_main()
    import json

    analysis = json.loads(capsys.readouterr().out)
    assert analysis["detections"]["format"]["kind"] == "component"
    assert analysis["detections"]["wasi"]["variants"] == ["preview2"]


def test_detect_component_accepts_pre_0x0d_layer1_preambles():
    # Older toolchains emitted pre-0x0d component versions; layer 1 is the
    # discriminator, so those must be detected rather than core-parsed.
    assert detect_component(b"\x00asm\x0a\x00\x01\x00") == (0x0A, 1)
    assert detect_component(b"\x00asm\x0c\x00\x01\x00") == (0x0C, 1)
    report = parse_wasm_bytes(b"\x00asm\x0a\x00\x01\x00", "old.wasm")
    assert report["is_component"] is True
    assert report["component"]["component_version"] == 10
