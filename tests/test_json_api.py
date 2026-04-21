import json
import os

from wasm_tools.api import (
    parse_wasm_bytes,
    parse_wasm_bytes_json,
    parse_wasm_file,
    parse_wasm_file_json,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture_path(name: str) -> str:
    return os.path.join(FIXTURES_DIR, name)


def _fixture_bytes(name: str) -> bytes:
    with open(_fixture_path(name), "rb") as fixture_file:
        return fixture_file.read()


def test_parse_wasm_file_returns_structured_report():
    report = parse_wasm_file(_fixture_path("simple_add.wasm"))

    assert report["errors"] == []
    assert report["module_version"] == 1
    assert report["function_count"] >= 1
    assert report["section_count"] >= 1
    assert any(fn["index"] == 0 for fn in report["functions"])

    instructions = report["functions"][0]["instructions"]
    assert any(ins["opcode"] == "local.get" for ins in instructions)
    assert any(ins["opcode"] == "i32.add" for ins in instructions)


def test_parse_wasm_file_captures_bulk_memory_immediates():
    report = parse_wasm_file(_fixture_path("bulk_memory.wasm"))

    assert report["errors"] == []
    instructions = report["functions"][0]["instructions"]

    assert any(
        ins["opcode"] == "memory.init" and ins["immediates"] == [0, 0]
        for ins in instructions
    )
    assert any(
        ins["opcode"] == "data.drop" and ins["immediates"] == [0]
        for ins in instructions
    )
    assert any(
        ins["opcode"] == "memory.fill" and ins["immediates"] == [0]
        for ins in instructions
    )


def test_parse_wasm_file_uses_module_global_function_indices_with_imports():
    report = parse_wasm_file(_fixture_path("globals_imports.wasm"))

    assert report["errors"] == []
    assert report["function_count"] == 1
    assert report["functions"][0]["index"] == 1


def test_parse_wasm_file_includes_security_analysis_summary():
    report = parse_wasm_file(_fixture_path("simple_add.wasm"))

    assert "analysis" in report
    assert report["analysis"]["summary"]["risk_score"] >= 0
    assert report["analysis"]["summary"]["risk_tier"] in {"none", "low", "medium", "high"}
    assert isinstance(report["analysis"]["findings"], list)


def test_parse_wasm_file_detects_wasi_capability_combo_risk():
    report = parse_wasm_file(_fixture_path("wasi_capabilities.wasm"))

    caps = set(report["analysis"]["capabilities"])
    assert "fs.path" in caps
    assert "network" in caps
    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-CAP-001" in finding_ids


def test_parse_wasm_file_profiles_indirect_control_flow():
    report = parse_wasm_file(_fixture_path("call_indirect.wasm"))

    cf = report["analysis"]["profiles"]["control_flow"]
    assert cf["indirect_call_ops"] >= 1


def test_parse_wasm_file_detects_loop_growth_dos_signal():
    report = parse_wasm_file(_fixture_path("dos_growth_loop.wasm"))

    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-DOS-003" in finding_ids
    compute = report["analysis"]["profiles"]["compute"]
    assert compute["loop_memory_ops"] >= 1


def test_parse_wasm_bytes_json_includes_unicode_content():
    raw = _fixture_bytes("unicode_names.wasm")
    json_text = parse_wasm_bytes_json(raw, filename="unicode_names.wasm")

    parsed = json.loads(json_text)
    assert parsed["file"] == "unicode_names.wasm"
    assert parsed["errors"] == []
    assert parsed["function_count"] >= 1


def test_parse_wasm_bytes_reports_parse_errors():
    # Bad magic should be surfaced through the structured errors field.
    report = parse_wasm_bytes(b"\x01asm\x01\x00\x00\x00", filename="bad.wasm")

    assert report["module_version"] is None
    assert report["errors"]
    assert "Bad magic value" in report["errors"][0]


def test_parse_wasm_file_json_handles_read_errors(tmp_path):
    missing = tmp_path / "does_not_exist.wasm"
    json_text = parse_wasm_file_json(str(missing))

    parsed = json.loads(json_text)
    assert parsed["file"] == str(missing)
    assert parsed["errors"]
    assert parsed["function_count"] == 0

