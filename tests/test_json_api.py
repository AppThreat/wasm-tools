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


def test_parse_wasm_file_captures_call_ref_immediates():
    report = parse_wasm_file(_fixture_path("call_refs.wasm"))

    assert report["errors"] == []
    assert any(
        ins["opcode"] == "call_ref" and ins["immediates"] == [0]
        for fn in report["functions"]
        for ins in fn["instructions"]
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
    assert report["analysis"]["summary"]["risk_tier"] in {
        "none",
        "low",
        "medium",
        "high",
    }
    assert isinstance(report["analysis"]["findings"], list)


def test_parse_wasm_file_detects_wasi_capability_combo_risk():
    report = parse_wasm_file(_fixture_path("wasi_capabilities.wasm"))

    caps = set(report["analysis"]["capabilities"])
    assert "fs.path" in caps
    assert "network" in caps
    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-CAP-001" in finding_ids


def test_parse_wasm_file_detects_wasi_preview1_imports():
    report = parse_wasm_file(_fixture_path("wasi_capabilities.wasm"))

    wasi = report["analysis"]["detections"]["wasi"]
    assert wasi["detected"] is True
    assert "wasi_snapshot_preview1" in wasi["import_modules"]
    assert "preview1" in wasi["variants"]


def test_parse_wasm_file_detects_wasi_preview2_like_imports():
    report = parse_wasm_file(_fixture_path("wasi_preview2_like.wasm"))

    wasi = report["analysis"]["detections"]["wasi"]
    assert wasi["detected"] is True
    assert "preview2-like" in wasi["variants"]
    assert any(module.startswith("wasi:") for module in wasi["import_modules"])


def test_parse_wasm_file_detects_js_interface_signals():
    report = parse_wasm_file(_fixture_path("js_interface.wasm"))

    jsi = report["analysis"]["detections"]["js_interface"]
    assert jsi["detected"] is True
    assert jsi["confidence"] == "high"
    assert "js_namespace_import" in jsi["signals"]
    assert "wasm_builtin_namespace_import" in jsi["signals"]
    assert "wbindgen_pattern" in jsi["signals"]
    assert "wasm:js-string" in jsi["import_modules"]
    assert "js-string" in jsi["builtin_sets"]
    assert jsi["import_count"] >= 3
    assert jsi["imports"] == [
        {
            "kind": "func",
            "module": "js",
            "name": "console_log",
        },
        {
            "kind": "func",
            "module": "wbg",
            "name": "__wbindgen_throw",
        },
        {
            "kind": "func",
            "module": "wasm:js-string",
            "name": "length",
        },
    ]
    assert jsi["export_count"] >= 1
    assert jsi["exports"] == [
        {
            "kind": "func",
            "name": "__wbindgen_start",
        },
    ]


def test_parse_wasm_file_keeps_js_interface_schema_when_not_detected():
    report = parse_wasm_file(_fixture_path("simple_add.wasm"))

    jsi = report["analysis"]["detections"]["js_interface"]
    assert jsi["detected"] is False
    assert jsi["confidence"] == "none"
    assert jsi["signals"] == []
    assert jsi["imports"] == []
    assert jsi["exports"] == []


def test_parse_wasm_file_marks_core_format_for_regular_module():
    report = parse_wasm_file(_fixture_path("simple_add.wasm"))

    fmt = report["analysis"]["detections"]["format"]
    assert fmt["kind"] == "core"
    assert fmt["module_version"] == 1


def test_parse_wasm_bytes_detects_non_core_version_as_possible_component():
    report = parse_wasm_bytes(
        b"\x00asm\x0a\x00\x00\x00",
        filename="possible_component.wasm",
    )

    fmt = report["analysis"]["detections"]["format"]
    assert fmt["kind"] == "possible-component"
    assert "non_core_version" in fmt["signals"]

    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-FMT-005" in finding_ids


def test_parse_wasm_file_profiles_indirect_control_flow():
    report = parse_wasm_file(_fixture_path("call_indirect.wasm"))

    cf = report["analysis"]["profiles"]["control_flow"]
    assert cf["indirect_call_ops"] >= 1


def test_parse_wasm_file_profiles_load64_control_flow():
    report = parse_wasm_file(_fixture_path("load64.wasm"))

    cf = report["analysis"]["profiles"]["control_flow"]
    assert cf["indirect_call_ops"] >= 1


def test_parse_wasm_file_profiles_memory64_shared_growth():
    report = parse_wasm_file(_fixture_path("memory64_shared.wasm"))

    assert report["analysis"]["profiles"]["memory"]["memory_grow_ops"] >= 1


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
    assert report["analysis"]["detections"]["format"]["kind"] == "invalid-core"


def test_parse_wasm_file_json_handles_read_errors(tmp_path):
    missing = tmp_path / "does_not_exist.wasm"
    json_text = parse_wasm_file_json(str(missing))

    parsed = json.loads(json_text)
    assert parsed["file"] == str(missing)
    assert parsed["errors"]
    assert parsed["function_count"] == 0
    assert parsed["analysis"]["detections"]["js_interface"]["detected"] is False


def test_parse_wasm_file_captures_load64_memory_profile_and_immediates():
    report = parse_wasm_file(_fixture_path("load64.wasm"))

    assert report["errors"] == []
    assert report["memories"][0]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "i64.load" and ins["immediates"] == [3, 1099511627776]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "i32.store" and ins["immediates"] == [2, 1099511627776]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_memory64_shared_limits():
    report = parse_wasm_file(_fixture_path("memory64_shared.wasm"))

    assert report["errors"] == []
    assert report["memories"][0]["limits"] == {"min": 1, "max": 3, "is_64": True}


def test_parse_wasm_file_captures_table_init64_tables_and_immediates():
    report = parse_wasm_file(_fixture_path("table_init64.wasm"))

    assert report["errors"] == []
    assert report["tables"][2]["limits"] == {"min": 30, "max": 30, "is_64": True}
    assert any(
        ins["opcode"] == "table.init" and ins["immediates"] == [1, 2]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "table.copy" and ins["immediates"] == [2, 2]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "call_indirect" and ins["immediates"] == [0, 2]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_unreachable_instruction_density():
    report = parse_wasm_file(_fixture_path("unreachable.wasm"))

    assert report["errors"] == []
    unreachable_ops = sum(
        1
        for fn in report["functions"]
        for ins in fn["instructions"]
        if ins["opcode"] == "unreachable"
    )
    assert unreachable_ops >= 40
    assert any(
        ins["opcode"] == "memory.grow" and ins["immediates"] == [0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert report["analysis"]["profiles"]["control_flow"]["indirect_call_ops"] >= 4


def test_parse_wasm_file_captures_float_memory64_immediates():
    report = parse_wasm_file(_fixture_path("float_memory64.wasm"))

    assert report["errors"] == []
    assert report["memories"][0]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "f64.load" and ins["immediates"] == [3, 8]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "f32.store" and ins["immediates"] == [2, 0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_bulk64_immediates_and_profiles():
    report = parse_wasm_file(_fixture_path("bulk64.wasm"))

    assert report["errors"] == []
    assert report["memories"][0]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "memory.init" and ins["immediates"] == [0, 1]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "memory.copy" and ins["immediates"] == [0, 0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "memory.fill" and ins["immediates"] == [0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert report["analysis"]["profiles"]["memory"]["bulk_memory_ops"] >= 3


def test_parse_wasm_file_captures_memory_trap64_growth_and_loads():
    report = parse_wasm_file(_fixture_path("memory_trap64.wasm"))

    assert report["errors"] == []
    assert report["memories"][0]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "memory.grow" and ins["immediates"] == [0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "i32.load" and ins["immediates"] == [2, 0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_table_fill64_ops():
    report = parse_wasm_file(_fixture_path("table_fill64.wasm"))

    assert report["errors"] == []
    assert report["tables"][1]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "table.fill" and ins["immediates"] == [1]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "table.get" and ins["immediates"] == [1]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_table_set64_ops():
    report = parse_wasm_file(_fixture_path("table_set64.wasm"))

    assert report["errors"] == []
    assert report["tables"][0]["limits"]["is_64"] is True
    assert report["tables"][1]["limits"]["is_64"] is True
    assert any(
        ins["opcode"] == "table.set" and ins["immediates"] == [0]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "table.set" and ins["immediates"] == [1]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )


def test_parse_wasm_file_captures_table_size64_limits_and_growth():
    report = parse_wasm_file(_fixture_path("table_size64.wasm"))

    assert report["errors"] == []
    assert all(table["limits"]["is_64"] is True for table in report["tables"])
    assert any(
        ins["opcode"] == "table.size" and ins["immediates"] == [3]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert any(
        ins["opcode"] == "table.grow" and ins["immediates"] == [3]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
    assert report["analysis"]["profiles"]["control_flow"]["table_mutation_ops"] >= 4


def test_parse_wasm_file_captures_simd_store64_lane_immediates():
    report = parse_wasm_file(_fixture_path("simd_store64_lane.wasm"))

    assert report["errors"] == []
    assert any(
        ins["opcode"] == "v128.store64_lane" and ins["immediates"] == [2, 1, 1]
        for fn in report["functions"]
        for ins in fn["instructions"]
    )
