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
    assert "preview2" in wasi["variants"]
    assert "preview2-like" not in wasi["variants"]
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
    assert jsi["signature_surface"] == {
        "boundary_count": 1,
        "risky_boundary_count": 0,
        "risks": [],
        "entries": [
            {
                "source": "export",
                "name": "add",
                "index": 0,
                "type_index": 0,
                "params": ["i32", "i32"],
                "results": ["i32"],
            }
        ],
    }
    assert jsi["risky_import_signatures"] == []
    assert jsi["entry_trampolines"] == {
        "detected": False,
        "count": 0,
        "functions": [],
    }


def test_parse_wasm_file_reports_js_boundary_surface_and_deopt_proxies():
    report = parse_wasm_file(_fixture_path("js_deopt_surface.wasm"))

    assert report["errors"] == []
    jsi = report["analysis"]["detections"]["js_interface"]
    assert jsi["detected"] is True
    assert jsi["confidence"] == "high"
    assert set(jsi["signature_surface"]["risks"]) >= {
        "externref_i64_mix",
        "multi_result_boundary",
        "ref_numeric_mix",
    }
    assert jsi["signature_surface"]["boundary_count"] >= 7
    assert jsi["signature_surface"]["risky_boundary_count"] >= 1
    assert any(
        sig["name"] == "to_i64" and "externref_i64_mix" in sig["reasons"]
        for sig in jsi["risky_import_signatures"]
    )

    assert jsi["entry_trampolines"]["detected"] is True
    assert any(
        item["risk_ops"]
        for item in jsi["entry_trampolines"]["functions"]
        if item["index"] >= 0
    )

    cf = report["analysis"]["profiles"]["control_flow"]
    assert cf["callsite_conversion_ops"] >= 1
    assert cf["call_ref_unguarded_ops"] >= 1

    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-CFG-002" in finding_ids
    assert "WASM-JSCFG-006" in finding_ids


def test_parse_wasm_file_profiles_call_ref_guard_quality():
    report = parse_wasm_file(_fixture_path("call_refs.wasm"))

    cf = report["analysis"]["profiles"]["control_flow"]
    assert cf["call_ref_unguarded_ops"] >= 1


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
    assert report["memories"][0]["limits"] == {
        "min": 1,
        "max": 3,
        "is_64": True,
        "shared": True,
        "page_size_log2": None,
    }


def test_parse_wasm_file_captures_table_init64_tables_and_immediates():
    report = parse_wasm_file(_fixture_path("table_init64.wasm"))

    assert report["errors"] == []
    assert report["tables"][2]["limits"] == {
        "min": 30,
        "max": 30,
        "is_64": True,
        "shared": False,
        "page_size_log2": None,
    }
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


# ─── DOS-003 tightening: growth must sit inside a loop body ─────────────────


def test_growth_outside_loop_with_loop_memory_ops_does_not_fire():
    # memory_grow_linear.wasm: one startup memory.grow plus memory traffic
    # inside a loop. The old rule (any grow + any loop memory op) fired here.
    report = parse_wasm_file(_fixture_path("memory_grow_linear.wasm"))

    finding_ids = {f["id"] for f in report["analysis"]["findings"]}
    assert "WASM-DOS-003" not in finding_ids
    # the loop memory traffic is still profiled
    assert report["analysis"]["profiles"]["compute"]["loop_memory_ops"] >= 1
    assert report["analysis"]["profiles"]["memory"]["memory_grow_ops"] >= 1


def test_loop_growth_finding_reports_grow_site_evidence():
    report = parse_wasm_file(_fixture_path("dos_growth_loop.wasm"))

    dos = next(f for f in report["analysis"]["findings"] if f["id"] == "WASM-DOS-003")
    assert dos["evidence"]["loop_memory_grow_ops"] >= 1
    assert dos["evidence"]["memory_grow_ops"] >= 1
    # functions list names grow-in-loop sites only, capped for large modules
    assert len(dos["evidence"]["functions"]) <= 50
    assert dos["evidence"]["functions"]


# ─── GC type kinds in the JSON report ───────────────────────────────────────


def test_rec_group_fixture_reports_correct_type_indices_and_kinds():
    report = parse_wasm_file(_fixture_path("gc_rec_group.wasm"))

    types = {t["index"]: t for t in report["types"]}
    assert sorted(types) == [0, 1, 2, 3]
    assert types[0]["kind"] == "func"
    assert types[1]["kind"] == "struct"
    assert types[2]["kind"] == "struct"
    assert types[3]["kind"] == "func"
    assert types[3]["params"] == ["anyref"]
    # the second function uses the post-rec-group func type at index 3
    func1 = next(f for f in report["functions"] if f["index"] == 1)
    assert func1["signature_index"] == 3


def test_plain_module_types_default_to_func_kind():
    report = parse_wasm_file(_fixture_path("simple_add.wasm"))

    assert report["types"], "expected at least one type"
    assert all(t["kind"] == "func" for t in report["types"])


# ─── DWARF awareness ────────────────────────────────────────────────────────


def _debug_module():
    # A module with .debug_info and .debug_str custom sections appended.
    def leb(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out += bytes([b | 0x80])
            else:
                out += bytes([b])
                return out

    def name(s):
        raw = s.encode()
        return leb(len(raw)) + raw

    def custom(payload):
        return bytes([0]) + leb(len(payload)) + payload

    debug_info = custom(name(".debug_info") + b"\x00\x01\x02")
    debug_str = custom(name(".debug_str") + b"src/main.c\x00libfoo\x00")
    return b"\x00asm\x01\x00\x00\x00" + debug_info + debug_str


def test_dwarf_sections_set_debug_info_present_signal():
    from wasm_tools.api import parse_wasm_bytes

    report = parse_wasm_bytes(_debug_module())
    signals = report["analysis"]["detections"]["format"]["signals"]
    assert "debug_info_present" in signals


def test_debug_str_strings_extracted_with_custom_provenance():
    from wasm_tools.api import parse_wasm_bytes

    report = parse_wasm_bytes(_debug_module())
    debug_hits = [s for s in report["strings"] if s.get("source") == "custom:.debug_str"]
    values = {s["value"] for s in debug_hits}
    assert "src/main.c" in values
    assert "libfoo" in values
    for hit in debug_hits:
        assert hit["segment_index"] is None
        assert hit["memory_offset"] is None


def test_debug_str_strings_do_not_feed_secret_detection():
    # A credential-looking value in .debug_str must not raise STR-007:
    # the finding is documented for data segments.
    from wasm_tools.api import parse_wasm_bytes

    def leb(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out += bytes([b | 0x80])
            else:
                out += bytes([b])
                return out

    def name(s):
        raw = s.encode()
        return leb(len(raw)) + raw

    payload = name(".debug_str") + b"https://evil.example.com\x00"
    custom = bytes([0]) + leb(len(payload)) + payload
    report = parse_wasm_bytes(b"\x00asm\x01\x00\x00\x00" + custom)
    detection = report["analysis"]["detections"]["strings"]
    assert "url" not in detection["signals"]
    # but the value is still reported for the analyst
    assert any(s["value"] == "https://evil.example.com" for s in report["strings"])


# ─── isa.* tokens that do not come from opcodes ─────────────────────────────


def test_gc_type_definitions_alone_yield_isa_gc():
    # gc_rec_group.wasm defines struct types and an anyref parameter but never
    # executes a GC instruction; an engine still needs GC support to load it.
    report = parse_wasm_file(_fixture_path("gc_rec_group.wasm"))

    assert "isa.gc" in report["analysis"]["capabilities"]


def test_imported_64_bit_memory_yields_isa_memory64():
    # Emscripten-style modules import their memory, so the memory section is
    # empty and only the import carries the 64-bit index type.
    def leb(n):
        out = b""
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out += bytes([b | 0x80])
            else:
                return out + bytes([b])

    def name(s):
        raw = s.encode()
        return leb(len(raw)) + raw

    # import section: env.memory, memory type, flags 0x04 (is_64), min 1
    payload = leb(1) + name("env") + name("memory") + b"\x02" + b"\x04" + leb(1)
    module = b"\x00asm\x01\x00\x00\x00" + bytes([2]) + leb(len(payload)) + payload
    report = parse_wasm_bytes(module)

    assert report["imports"][0]["limits"]["is_64"] is True
    assert "isa.memory64" in report["analysis"]["capabilities"]


def test_memory_profile_exposes_loop_growth_counter():
    report = parse_wasm_file(_fixture_path("dos_growth_loop.wasm"))
    linear = parse_wasm_file(_fixture_path("memory_grow_linear.wasm"))

    assert report["analysis"]["profiles"]["memory"]["loop_memory_grow_ops"] >= 1
    assert linear["analysis"]["profiles"]["memory"]["loop_memory_grow_ops"] == 0
    assert linear["analysis"]["profiles"]["memory"]["memory_grow_ops"] >= 1
