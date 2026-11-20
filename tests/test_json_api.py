import json
import os

from wasm_tools.api import (
    apply_instruction_budget,
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


# ─── WASM 3.0-era coverage: JS String Builtins, branch hints, multi-memory ──


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


def test_parse_wasm_file_detects_js_string_builtins():
    raw = _fixture_bytes("js_string.wasm")
    report = parse_wasm_bytes(raw, "js_string.wasm")

    analysis = report["analysis"]
    assert "js-strings" in analysis["capabilities"]
    assert "js.host" in analysis["capabilities"]
    js_detection = analysis["detections"]["js_interface"]
    assert js_detection["detected"] is True
    assert "js_string_builtins" in js_detection["signals"]
    assert js_detection["js_string_builtins"] == 3
    assert js_detection["builtin_sets"] == ["js-string"]


def test_js_string_capability_carries_js_host_risk_weight():
    raw = _fixture_bytes("js_string.wasm")
    report = parse_wasm_bytes(raw, "js_string.wasm")
    analysis = report["analysis"]
    # js-strings adds the same 6-point weight as js.host, on top of any other
    # scoring, so the risk score must reflect it.
    assert analysis["summary"]["risk_score"] >= 6


def test_parse_wasm_file_reports_multi_memory():
    raw = _fixture_bytes("multi_memory.wasm")
    report = parse_wasm_bytes(raw, "multi_memory.wasm")

    assert report["errors"] == []
    assert len(report["memories"]) == 2
    # memory.copy immediates are (dst_mem, src_mem, dst, src, len) in the
    # visitor's rendering and [dst_mem, src_mem, dst, src, len]-shaped in
    # JSON (JSON_REFERENCE documents the memory.init order [data, mem]; the
    # copy order follows the binary: dst, src, then offsets).
    ops = [i["opcode"] for fn in report["functions"] for i in fn["instructions"]]
    assert "memory.copy" in ops
    assert "memory.fill" in ops
    # The data segment points at the second memory (mem_idx 1).
    data_segments = report["data_segments"]
    assert len(data_segments) == 1
    assert data_segments[0].get("memory_index", data_segments[0].get("mem_idx", 1)) == 1


def test_parse_wasm_file_reports_branch_hints():
    # metadata.code.branch_hint custom section (branch-hinting proposal):
    # payload is vec(function) per tool-conventions CodeMetadata.md; a
    # top-level count of 2 functions is enough for the signal.
    hint_payload = _leb(2) + _leb(0) + _leb(1) + b"\x01\x00\x01" + _leb(1) + _leb(1) + b"\x01\x04\x00"
    hint_section = bytes([0]) + _leb(len(_name("metadata.code.branch_hint") + hint_payload)) + _name("metadata.code.branch_hint") + hint_payload
    core = b"\x00asm\x01\x00\x00\x00" + hint_section
    report = parse_wasm_bytes(core, "hints.wasm")

    assert "branch_hints_present" in report["analysis"]["detections"]["format"]["signals"]
    assert "isa.branch-hints" in report["analysis"]["capabilities"]


# ─── Instruction budgets (P01) ───────────────────────────────────────────────


def test_instruction_budget_default_reports_have_no_truncation_block():
    raw = _fixture_bytes("unreachable.wasm")
    report = parse_wasm_bytes(raw, "unreachable.wasm")
    assert "truncation" not in report
    for fn in report["functions"]:
        assert "instructions_truncated" not in fn


def test_instruction_budget_caps_total_and_keeps_counts():
    raw = _fixture_bytes("unreachable.wasm")
    full = parse_wasm_bytes(raw, "unreachable.wasm")
    budgeted = parse_wasm_bytes(raw, "unreachable.wasm", instruction_budget=40)

    kept = sum(len(fn["instructions"]) for fn in budgeted["functions"])
    assert kept <= 40
    # instruction_count stays the pre-trim truth on every function.
    assert kept < sum(fn["instruction_count"] for fn in budgeted["functions"])
    assert [fn["instruction_count"] for fn in full["functions"]] == [
        fn["instruction_count"] for fn in budgeted["functions"]
    ]

    truncation = budgeted["truncation"]["instructions"]
    assert truncation["budget"] == 40
    assert truncation["total_kept"] == kept
    assert truncation["total_original"] == sum(
        fn["instruction_count"] for fn in budgeted["functions"]
    )
    assert truncation["truncated_functions"] > 0
    trimmed = [fn for fn in budgeted["functions"] if fn.get("instructions_truncated")]
    assert trimmed
    for fn in trimmed:
        assert fn["instructions_kept"] == len(fn["instructions"])


def test_per_function_instruction_cap():
    raw = _fixture_bytes("unreachable.wasm")
    report = parse_wasm_bytes(
        raw, "unreachable.wasm", max_instructions_per_function=5
    )
    for fn in report["functions"]:
        assert len(fn["instructions"]) <= 5
        if fn["instruction_count"] > 5:
            assert fn["instructions_truncated"] is True
            assert fn["instructions_kept"] == 5
        else:
            assert "instructions_truncated" not in fn


def test_instruction_budget_waterfall_is_max_min_fair():
    from wasm_tools.api import _fair_instruction_shares

    # [10, 1, 1] with budget 6: equal allowance of 2 first spends 4, the
    # remainder 2 extends the long function to 4 kept.
    assert _fair_instruction_shares([10, 1, 1], 6) == [4, 1, 1]
    # A generous budget never trims.
    assert _fair_instruction_shares([10, 1, 1], 100) == [10, 1, 1]
    assert _fair_instruction_shares([], 50) == []
    # Zero budget keeps nothing.
    assert _fair_instruction_shares([7, 3], 0) == [0, 0]


def test_instruction_budget_preserves_findings_and_graph():
    raw = _fixture_bytes("dos_growth_loop.wasm")
    full = parse_wasm_bytes(raw, "dos_growth_loop.wasm")
    budgeted = parse_wasm_bytes(raw, "dos_growth_loop.wasm", instruction_budget=3)
    assert [f["id"] for f in full["analysis"]["findings"]] == [
        f["id"] for f in budgeted["analysis"]["findings"]
    ]
    assert (
        full["call_graph"]["edge_count"] == budgeted["call_graph"]["edge_count"]
    )


def test_apply_instruction_budget_trims_component_trees():
    raw = _fixture_bytes("unreachable.wasm")
    report = parse_wasm_bytes(raw, "unreachable.wasm")
    block = apply_instruction_budget(report, budget=10)
    assert block is not None
    kept = sum(len(fn["instructions"]) for fn in report["functions"])
    assert kept <= 10
    assert block["instructions"]["total_kept"] == kept
    # Applying again with no budget is a no-op.
    assert apply_instruction_budget(report, budget=None, per_function=None) is None


def test_apply_instruction_budget_counts_aliased_functions_once():
    from wasm_tools.api import _budget_functions

    fn = {"instructions": list(range(10))}
    functions = [fn, fn]  # aliased on purpose
    block = _budget_functions(functions, budget=4, per_function=None)
    assert block["instructions"]["function_count"] == 1
    assert block["instructions"]["total_kept"] == 4


def test_component_report_aggregates_per_module_truncation():
    core = _fixture_bytes("unreachable.wasm")
    imports_payload = _leb(1) + b"\x00" + _name("wasi:cli/run@0.2.0") + b"\x01\x00"
    component = (
        b"\x00asm\x0d\x00\x01\x00"
        + bytes([10]) + _leb(len(imports_payload)) + imports_payload
        + bytes([1]) + _leb(len(core)) + core
    )
    report = parse_wasm_bytes(component, "comp.wasm", instruction_budget=30)
    truncation = report.get("truncation", {}).get("instructions", {})
    assert truncation.get("core_modules"), "expected per-module truncation entries"
    module_block = truncation["core_modules"][0]
    assert module_block["core_module"] == 0
    assert module_block["budget"] == 30
    assert truncation["total_kept"] == module_block["total_kept"]


# ─── Per-function structural features (P02) ──────────────────────────────────


def test_function_features_present_on_every_local_function():
    raw = _fixture_bytes("call_graph.wasm")
    report = parse_wasm_bytes(raw, "call_graph.wasm")
    for fn in report["functions"]:
        features = fn["features"]
        for key in (
            "instruction_count",
            "has_loop",
            "max_loop_depth",
            "has_direct_call",
            "has_indirect_call",
            "has_call_ref",
            "has_tail_call",
            "has_table_mutation",
            "has_memory_grow",
            "has_bulk_memory",
            "has_simd",
            "has_atomics",
            "has_exceptions",
            "has_gc_ops",
            "calls_imported_functions",
            "imported_callees",
            "body_hash",
        ):
            assert key in features, f"missing feature {key}"


def test_function_features_track_indirect_calls_and_loops():
    raw = _fixture_bytes("call_graph.wasm")
    report = parse_wasm_bytes(raw, "call_graph.wasm")
    indirect_fns = [
        fn for fn in report["functions"] if fn["features"]["has_indirect_call"]
    ]
    assert indirect_fns, "call_indirect fixture must have an indirect caller"


def test_function_features_distinguish_loop_growth():
    growing = parse_wasm_bytes(
        _fixture_bytes("dos_growth_loop.wasm"), "dos_growth_loop.wasm"
    )
    grow_features = [
        fn["features"] for fn in growing["functions"] if fn["features"]["has_memory_grow"]
    ]
    assert grow_features, "the growing function must report has_memory_grow"
    assert any(f["has_loop"] for f in grow_features), (
        "growth inside a loop must also report has_loop"
    )

    linear = parse_wasm_bytes(
        _fixture_bytes("memory_grow_linear.wasm"), "memory_grow_linear.wasm"
    )
    # Features are function-granular, so the linear module's function
    # reports both flags; the loop-vs-grow nesting distinction that DOS-003
    # cares about stays in the analysis profiles (loop_memory_grow_ops).
    linear_grow = [
        fn["features"] for fn in linear["functions"] if fn["features"]["has_memory_grow"]
    ]
    assert linear_grow
    growing_profiles = growing["analysis"]["profiles"]["memory"]
    linear_profiles = linear["analysis"]["profiles"]["memory"]
    assert growing_profiles["loop_memory_grow_ops"] > 0
    assert linear_profiles["loop_memory_grow_ops"] == 0


def test_function_features_flag_isa_families():
    cases = {
        "simd_basic.wasm": "has_simd",
        "threads_basic.wasm": "has_atomics",
        "exceptions_basic.wasm": "has_exceptions",
        "gc_ops.wasm": "has_gc_ops",
        "call_refs.wasm": "has_call_ref",
        "bulk_memory.wasm": "has_bulk_memory",
    }
    for fixture, key in cases.items():
        report = parse_wasm_bytes(_fixture_bytes(fixture), fixture)
        assert any(fn["features"][key] for fn in report["functions"]), (
            f"{fixture} must set {key} on at least one function"
        )


def test_function_features_count_imported_callees():
    raw = _fixture_bytes("import_calls.wasm")
    report = parse_wasm_bytes(raw, "import_calls.wasm")
    callers = [
        fn for fn in report["functions"] if fn["features"]["calls_imported_functions"]
    ]
    assert len(callers) == 2, "both exported functions call WASI imports"
    # fd_write is called from both functions, proc_exit from one.
    assert sum(f["features"]["imported_callees"] for f in callers) == 3
    assert all(f["features"]["imported_callees"] >= 1 for f in callers)


def test_function_body_hash_matches_identical_bodies():
    raw = _fixture_bytes("duplicate_bodies.wasm")
    report = parse_wasm_bytes(raw, "duplicate_bodies.wasm")
    # wat2wasm emits no name section here, so key functions by index:
    # 0 and 1 are the identical bodies, 2 is distinct.
    hashes = {fn["index"]: fn["features"]["body_hash"] for fn in report["functions"]}
    assert hashes[0] == hashes[1]
    assert hashes[0] != hashes[2]
    assert hashes[0].startswith("sha256:")


def test_function_features_independent_of_call_graph_and_budget():
    raw = _fixture_bytes("dos_growth_loop.wasm")
    without_graph = parse_wasm_bytes(raw, "m.wasm", include_call_graph=False)
    with_graph = parse_wasm_bytes(raw, "m.wasm")
    assert [fn["features"] for fn in without_graph["functions"]] == [
        fn["features"] for fn in with_graph["functions"]
    ]
    budgeted = parse_wasm_bytes(raw, "m.wasm", instruction_budget=3)
    assert [fn["features"] for fn in budgeted["functions"]] == [
        fn["features"] for fn in with_graph["functions"]
    ]
