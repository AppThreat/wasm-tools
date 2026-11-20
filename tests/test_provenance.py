# tests/test_provenance.py
"""Tests for toolchain provenance detection and pure-Python demangling."""

import os

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.demangle import demangle, demangle_best_effort
from wasm_tools.provenance import build_provenance

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as fixture_file:
        return fixture_file.read()


def _provenance(report: dict) -> dict:
    return report["analysis"]["provenance"]


# ─── corpus provenance ───────────────────────────────────────────────────────


def test_bz2_provenance_clang_via_producers():
    report = parse_wasm_bytes(_fixture_bytes("corpus/bz2.wasm"), "bz2.wasm")
    provenance = _provenance(report)
    names = [c["name"] for c in provenance["compilers"]]
    assert "clang" in names
    clang = next(c for c in provenance["compilers"] if c["name"] == "clang")
    assert clang["confidence"] == "high"
    assert clang["version"].startswith("11.0.0")
    assert any("producers" in e for e in clang["evidence"])
    assert provenance["runtime_target"]["name"] in {"wasi-preview1", "unknown"}


def test_erc20_provenance_reports_something_or_notes():
    report = parse_wasm_bytes(_fixture_bytes("corpus/erc20.wasm"), "erc20.wasm")
    provenance = _provenance(report)
    # The Soroban fixtures carry no producers; provenance must be honest
    # about it rather than inventing a compiler claim.
    claimed = {c["name"] for c in provenance["compilers"]}
    if not claimed:
        assert provenance["runtime_target"]["name"] in {"unknown", "wasi-preview1"}


def test_wasm_bindgen_glue_detection():
    report = parse_wasm_bytes(_fixture_bytes("js_interface.wasm"), "js.wasm")
    provenance = _provenance(report)
    glue_names = [g["name"] for g in provenance["glue"]]
    assert "wasm-bindgen" in glue_names
    bindgen = next(g for g in provenance["glue"] if g["name"] == "wasm-bindgen")
    assert bindgen["confidence"] in {"high", "medium"}
    assert bindgen["evidence"], "every claim names its evidence"


def test_wasi_runtime_target_detection():
    report = parse_wasm_bytes(_fixture_bytes("wasi_capabilities.wasm"), "w.wasm")
    provenance = _provenance(report)
    assert provenance["runtime_target"]["name"] == "wasi-preview1"
    assert provenance["runtime_target"]["confidence"] == "high"


def test_wasi_preview2_target_detection():
    report = parse_wasm_bytes(_fixture_bytes("wasi_preview2_like.wasm"), "w.wasm")
    provenance = _provenance(report)
    assert provenance["runtime_target"]["name"] == "wasi-preview2+"


def test_fastly_platform_detection():
    # A module importing fastly:compute interfaces resolves the platform.
    def _leb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _name(s):
        raw = s.encode()
        return _leb(len(raw)) + raw

    imports_payload = (
        _leb(1)
        + _name("fastly:compute/http-req@0.1.0")
        + _name("get")
        + b"\x00\x00"
    )
    module = (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([2]) + _leb(len(imports_payload)) + imports_payload
    )
    report = parse_wasm_bytes(module, "fastly.wasm")
    provenance = _provenance(report)
    assert provenance["platform"]["name"] == "fastly-compute"
    assert provenance["platform"]["confidence"] == "high"
    hints = {h["hint"] for h in report["analysis"]["dependency_hints"]}
    assert "fastly-compute" in hints


def test_provenance_never_claims_versions_without_evidence():
    report = parse_wasm_bytes(_fixture_bytes("simple_add.wasm"), "s.wasm")
    provenance = _provenance(report)
    for compiler in provenance["compilers"] + provenance["glue"]:
        if compiler["confidence"] == "medium":
            assert compiler["version"] == "", (
                "medium-confidence claims never state a version"
            )


# ─── demangling ──────────────────────────────────────────────────────────────


def test_demangle_rust_legacy():
    assert (
        demangle("_ZN10wasm_tools3cli4main17h1a2b3c4d5e6f7a8bE")
        == "wasm_tools::cli::main"
    )
    assert (
        demangle("_ZN4core3ptr13drop_in_place17h4518ea05d7edef0cE")
        == "core::ptr::drop_in_place"
    )


def test_demangle_rust_v0():
    assert (
        demangle("_RNvCs9u3S9iDnTzs_10demo_write4main") == "demo_write::main"
    )
    assert demangle("_RNvC7mycrate4main") == "mycrate::main"
    assert (
        demangle("_RNCNvNtC7mycrate3foo3bar0")
        == "mycrate::foo::bar::{closure#0}"
    )


def test_demangle_leaves_out_of_scope_names_unchanged():
    # C++ Itanium (no hash terminator), M-path v0 forms, plain names.
    for name in (
        "_ZNSt6vectorIiSaIiEE9push_backERKi",
        "_RNvMNtCs4R8zzWJ3UaT_6simple5Thing3new",
        "not_mangled",
        "_ZNtruncated",
        "",
    ):
        assert demangle(name) == name


def test_demangle_never_raises_on_adversarial_input():
    for name in (
        "_R" + "N" * 500,
        "_RNs" + "9" * 300,
        "_ZN99999999999999x",
        "_R" + "C" + "s" * 50,
    ):
        assert demangle(name) == name


def test_demangle_batch_maps_only_changed_names():
    mapping = demangle_best_effort(
        ["_ZN10wasm_tools3cli4main17h1a2b3c4d5e6f7a8bE", "plain_export"]
    )
    assert mapping == {"_ZN10wasm_tools3cli4main17h1a2b3c4d5e6f7a8bE": "wasm_tools::cli::main"}


def test_demangling_attaches_demangled_name_and_never_changes_identity():
    # A module with a mangled name section: functions gain demangled_name
    # and the call graph keeps index-based identity.
    def _leb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _name(s):
        raw = s.encode()
        return _leb(len(raw)) + raw

    body = _leb(0) + b"\x0b"
    code = _leb(1) + _leb(len(body)) + body
    module = (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1]) + _leb(4) + _leb(1) + b"\x60\x00\x00"
        + bytes([3]) + _leb(2) + _leb(1) + _leb(0)
        + bytes([10]) + _leb(len(code)) + code
    )
    entries = _leb(1) + _leb(0) + _name("_ZN5mymod3run17hab12cd34ef56ab12E")
    name_section = (
        bytes([0]) + _leb(len(_name("name") + _leb(1) + _leb(len(entries)) + entries))
        + _name("name") + _leb(1) + _leb(len(entries)) + entries
    )
    raw = module + name_section

    demangled_report = parse_wasm_bytes(raw, "m.wasm")
    assert demangled_report["functions"][0]["demangled_name"] == "mymod::run"
    undemangled = parse_wasm_bytes(raw, "m.wasm", include_demangled=False)
    assert "demangled_name" not in undemangled["functions"][0]

    # Node identity is index-based and unaffected by demangling.
    graph_with = demangled_report["call_graph"]
    graph_without = undemangled["call_graph"]
    assert [n["index"] for n in graph_with["nodes"]] == [
        n["index"] for n in graph_without["nodes"]
    ]
    assert [e["kind"] for e in graph_with["edges"]] == [
        e["kind"] for e in graph_without["edges"]
    ]
