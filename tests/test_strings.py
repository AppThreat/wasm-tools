"""Tests for string extraction and secret/IoC heuristics."""

import sys
from pathlib import Path

import pytest

from wasm_tools.api import _BinaryReaderJsonCollector, parse_wasm_bytes, parse_wasm_file
from wasm_tools.cli import main as cli_main
from wasm_tools.strings import analyze_strings, extract_strings

_FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return str(_FIXTURES / name)


# ─── extraction ──────────────────────────────────────────────────────────────


def test_extract_strings_ascii_with_memory_provenance():
    segments = [(0, 1024, b"\x00\x00https://example.com\x00trailing")]
    entries, truncated = extract_strings(segments, min_len=5)
    assert truncated is False
    assert entries == [
        {
            "segment_index": 0,
            "byte_offset": 2,
            "memory_offset": 1026,
            "length": 19,
            "encoding": "utf-8",
            "value": "https://example.com",
        },
        {
            "segment_index": 0,
            "byte_offset": 22,
            "memory_offset": 1046,
            "length": 8,
            "encoding": "utf-8",
            "value": "trailing",
        },
    ]


def test_extract_strings_passive_segment_has_null_memory_offset():
    segments = [(3, None, b"anonymous blob")]
    entries, _ = extract_strings(segments, min_len=5)
    assert entries[0]["memory_offset"] is None
    assert entries[0]["segment_index"] == 3


def test_extract_strings_utf16le():
    payload = "deep string".encode("utf-16-le") + b"\x00\x01"
    segments = [(0, 0, payload)]
    entries, _ = extract_strings(segments, min_len=5)
    utf16 = [e for e in entries if e["encoding"] == "utf-16le"]
    assert len(utf16) == 1
    assert utf16[0]["value"] == "deep string"


def test_extract_strings_respects_min_len_and_cap():
    segments = [(0, 0, b"abcdefgh")]
    entries, _ = extract_strings(segments, min_len=9)
    assert entries == []
    entries, truncated = extract_strings(
        [(0, 0, b"aaa\x00bbb\x00ccc\x00ddd")], min_len=3, max_entries=2
    )
    assert truncated is True
    assert len(entries) == 2


# ─── heuristics ──────────────────────────────────────────────────────────────


def test_analyze_strings_flags_url_aws_jwt_pem():
    entries = [
        {"value": "fetch https://evil.example.com/p from here"},
        {"value": "key=AKIAIOSFODNN7EXAMPLE"},
        {"value": "xeyJnotajwt.y.z"},
        {"value": "header -----BEGIN RSA PRIVATE KEY-----"},
    ]
    det = analyze_strings(entries)
    assert det["detected"] is True
    for signal in ("url", "aws_access_key", "pem_private_key"):
        assert signal in det["signals"]
    # "eyJnotajwt.y.z" is not a full JWT (short segments) -> must not match
    assert "jwt_token" not in det["signals"]


def test_analyze_strings_flags_jwt_and_mining():
    det = analyze_strings(
        [
            {
                "value": (
                    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
                )
            },
            {"value": "stratum+tcp://pool.minexmr.com:3333"},
        ]
    )
    assert "jwt_token" in det["signals"]
    assert "mining_indicator" in det["signals"]


def test_analyze_strings_quiet_on_benign_text():
    det = analyze_strings([{"value": "just a plain harmless string for coverage"}])
    assert det["detected"] is False
    assert det["signals"] == []


# ─── report integration ──────────────────────────────────────────────────────


def test_strings_secrets_fixture_report_and_finding():
    report = parse_wasm_file(_fixture("strings_secrets.wasm"))
    assert report["errors"] == []

    values = [entry["value"] for entry in report["strings"]]
    assert "https://evil.example.com/payload" in values
    assert "AKIAIOSFODNN7EXAMPLE" in values
    assert any(v.startswith("-----BEGIN RSA PRIVATE KEY") for v in values)

    detection = report["analysis"]["detections"]["strings"]
    assert detection["detected"] is True
    for signal in ("url", "aws_access_key", "jwt_token", "pem_private_key"):
        assert signal in detection["signals"]

    finding_ids = [f["id"] for f in report["analysis"]["findings"]]
    assert "WASM-STR-007" in finding_ids
    finding = next(f for f in report["analysis"]["findings"] if f["id"] == "WASM-STR-007")
    assert finding["severity"] == "high"
    assert "url" in finding["evidence"]["signals"]


def test_plain_module_has_no_strings_finding():
    report = parse_wasm_file(_fixture("simple_add.wasm"))
    assert report["analysis"]["detections"]["strings"]["detected"] is False
    assert "WASM-STR-007" not in [
        f["id"] for f in report["analysis"]["findings"]
    ]


# ─── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_strings_mode(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", _fixture("strings_secrets.wasm"), "--strings"]
    )
    cli_main()
    out = capsys.readouterr().out
    assert "Strings:" in out
    assert "https://evil.example.com/payload" in out
    assert "utf-8" in out
    assert "mem[" in out


def test_cli_strings_min_len_filters(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["wasm-tools", _fixture("strings_secrets.wasm"), "--strings", "--strings-min-len", "40"],
    )
    cli_main()
    out = capsys.readouterr().out
    assert "https://evil.example.com/payload" not in out
    assert "just a plain harmless string for baseline coverage" in out


# ─── regression: min_len must reach extraction ───────────────────────────────


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


def _short_strings_module() -> bytes:
    # One active data segment at offset 0 containing "hi\0yo".
    payload = _leb(1) + b"\x00" + b"\x41\x00\x0b" + _leb(5) + b"hi\x00yo"
    section = bytes([11]) + _leb(len(payload)) + payload
    return b"\x00asm\x01\x00\x00\x00" + section


def test_strings_min_len_below_default_surfaces_short_strings():
    data = _short_strings_module()
    default = parse_wasm_bytes(data)
    assert "hi" not in [e["value"] for e in default["strings"]]

    lowered = parse_wasm_bytes(data, strings_min_len=2)
    values = [e["value"] for e in lowered["strings"]]
    assert "hi" in values
    assert "yo" in values


def test_cli_strings_min_len_two_surfaces_short_strings(capsys, monkeypatch, tmp_path):
    path = tmp_path / "short.wasm"
    path.write_bytes(_short_strings_module())
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", str(path), "--strings", "--strings-min-len", "2"]
    )
    cli_main()
    out = capsys.readouterr().out
    assert '"hi"' in out
    assert '"yo"' in out


# ─── severity policy and sample masking ──────────────────────────────────────


def test_str_007_url_only_is_medium_severity():
    det = {"detected": True, "signals": ["url"], "counts": {"url": 1}, "samples": {}}
    from wasm_tools.models import ObjdumpState

    findings = _BinaryReaderJsonCollector("x", ObjdumpState())._build_findings(
        capabilities=[],
        indirect_call_ops=0,
        table_mutation_ops=0,
        dynamic_funcs=set(),
        table_mutation_funcs=set(),
        memory_grow_ops=0,
        loop_memory_ops=0,
        loop_memory_funcs=set(),
        loop_memory_grow_ops=0,
        loop_grow_funcs=set(),
        format_detection={"kind": "core"},
        loop_max_depth=0,
        js_interface_detection={"detected": False},
        js_exposed_dynamic_funcs=set(),
        js_exposed_table_mutation_funcs=set(),
        strings_detection=det,
    )
    finding = next(f for f in findings if f["id"] == "WASM-STR-007")
    assert finding["severity"] == "medium"
    assert finding["evidence"]["signals"] == ["url"]


def test_aws_sample_is_masked():
    det = analyze_strings([{"value": "key=AKIAIOSFODNN7EXAMPLE"}])
    sample = det["samples"]["aws_access_key"]
    assert sample.startswith("AKIA")
    assert "IOSFODNN7EXAMPLE" not in sample
    assert sample.endswith("...")


def test_opt_out_flags_exclude_derived_blocks():
    data = (_FIXTURES / "strings_secrets.wasm").read_bytes()
    report = parse_wasm_bytes(data, include_strings=False, include_call_graph=False)
    assert report["strings"] == []
    assert report["strings_truncated"] is False
    assert report["call_graph"] == {}
    assert report["analysis"]["detections"]["strings"]["detected"] is False
    assert "export_reachable_functions" not in report["analysis"]["profiles"]["control_flow"]
    # The same files with defaults still carry both blocks.
    assert parse_wasm_bytes(data)["strings"]
    assert parse_wasm_bytes((_FIXTURES / "call_graph.wasm").read_bytes())["call_graph"]["edges"]


def test_cli_json_no_strings_no_call_graph(capsys, monkeypatch):
    import json

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wasm-tools",
            _fixture("strings_secrets.wasm"),
            "--json",
            "--no-strings",
            "--no-call-graph",
        ],
    )
    cli_main()
    report = json.loads(capsys.readouterr().out)
    assert report["strings"] == []
    assert report["call_graph"] == {}
    # Findings depending on strings also disappear.
    assert "WASM-STR-007" not in [f["id"] for f in report["analysis"]["findings"]]
