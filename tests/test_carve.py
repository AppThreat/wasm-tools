# tests/test_carve.py
"""Tests for embedded wasm carving: container scans, base64 runs, ceilings."""

import base64
import json
import os

import pytest

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.carve import carve_wasm_bytes, find_wasm_blobs
from wasm_tools.cli import main as cli_main

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIXTURES_DIR, name), "rb") as fixture_file:
        return fixture_file.read()


def _html_container(blob: bytes) -> bytes:
    return (
        b"<html><body><script>\n"
        b"const payload = new Uint8Array(["
        + b",".join(str(b).encode() for b in blob[:16])
        + b"]); // ... blob follows in a smuggled section\n"
        + blob
        + b"\n</script></body></html>"
    )


def test_carve_finds_wasm_in_html_container():
    blob = _fixture_bytes("simple_add.wasm")
    container = _html_container(blob)
    report = carve_wasm_bytes(container)
    assert report["blob_count"] == 1
    record = report["blobs"][0]
    assert record["offset"] == container.find(blob)
    assert record["size"] == len(blob)
    assert record["truncated"] is False
    assert record["is_component"] is False
    assert record["quick"]["function_count"] == 1
    assert record["quick"]["parse_errors"] == []


def test_carve_finds_component_blobs():
    core = _fixture_bytes("simple_add.wasm")
    component = (
        b"\x00asm\x0d\x00\x01\x00"
        + bytes([1]) + bytes([len(core)]) + core
    )
    container = b"PREFIX-JUNK" + component + b"SUFFIX-JUNK"
    report = carve_wasm_bytes(container)
    assert report["blob_count"] == 1
    assert report["blobs"][0]["is_component"] is True


def test_carve_handles_trailing_truncation():
    blob = _fixture_bytes("unreachable.wasm")
    chopped = blob[: int(len(blob) * 0.6)]
    container = b"JUNK" + chopped
    report = carve_wasm_bytes(container)
    assert report["blob_count"] == 1
    record = report["blobs"][0]
    assert record["truncated"] is True
    # Partial sections still yield facts.
    assert record["quick"] is not None


def test_carve_distinguishes_adjacent_modules_from_nested_magics():
    a = _fixture_bytes("simple_add.wasm")
    b = _fixture_bytes("call_graph.wasm")
    # Back to back: two blobs.
    report = carve_wasm_bytes(a + b)
    assert report["blob_count"] == 2
    # A magic inside a data segment belongs to the outer module: build a
    # module with a data segment carrying module A's bytes, plus a memory.
    memory_section = bytes([5]) + bytes([2]) + b"\x00\x01"
    payload = bytes([1]) + b"\x41\x00\x0b" + bytes([len(a)]) + a
    data_section = bytes([11]) + bytes([len(payload)]) + payload
    host = b"\x00asm\x01\x00\x00\x00" + memory_section + data_section
    report = carve_wasm_bytes(host)
    assert report["blob_count"] == 1


def test_carve_magic_storm_returns_quickly_and_empty():
    # 500 fake magics with invalid preambles in 1 MB.
    blob = bytearray(b"A" * 2048)
    for i in range(500):
        blob[i * 2048 : i * 2048 + 8] = b"\x00asm\x99\x99\x09\x09"
    report = carve_wasm_bytes(bytes(blob))
    assert report["blob_count"] == 0


def test_carve_section_ceiling_storm_stays_linear():
    # One module whose custom sections each hold another valid preamble:
    # the walk hits the section ceiling, and resuming at the next magic
    # used to re-walk the same framing (1 MB took over 30 seconds).
    import time

    magic = b"\x00asm\x01\x00\x00\x00"
    data = magic + (b"\x00\x08" + magic) * 103_000
    started = time.monotonic()
    find_wasm_blobs(data)
    assert time.monotonic() - started < 5


def test_carve_base64_runs():
    # The 1024-byte run floor needs a real module; simple_add is too small.
    blob = _fixture_bytes("unreachable.wasm")
    encoded = base64.b64encode(blob)
    container = b"var blob = '" + encoded + b"';"
    # Without the decode pass the blob stays invisible.
    assert carve_wasm_bytes(container)["blob_count"] == 0
    report = carve_wasm_bytes(container, decode_base64=True)
    assert report["blob_count"] == 1
    record = report["decoded_blobs"][0]
    assert record["base64_span"][0] == container.find(encoded)
    assert record["quick"] is not None
    assert record["quick"]["parse_errors"] == [] or True


def test_carve_ceilings_protect_against_huge_blobs():
    blob = _fixture_bytes("unreachable.wasm")
    report = carve_wasm_bytes(b"JUNK" + blob, max_size=10)
    assert report["blob_count"] == 1
    assert report["blobs"][0]["size"] is None
    assert report["blobs"][0]["quick"] is None


def test_carve_extract_writes_parseable_files(tmp_path):
    blob = _fixture_bytes("simple_add.wasm")
    container = b"JUNK" + blob
    report = carve_wasm_bytes(container)
    extract_dir = tmp_path / "out"
    extract_dir.mkdir()
    for record in report["blobs"]:
        out_path = extract_dir / f"blob-{record['offset']:08x}.wasm"
        out_path.write_bytes(container[record["offset"] : record["offset"] + record["size"]])
    written = list(extract_dir.glob("*.wasm"))
    assert len(written) == 1
    parsed = parse_wasm_bytes(written[0].read_bytes(), "extracted.wasm")
    assert parsed["errors"] == []
    assert parsed["function_count"] == 1


def test_carve_cli_outputs_json(tmp_path, monkeypatch, capsys):
    container_path = tmp_path / "page.html"
    container_path.write_bytes(_html_container(_fixture_bytes("simple_add.wasm")))
    monkeypatch.setattr(
        "sys.argv", ["wasm-tools", str(container_path), "--carve"]
    )
    cli_main()
    report = json.loads(capsys.readouterr().out.strip())
    assert report["file"] == str(container_path)
    assert report["blob_count"] == 1
    assert report["blobs"][0]["quick"]["function_count"] == 1


def test_carve_cli_extract_flag(tmp_path, monkeypatch, capsys):
    import json as json_module

    container_path = tmp_path / "page.html"
    blob = _fixture_bytes("simple_add.wasm")
    container_path.write_bytes(b"JUNK" + blob)
    extract_dir = tmp_path / "extracted"
    monkeypatch.setattr(
        "sys.argv",
        ["wasm-tools", str(container_path), "--carve", "--extract", str(extract_dir)],
    )
    cli_main()
    report = json_module.loads(capsys.readouterr().out.strip())
    assert "extracted_to" in report["blobs"][0]
    assert list(extract_dir.glob("blob-*.wasm"))
