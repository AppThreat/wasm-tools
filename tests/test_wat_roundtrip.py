# tests/test_wat_roundtrip.py
"""Round-trip conformance harness: emit WAT, recompile with wat2wasm, compare
the decoded instruction sequences. The strongest regression net the parser
has: any decoder or emitter drift that changes the program's meaning shows
up here. Skips gracefully when wat2wasm is absent (test_docs.py's pattern).
"""

import functools
import os
import shutil
import subprocess
import tempfile

import pytest

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.wat import emit_wat

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

_WAT2WASM = shutil.which("wat2wasm")

# Per-fixture assembler flags, mirroring tests/fixtures/build.py so emitted
# WAT recompiles under the same feature gates the fixtures were built with.
_EXTRA_FLAGS = {
    "simd_basic.wat": ["--enable-simd"],
    "exceptions_basic.wat": ["--enable-exceptions"],
    "threads_basic.wat": ["--enable-threads"],
    "call_refs.wat": ["--enable-function-references", "--enable-gc"],
    "js_deopt_surface.wat": ["--enable-function-references", "--enable-gc"],
    "load64.wat": ["--enable-memory64"],
    "memory64_shared.wat": ["--enable-memory64", "--enable-threads"],
    "table_init64.wat": ["--enable-memory64"],
    "float_memory64.wat": ["--enable-memory64"],
    "bulk64.wat": ["--enable-memory64"],
    "memory_trap64.wat": ["--enable-memory64"],
    "table_fill64.wat": ["--enable-memory64"],
    "table_set64.wat": ["--enable-memory64"],
    "table_size64.wat": ["--enable-memory64"],
    "thunk_swarm.wat": ["--debug-names"],
}





def _roundtrip(name: str) -> None:
    raw = open(os.path.join(FIXTURES_DIR, name), "rb").read()
    report = parse_wasm_bytes(raw, name)
    if report.get("is_component"):
        pytest.skip("components emit per-core-module WAT")
    wat_text = emit_wat(report, source=raw)
    assert ";; unknown opcode" not in wat_text, f"{name}: emitter hit unknown opcodes"

    with tempfile.TemporaryDirectory() as tmp:
        wat_path = os.path.join(tmp, "module.wat")
        wasm_path = os.path.join(tmp, "module.wasm")
        with open(wat_path, "w", encoding="utf-8") as out:
            out.write(wat_text)
        flags = [
            flag
            for flag in _EXTRA_FLAGS.get(name.replace(".wasm", ".wat"), [])
            if _flag_supported(flag)
        ]
        result = subprocess.run(
            ["wat2wasm"] + flags + [wat_path, "-o", wasm_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"{name}: emitted WAT failed to recompile:\n{result.stderr[:800]}"
        )
        recompiled = parse_wasm_bytes(open(wasm_path, "rb").read(), name)
        assert recompiled["errors"] == [], f"{name}: recompiled module has errors"

        original_sequences = [
            [(i["opcode"], tuple(i["immediates"])) for i in fn["instructions"]]
            for fn in report["functions"]
        ]
        recompiled_sequences = [
            [(i["opcode"], tuple(i["immediates"])) for i in fn["instructions"]]
            for fn in recompiled["functions"]
        ]
        assert original_sequences == recompiled_sequences, (
            f"{name}: instruction streams diverged across the round trip"
        )


def _fixture_names():
    names = [n for n in _RAW_FIXTURE_NAMES() if not n.startswith(("gc_",))]
    return names


@functools.cache
def _RAW_FIXTURE_NAMES():
    names = sorted(
        name for name in os.listdir(FIXTURES_DIR) if name.endswith(".wasm")
    )
    skip = {"f16x8_binary.wasm"}
    return [n for n in names if n not in skip]


@functools.cache
def _flag_supported(flag: str) -> bool:
    """Drop flags this wat2wasm no longer knows (newer releases enable
    memory64, SIMD and exceptions by default)."""
    if _WAT2WASM is None:
        return False
    probe = subprocess.run(
        [_WAT2WASM, flag, "--help"], capture_output=True, text=True
    )
    return "unknown option" not in probe.stderr


@pytest.mark.skipif(_WAT2WASM is None, reason="wat2wasm not installed")
@pytest.mark.parametrize("name", _RAW_FIXTURE_NAMES())
def test_roundtrip_fixture(name):
    if name.startswith("gc_"):
        # GC text needs the Rust wasm-tools front-end; emitted WAT for these
        # is exercised only when that binary is available.
        if shutil.which("wasm-tools") is None:
            pytest.skip("gc fixtures need the Rust wasm-tools to recompile")
        pytest.skip("GC emission covers struct/array types minimally; skipped")
    _roundtrip(name)


# ─── Golden files: wording changes become reviewable diffs ───────────────────


@pytest.mark.parametrize(
    "name", ["simple_add.wasm", "call_indirect.wasm", "exceptions_basic.wasm"]
)
def test_golden_emission(name):
    raw = open(os.path.join(FIXTURES_DIR, name), "rb").read()
    report = parse_wasm_bytes(raw, name)
    emitted = emit_wat(report, source=raw)
    golden_path = os.path.join(FIXTURES_DIR, "golden", name.replace(".wasm", ".wat"))
    golden = open(golden_path, encoding="utf-8").read()
    assert emitted == golden, (
        f"{name}: emitted WAT drifted from the golden file; regenerate with "
        f"`wasm-tools {name} --print-wat > tests/fixtures/golden/{name[:-5]}.wat` "
        "and review the diff"
    )
