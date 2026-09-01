"""Regression tests over the vendored real-toolchain corpus.

The files under tests/fixtures/corpus/ are real binaries produced by clang and
rustc-era toolchains (see corpus/README.md for provenance). They guard the
opcode table and toolchain extraction against real-toolchain drift: a new
opcode or producers spelling that this decoder mishandles shows up here as an
unknown opcode, a parse error, or a changed risk profile before it ships.

Risk pins are drift guards, not judgments: the corpus is known-benign open
source code, and the pins record what the current rule set scores it at.
"""

from pathlib import Path

import pytest

from wasm_tools.api import parse_wasm_file

_CORPUS = Path(__file__).parent / "fixtures" / "corpus"

pytestmark = pytest.mark.skipif(
    not _CORPUS.exists(), reason="corpus directory not vendored"
)


def _report(name: str) -> dict:
    return parse_wasm_file(str(_CORPUS / name))


def _corpus_files() -> list[str]:
    return sorted(p.name for p in _CORPUS.glob("*.wasm"))


def test_corpus_is_vendored():
    assert set(_corpus_files()) == {
        "bz2.wasm",
        "erc1155.wasm",
        "erc20.wasm",
        "erc721.wasm",
    }


@pytest.mark.parametrize("name", _corpus_files())
def test_corpus_file_decodes_without_errors(name):
    report = _report(name)

    assert report["errors"] == []
    summary = report["analysis"]["summary"]
    assert summary["unknown_opcode_count"] == 0
    assert summary["unknown_opcodes"] == []
    assert report["function_count"] > 0
    assert report["analysis"]["detections"]["format"]["kind"] == "core"
    # the call graph builds over real instruction streams
    assert report["call_graph"]["node_count"] > 0


@pytest.mark.parametrize(
    "name,tier,finding_ids",
    [
        ("bz2.wasm", "medium", ["WASM-LOOP-004"]),
        ("erc20.wasm", "low", []),
        ("erc721.wasm", "low", []),
        ("erc1155.wasm", "low", []),
    ],
)
def test_corpus_risk_pins(name, tier, finding_ids):
    # Known-benign corpus must stay out of the high tier under the current
    # rules. bz2 previously scored 71/high from a DOS-003 false positive.
    #
    # The pins are the tier and the finding id list, not the exact score: a
    # new rule with a nonzero weight legitimately moves every score, and
    # asserting integers turns that into four unrelated failures. Tier plus
    # ids still catches the drift that matters (a benign binary starting to
    # fire a rule, or climbing into the high tier).
    report = _report(name)
    analysis = report["analysis"]
    assert [f["id"] for f in analysis["findings"]] == finding_ids
    assert analysis["summary"]["risk_tier"] == tier
    assert analysis["summary"]["risk_score"] < 70


def test_corpus_bz2_toolchain_extraction():
    report = _report("bz2.wasm")

    toolchain = report["toolchain"]
    assert toolchain["languages"] == ["C99"]
    assert any(
        entry["name"] == "clang" and entry["version"].startswith("11.0.0")
        for entry in toolchain["processed_by"]
    )


def test_corpus_bz2_dwarf_awareness():
    report = _report("bz2.wasm")

    # clang 11 emits DWARF custom sections; the unstripped build is surfaced
    # as a format signal and its .debug_str payload feeds string extraction.
    signals = report["analysis"]["detections"]["format"]["signals"]
    assert "debug_info_present" in signals
    section_names = {s["name"] for s in report["sections"]}
    assert ".debug_str" in section_names
    debug_hits = [s for s in report["strings"] if s.get("source") == "custom:.debug_str"]
    assert debug_hits, "expected .debug_str strings with custom provenance"
    assert all(s["segment_index"] is None for s in debug_hits)
