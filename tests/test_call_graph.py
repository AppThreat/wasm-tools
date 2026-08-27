"""Tests for the static call graph, import xrefs, and export reachability."""

import sys
from pathlib import Path

import pytest

from wasm_tools.api import parse_wasm_file
from wasm_tools.cli import main as cli_main
from wasm_tools.graph import build_call_graph, sample_paths

_FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return str(_FIXTURES / name)


def test_call_graph_fixture_edges_and_reachability():
    report = parse_wasm_file(_fixture("call_graph.wasm"))
    graph = report["call_graph"]
    edges = {(e["from"], e["to"]): e["kind"] for e in graph["edges"]}

    # $run = func[2] (1 imported func), $helper = func[1], $log = func[0].
    assert edges[(2, 0)] == "direct"  # run -> env.log
    assert edges[(2, 1)] == "indirect-approx"  # run -> helper via elem table
    assert edges[(3, 0)] == "direct"  # dead -> env.log
    assert all({"direct", "indirect-approx"} >= {kind} for kind in edges.values())

    reach = graph["reachability"]
    assert reach["roots"] == [2]  # only "run" is exported
    assert reach["unreachable_functions"] == [3]  # $dead is never called


def test_call_graph_nodes_flag_imported_and_exported():
    report = parse_wasm_file(_fixture("call_graph.wasm"))
    nodes = {n["index"]: n for n in report["call_graph"]["nodes"]}
    assert nodes[0]["imported"] is True
    assert nodes[0]["name"] == "env.log"
    assert nodes[2]["exported"] is True
    assert nodes[2]["imported"] is False
    assert nodes[3]["exported"] is False


def test_import_xrefs_map_host_calls_to_callers():
    report = parse_wasm_file(_fixture("call_graph.wasm"))
    xrefs = report["call_graph"]["import_xrefs"]
    log_xref = next(x for x in xrefs if x["module"] == "env")
    assert log_xref["call_count"] == 2
    assert sorted(c["index"] for c in log_xref["callers"]) == [2, 3]


def test_direct_calls_in_complex_flow():
    report = parse_wasm_file(_fixture("complex_flow.wasm"))
    edges = report["call_graph"]["edges"]
    direct = [e for e in edges if e["kind"] == "direct"]
    assert direct, "expected at least one direct call edge"
    # Reachability profile lands in analysis for consumers.
    profile = report["analysis"]["profiles"]["control_flow"]
    assert "export_reachable_functions" in profile
    assert "unreachable_functions" in profile


def test_call_ref_produces_typed_approx_edges():
    report = parse_wasm_file(_fixture("call_refs.wasm"))
    kinds = {e["kind"] for e in report["call_graph"]["edges"]}
    assert "typed-approx" in kinds


def test_indirect_calls_in_call_indirect_fixture():
    report = parse_wasm_file(_fixture("call_indirect.wasm"))
    kinds = {e["kind"] for e in report["call_graph"]["edges"]}
    assert "indirect-approx" in kinds


# ─── sample paths ────────────────────────────────────────────────────────────


def test_sample_paths_walks_from_root():
    graph = {
        "_parents": {2: 1, 1: 0},
        "reachability": {"roots": [0]},
    }
    assert sample_paths(graph, [2]) == [[0, 1, 2]]


def test_sample_paths_root_target_returns_self():
    graph = {"_parents": {}, "reachability": {"roots": [5]}}
    assert sample_paths(graph, [5]) == [[5]]


# ─── unit-level graph build ──────────────────────────────────────────────────


def test_build_call_graph_type_resolution_and_caps():
    functions = [
        {
            "index": 1,
            "name": "one",
            "signature_index": 0,
            "instructions": [
                {"offset": 10, "opcode": "call", "immediates": [2]},
                {"offset": 12, "opcode": "call_ref", "immediates": [0]},
            ],
        },
        {"index": 2, "name": "two", "signature_index": 0, "instructions": []},
    ]
    imports = [{"index": 0, "module": "env", "name": "log", "kind": "func", "type_index": 0}]
    exports = [{"index": 0, "name": "run", "kind": "func", "ref_index": 1}]
    graph = build_call_graph(
        functions=functions,
        imports=imports,
        exports=exports,
        elements=[],
        start_function=None,
        max_edges=1,
    )
    kinds = [(e["from"], e["to"], e["kind"]) for e in graph["edges"]]
    # call 2 is direct; call_ref 0 resolves to funcs with sig 0 (import 0, func 1, func 2)
    assert kinds[0] == (1, 2, "direct")
    assert graph["truncated"] is True


# ─── CLI ─────────────────────────────────────────────────────────────────────


def test_cli_calls_tree(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", _fixture("call_graph.wasm"), "--calls", "run"]
    )
    cli_main()
    out = capsys.readouterr().out
    assert "Call tree for func[2] <run>" in out
    assert "env.log" in out
    assert "indirect-approx" in out


def test_cli_calls_by_index(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", _fixture("call_graph.wasm"), "--calls", "3"]
    )
    cli_main()
    out = capsys.readouterr().out
    assert "Call tree for func[3]" in out
    assert "direct" in out


def test_cli_calls_unknown_selector_fails(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["wasm-tools", _fixture("call_graph.wasm"), "--calls", "nope"]
    )
    with pytest.raises(SystemExit) as excinfo:
        cli_main()
    assert excinfo.value.code == 1
    assert "no function matches" in capsys.readouterr().err


# ─── regression: self-recursive edges must not be dropped ────────────────────


def test_indirect_self_recursion_edge_is_kept():
    # A function that dispatches through a table it sits in recurses; the
    # edge (0 -> 0) must appear rather than being suppressed.
    functions = [
        {
            "index": 0,
            "name": "loop",
            "signature_index": 0,
            "instructions": [
                {"offset": 1, "opcode": "call_indirect", "immediates": [0, 0]}
            ],
        }
    ]
    elements = [{"table_index": 0, "func_indices": [0]}]
    graph = build_call_graph(functions=functions, imports=[], exports=[], elements=elements)
    assert [(e["from"], e["to"], e["kind"]) for e in graph["edges"]] == [
        (0, 0, "indirect-approx")
    ]


def test_typed_self_recursion_edge_is_kept():
    functions = [
        {
            "index": 0,
            "name": "loop",
            "signature_index": 0,
            "instructions": [
                {"offset": 1, "opcode": "call_ref", "immediates": [0]}
            ],
        }
    ]
    graph = build_call_graph(functions=functions, imports=[], exports=[], elements=[])
    assert (0, 0, "typed-approx") in [
        (e["from"], e["to"], e["kind"]) for e in graph["edges"]
    ]


def test_self_recursion_counts_as_reachable():
    functions = [
        {
            "index": 0,
            "name": "loop",
            "signature_index": 0,
            "instructions": [
                {"offset": 1, "opcode": "call_indirect", "immediates": [0, 0]}
            ],
        }
    ]
    elements = [{"table_index": 0, "func_indices": [0]}]
    exports = [{"name": "run", "kind": "func", "ref_index": 0}]
    graph = build_call_graph(
        functions=functions, imports=[], exports=exports, elements=elements
    )
    assert graph["reachability"]["reachable_functions"] == [0]
