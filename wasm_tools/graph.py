"""Static call graph, import-boundary cross references, and export reachability.

WebAssembly indirect calls (``call_indirect`` through tables, ``call_ref``
through typed references) cannot be resolved exactly without execution, so
this module produces a conservative over-approximation and labels every edge
with its resolution kind:

- ``direct``: ``call`` / ``return_call`` with a function index immediate.
- ``indirect-approx``: ``call_indirect`` / ``return_call_indirect`` resolved
  through element segments that populate the referenced table.  This is a
  superset of the true call targets.
- ``typed-approx``: ``call_ref`` / ``return_call_ref`` resolved to every known
  function whose signature type matches the immediate type index.  Also a
  superset.

Consumers must not treat ``*-approx`` edges as ground truth.  This mirrors the
lesson from call-graph research for WebAssembly (ISSTA 2023).

Everything here is pure post-processing over decoded instruction streams; no
parser behavior is involved.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

DEFAULT_MAX_EDGES = 5000
_DEFAULT_MAX_XREF_CALLERS = 50

_DIRECT_CALLS = {"call", "return_call"}
_INDIRECT_CALLS = {"call_indirect", "return_call_indirect"}
_TYPED_CALLS = {"call_ref", "return_call_ref"}


def _imported_func_nodes(
    imports: Sequence[dict[str, Any]],
    function_names: Optional[Dict[int, str]],
) -> List[dict[str, Any]]:
    """Map func-kind imports to module-global function index space.

    Import records carry the import-section ordinal as ``index``; the function
    index of an imported function is its position among func imports, so it is
    recomputed here by walking the import list in order.
    """
    function_names = function_names or {}
    nodes: List[dict[str, Any]] = []
    func_index = 0
    for imp in imports:
        if str(imp.get("kind", "")) != "func":
            continue
        module = str(imp.get("module", ""))
        name = str(imp.get("name", ""))
        label = function_names.get(func_index) or (
            f"{module}.{name}" if module or name else f"func[{func_index}]"
        )
        nodes.append(
            {
                "index": func_index,
                "name": label,
                "imported": True,
                "exported": False,
                "module": module,
                "import_name": name,
            }
        )
        func_index += 1
    return nodes


def build_call_graph(
    functions: Sequence[dict[str, Any]],
    imports: Sequence[dict[str, Any]],
    exports: Sequence[dict[str, Any]],
    elements: Sequence[dict[str, Any]],
    function_names: Optional[Dict[int, str]] = None,
    start_function: Optional[int] = None,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> dict[str, Any]:
    """Build a labeled call graph over imported and locally-defined functions.

    ``functions`` is the report's decoded function list (locally-defined
    bodies with instruction streams).  ``imports``/``exports``/``elements``
    are the report's decoded section records.
    """
    function_names = function_names or {}

    # Export names are a fallback label when no name section exists.
    export_names: Dict[int, str] = {}
    for exp in exports:
        if str(exp.get("kind", "")) == "func" and isinstance(
            exp.get("ref_index"), int
        ):
            name = str(exp.get("name", ""))
            if name:
                export_names.setdefault(exp["ref_index"], name)

    imported_nodes = _imported_func_nodes(imports, function_names)
    local_nodes = [
        {
            "index": int(fn.get("index", -1)),
            "name": str(
                fn.get("name")
                or function_names.get(int(fn.get("index", -1)), "")
                or export_names.get(int(fn.get("index", -1)), "")
            ),
            "imported": False,
            "exported": False,
        }
        for fn in functions
        if isinstance(fn.get("index"), int)
    ]
    nodes = imported_nodes + local_nodes

    exported_func_indices: Set[int] = {
        int(exp.get("ref_index", -1))
        for exp in exports
        if str(exp.get("kind", "")) == "func" and isinstance(exp.get("ref_index"), int)
    }
    for node in nodes:
        if node["index"] in exported_func_indices:
            node["exported"] = True

    # sig-type -> func indices (for typed-approx call_ref resolution).
    funcs_by_type: Dict[int, List[int]] = {}
    imported_sig_by_index: Dict[int, Any] = {}
    func_index = 0
    for imp in imports:
        if str(imp.get("kind", "")) != "func":
            continue
        if isinstance(imp.get("type_index"), int):
            imported_sig_by_index[func_index] = imp["type_index"]
            funcs_by_type.setdefault(imp["type_index"], []).append(func_index)
        func_index += 1
    for fn in functions:
        sig = fn.get("signature_index")
        idx = fn.get("index")
        if isinstance(sig, int) and isinstance(idx, int):
            funcs_by_type.setdefault(sig, []).append(idx)

    # table index -> candidate func indices (for indirect-approx resolution).
    table_elems: Dict[int, Set[int]] = {}
    for elem in elements:
        table_idx = int(elem.get("table_index", 0) or 0)
        bucket = table_elems.setdefault(table_idx, set())
        for fi in elem.get("func_indices", []) or []:
            if isinstance(fi, int):
                bucket.add(fi)

    edges: List[dict[str, Any]] = []
    truncated = False
    import_callers: Dict[int, List[dict[str, Any]]] = {}

    def add_edge(src: int, dst: int, kind: str, offset: Any) -> bool:
        nonlocal truncated
        if len(edges) >= max_edges:
            truncated = True
            return False
        edges.append({"from": src, "to": dst, "kind": kind, "offset": offset})
        return True

    imported_indices = {node["index"] for node in imported_nodes}

    for fn in functions:
        src = fn.get("index")
        if not isinstance(src, int):
            continue
        for ins in fn.get("instructions", []):
            op = str(ins.get("opcode", ""))
            imm = ins.get("immediates", []) or []
            offset = ins.get("offset")
            if op in _DIRECT_CALLS and imm and isinstance(imm[0], int):
                dst = imm[0]
                if not add_edge(src, dst, "direct", offset):
                    break
                if dst in imported_indices:
                    callers = import_callers.setdefault(dst, [])
                    if len(callers) < _DEFAULT_MAX_XREF_CALLERS:
                        callers.append(
                            {"index": src, "name": fn.get("name", ""), "offset": offset}
                        )
            elif op in _INDIRECT_CALLS and len(imm) >= 2:
                table_idx = imm[1] if isinstance(imm[1], int) else 0
                # Self-edges are kept: a function calling itself through a
                # table is real (indirect) recursion.
                for dst in sorted(table_elems.get(table_idx, ())):
                    if not add_edge(src, dst, "indirect-approx", offset):
                        break
            elif op in _TYPED_CALLS and imm and isinstance(imm[0], int):
                for dst in funcs_by_type.get(imm[0], ()):
                    if not add_edge(src, dst, "typed-approx", offset):
                        break

    import_xrefs = []
    for node in imported_nodes:
        callers = import_callers.get(node["index"], [])
        import_xrefs.append(
            {
                "func": node["index"],
                "name": node["name"],
                "module": node.get("module", ""),
                "import_name": node.get("import_name", ""),
                "call_count": len(callers),
                "callers": callers,
            }
        )

    roots = sorted(
        {r for r in exported_func_indices if r >= 0}
        | ({start_function} if isinstance(start_function, int) and start_function >= 0 else set())
    )
    reachable, parents = _bfs(edges, roots)

    local_indices = [node["index"] for node in local_nodes]
    unreachable = sorted(
        idx for idx in local_indices if idx not in reachable
    )

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "truncated": truncated,
        "nodes": nodes,
        "edges": edges,
        "import_xrefs": import_xrefs,
        "reachability": {
            "roots": roots,
            "reachable_functions": sorted(r for r in reachable if r >= 0),
            "reachable_count": len(reachable),
            "unreachable_functions": unreachable,
            "unreachable_count": len(unreachable),
        },
        "_parents": parents,  # internal; stripped before serialization
    }


def _bfs(
    edges: Sequence[dict[str, Any]], roots: Sequence[int]
) -> Tuple[Set[int], Dict[int, int]]:
    adjacency: Dict[int, List[int]] = {}
    for edge in edges:
        adjacency.setdefault(edge["from"], []).append(edge["to"])
    parents: Dict[int, int] = {}
    seen: Set[int] = set(roots)
    queue = deque(roots)
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                parents[nxt] = node
                queue.append(nxt)
    return seen, parents


def sample_paths(
    graph: dict[str, Any],
    targets: Sequence[int],
    max_len: int = 5,
    max_paths: int = 3,
) -> List[List[int]]:
    """Return short example paths from a reachability root to each target."""
    parents: Dict[int, int] = graph.get("_parents", {})
    roots = set(graph.get("reachability", {}).get("roots", []))
    out: List[List[int]] = []
    for target in targets:
        if target not in parents:
            if target in roots:
                out.append([target])
            continue
        path = [target]
        node = target
        while node in parents and len(path) <= max_len:
            node = parents[node]
            path.append(node)
        if node in roots or node not in parents:
            path.reverse()
            out.append(path)
        if len(out) >= max_paths:
            break
    return out


def merge_component_graphs(
    module_reports: Sequence[dict[str, Any]],
    canon_wiring: Sequence[dict[str, Any]],
    max_edges: int = DEFAULT_MAX_EDGES,
) -> dict[str, Any]:
    """Merge per-core-module call graphs into a module-scoped component graph.

    Flattened function indices collide across core modules (module 0 and
    module 1 both have a function index 0), so every node carries
    ``module_id`` and every edge carries ``from_module``/``to_module``; the
    node identity consumers should key on is ``(module_id, index)``.
    ``canon_wiring`` entries describe canon lift/lower records already
    decoded from the component canon section:
    ``{"module": int, "func": int, "type_index": int, "direction":
    "lift"|"lower"}``. Each record becomes a ``canon`` edge between the core
    function and a synthetic ``component:type<N>`` node: provable from the
    canon section itself, though the interface NAME behind ``type_index``
    needs instance and alias section decoding (a documented follow-up), so
    cross-module interface wiring is intentionally absent rather than
    guessed.

    Each module keeps its own ``reachability`` block, keyed by module id, so
    per-module dead-code analysis stays exact; the component-level summary
    counts nodes, edges, and canon edges.
    """
    nodes: List[dict[str, Any]] = []
    edges: List[dict[str, Any]] = []
    import_xrefs: List[dict[str, Any]] = []
    reachability: Dict[str, Any] = {}
    edge_count = 0
    truncated = False

    for module_id, report in enumerate(module_reports):
        graph = report.get("call_graph") or {}
        for node in graph.get("nodes", []):
            entry = dict(node)
            entry["module_id"] = module_id
            nodes.append(entry)
        for edge in graph.get("edges", []):
            entry = dict(edge)
            entry["from_module"] = module_id
            entry["to_module"] = module_id
            edges.append(entry)
            edge_count += 1
        for xref in graph.get("import_xrefs", []):
            entry = dict(xref)
            entry["module_id"] = module_id
            import_xrefs.append(entry)
        reach = graph.get("reachability") or {}
        if reach:
            reachability[str(module_id)] = reach
        truncated = truncated or bool(graph.get("truncated"))
        edge_count = min(edge_count, max_edges)

    # Canon wiring: synthetic interface nodes per distinct type index.
    canon_type_nodes: Dict[int, int] = {}
    for record in canon_wiring:
        type_index = int(record.get("type_index", -1))
        if type_index not in canon_type_nodes:
            synthetic_index = 10_000_000 + type_index
            canon_type_nodes[type_index] = synthetic_index
            nodes.append(
                {
                    "index": synthetic_index,
                    "name": f"component:type{type_index}",
                    "imported": True,
                    "exported": False,
                    "module_id": None,
                    "synthetic": True,
                }
            )
        target = canon_type_nodes[type_index]
        direction = str(record.get("direction", "lift"))
        module_id = record.get("module")
        if direction == "lift":
            edges.append(
                {
                    "from": record.get("func"),
                    "from_module": module_id,
                    "to": target,
                    "to_module": None,
                    "kind": "canon",
                    "offset": None,
                    "type_index": type_index,
                }
            )
        else:
            edges.append(
                {
                    "from": target,
                    "from_module": None,
                    "to": record.get("func"),
                    "to_module": module_id,
                    "kind": "canon",
                    "offset": None,
                    "type_index": type_index,
                }
            )
            edge_count += 1

    canon_edge_count = sum(1 for e in edges if e.get("kind") == "canon")
    return {
        "node_count": len(nodes),
        "edge_count": edge_count + canon_edge_count,
        "truncated": truncated,
        "nodes": nodes,
        "edges": edges,
        "import_xrefs": import_xrefs,
        "reachability": {
            "per_module": reachability,
            "roots": [],
            "reachable_functions": sum(
                r.get("reachable_count", 0) for r in reachability.values()
            ),
            "unreachable_functions": sum(
                r.get("unreachable_count", 0) for r in reachability.values()
            ),
        },
        "component_summary": {
            "module_count": len(module_reports),
            "canon_edge_count": canon_edge_count,
            "canon_type_nodes": len(canon_type_nodes),
        },
    }
