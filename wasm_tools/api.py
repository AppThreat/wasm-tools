"""Library-first JSON-friendly API for WebAssembly parsing results."""

from __future__ import annotations

import json
from typing import Any, Optional

from .component import (
    detect_component,
    parse_component_bytes,
    wasi_variants_from_interfaces,
)
from .graph import build_call_graph, sample_paths
from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState, SECTION_NAMES
from .parser import BinaryReader
from .strings import DEFAULT_MAX_STRINGS, analyze_strings, extract_strings
from .visitor import BinaryReaderNop, BinaryReaderObjdumpPrepass


_HIGH_RISK_FINDING_WEIGHTS = {
    "WASM-CAP-001": 30,
    "WASM-CFG-002": 25,
    "WASM-DOS-003": 30,
    "WASM-LOOP-004": 15,
    "WASM-FMT-005": 10,
    "WASM-JSCFG-006": 20,
    "WASM-STR-007": 20,
}


def _tier_from_score(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


class _BinaryReaderJsonCollector(BinaryReaderNop):
    """Collect parser callbacks into a structured report dictionary."""

    def __init__(self, filename: str, state: ObjdumpState) -> None:
        """Initialize per-module collection state."""
        self.filename = filename
        self.objdump_state = state
        self.module_version: int | None = None
        self.offset = 0
        self.current_opcode: Any | None = None
        self.errors: list[str] = []
        self.sections: list[dict[str, Any]] = []
        self._functions: dict[int, dict[str, Any]] = {}
        self._current_function: dict[str, Any] | None = None
        self._pending_instruction: dict[str, Any] | None = None

    def begin_module(self, version: int) -> None:
        """Capture the module version from the binary header."""
        self.module_version = version

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        """Record section metadata and byte offsets."""
        self.sections.append(
            {
                "index": section_index,
                "id": section_code,
                "name": SECTION_NAMES.get(section_code, "Unknown"),
                "size": size,
                "offset": self.offset,
            }
        )

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        """Attach custom section names to the last-recorded section."""
        if self.sections:
            self.sections[-1]["name"] = section_name

    def begin_function_body(self, index: int, size: int) -> None:
        """Start collecting instructions for a function body."""
        self._current_function = {
            "index": index,
            "name": self.objdump_state.function_names.get(index, ""),
            "signature_index": self.objdump_state.function_types.get(index),
            "offset": self.offset,
            "body_size": size,
            "instructions": [],
        }
        self._functions[index] = self._current_function

    def end_function_body(self, index: int) -> None:
        """Close function collection and flush unfinished instruction records."""
        if self._pending_instruction and self._current_function:
            self._pending_instruction["decode_incomplete"] = True
            self._current_function["instructions"].append(self._pending_instruction)
            self._pending_instruction = None
        self._current_function = None

    def on_opcode(self, opcode: Any) -> None:
        """Create a pending instruction that later callbacks will complete."""
        self.current_opcode = opcode
        self._pending_instruction = {
            "offset": self.offset,
            "opcode": getattr(opcode, "name", "unknown"),
            "immediates": [],
        }

    def on_opcode_bare(self) -> None:
        """Finalize an opcode that has no immediate operands."""
        self._finalize_instruction()

    def on_end_expr(self) -> None:
        """Finalize an `end` opcode that closes an expression."""
        self._finalize_instruction()

    def on_opcode_block_sig(self, sig: int) -> None:
        """Finalize block-like opcodes with signature immediates."""
        self._append_immediates(sig)

    def on_opcode_index(self, idx: int) -> None:
        """Finalize index-based opcodes."""
        self._append_immediates(idx)

    def on_opcode_uint32(self, val: int) -> None:
        """Finalize opcodes with one 32-bit integer immediate."""
        self._append_immediates(val)

    def on_opcode_uint64(self, val: int) -> None:
        """Finalize opcodes with one 64-bit integer immediate."""
        self._append_immediates(val)

    def on_opcode_f32(self, val: float) -> None:
        """Finalize opcodes with one 32-bit float immediate."""
        self._append_immediates(val)

    def on_opcode_f64(self, val: float) -> None:
        """Finalize opcodes with one 64-bit float immediate."""
        self._append_immediates(val)

    def on_opcode_uint32_uint32(self, v1: int, v2: int) -> None:
        """Finalize opcodes with two integer immediates."""
        self._append_immediates(v1, v2)

    def on_call_indirect_expr(self, sig: int, tab: int) -> None:
        """Finalize call_indirect with signature and table indices."""
        self._append_immediates(sig, tab)

    def on_error(self, message: str) -> None:
        """Capture parser errors for programmatic callers."""
        self.errors.append(message)

    def on_opcode_lane_idx(self, lane: int) -> None:
        """Finalize lane-index SIMD opcodes."""
        self._append_immediates(lane)

    def on_opcode_memarg_lane(self, align: int, mem_offset: int, lane: int) -> None:
        """Finalize SIMD memory lane opcodes with align, offset, and lane immediates."""
        self._append_immediates(align, mem_offset, lane)

    def _append_immediates(self, *values: Any) -> None:
        """Append immediate values and finalize the current instruction."""
        if self._pending_instruction is None:
            return
        self._pending_instruction["immediates"].extend(values)
        self._finalize_instruction()

    def _finalize_instruction(self) -> None:
        """Add the pending instruction to the active function."""
        if self._pending_instruction and self._current_function:
            self._current_function["instructions"].append(self._pending_instruction)
        self._pending_instruction = None

    def build_report(
        self,
        strings_min_len: int = 5,
        include_strings: bool = True,
        include_call_graph: bool = True,
    ) -> dict[str, Any]:
        """Build the final JSON-ready report for this module.

        ``strings_min_len`` controls extraction (the CLI flag must reach this
        call or short strings can never surface); ``include_strings`` and
        ``include_call_graph`` let consumers opt out of the heavier derived
        blocks.
        """
        functions = [self._functions[idx] for idx in sorted(self._functions)]
        for fn in functions:
            fn["instruction_count"] = len(fn["instructions"])

        state = self.objdump_state

        types = [
            {"index": i, "params": list(t.params), "results": list(t.results)}
            for i, t in enumerate(state.types)
            if t is not None
        ]

        imports = []
        for imp in state.imports:
            if imp is None:
                continue
            rec: dict[str, Any] = {
                "index": imp.index,
                "module": imp.module,
                "name": imp.name,
                "kind": imp.kind,
            }
            if imp.kind == "func":
                rec["type_index"] = imp.type_index
            elif imp.kind == "table":
                rec["ref_type"] = imp.table_ref_type
                if imp.table_limits:
                    rec["limits"] = self._limits_dict(imp.table_limits)
            elif imp.kind == "memory":
                if imp.mem_limits:
                    rec["limits"] = self._limits_dict(imp.mem_limits)
            elif imp.kind == "global":
                rec["valtype"] = imp.global_valtype
                rec["mutable"] = imp.global_mutable
            elif imp.kind == "tag":
                rec["type_index"] = imp.tag_type_index
            imports.append(rec)

        exports = [
            {
                "index": exp.index,
                "name": exp.name,
                "kind": exp.kind,
                "ref_index": exp.ref_index,
            }
            for exp in state.exports
            if exp is not None
        ]

        globals_ = [
            {
                "index": g.index,
                "valtype": g.valtype,
                "mutable": g.mutable,
                "init": g.init_expr,
            }
            for g in state.globals
            if g is not None
        ]

        tables = [
            {
                "index": t.index,
                "ref_type": t.ref_type,
                "limits": self._limits_dict(t.limits),
            }
            for t in state.tables
            if t is not None
        ]

        memories = [
            {
                "index": m.index,
                "limits": self._limits_dict(m.limits),
            }
            for m in state.memories
            if m is not None
        ]

        data_segments = [
            {
                "index": d.index,
                "mode": d.mode,
                "memory_index": d.memory_index,
                "offset": d.offset_expr,
                "offset_value": d.offset_value,
                "size": d.size,
            }
            for d in state.data_segments
            if d is not None
        ]

        elements = [
            {
                "index": e.index,
                "mode": e.mode,
                "ref_type": e.ref_type,
                "table_index": e.table_index,
                "offset": e.offset_expr,
                "count": e.count,
                "func_indices": list(e.func_indices),
            }
            for e in state.elements
            if e is not None
        ]

        tags = [
            {"index": tg.index, "type_index": tg.type_index}
            for tg in state.tags
            if tg is not None
        ]

        segments = [
            (d.index, d.offset_value, d.data)
            for d in state.data_segments
            if d is not None
        ]
        if include_strings:
            strings, strings_truncated = extract_strings(
                segments, min_len=strings_min_len
            )
            strings_detection = analyze_strings(strings)
        else:
            strings, strings_truncated = [], False
            strings_detection = {
                "detected": False,
                "signals": [],
                "counts": {},
                "samples": {},
                "string_count": 0,
            }
        toolchain = self._build_toolchain()
        call_graph = None
        if include_call_graph:
            call_graph = build_call_graph(
                functions=functions,
                imports=imports,
                exports=exports,
                elements=elements,
                function_names=state.function_names,
                start_function=state.start_function,
            )

        analysis = self._build_analysis(
            functions=functions,
            types=types,
            imports=imports,
            exports=exports,
            data_segments=data_segments,
            sections=self.sections,
            module_version=self.module_version,
            start_function=state.start_function,
            errors=self.errors,
            strings_detection=strings_detection,
            call_graph=call_graph,
        )

        return {
            "file": self.filename,
            "module_version": self.module_version,
            "is_component": False,
            "section_count": len(self.sections),
            "sections": self.sections,
            "function_count": len(functions),
            "functions": functions,
            "types": types,
            "imports": imports,
            "exports": exports,
            "globals": globals_,
            "tables": tables,
            "memories": memories,
            "data_segments": data_segments,
            "elements": elements,
            "tags": tags,
            "strings": strings,
            "strings_truncated": strings_truncated,
            "call_graph": {
                k: v for k, v in call_graph.items() if not k.startswith("_")
            }
            if call_graph is not None
            else {},
            "toolchain": toolchain,
            "start_function": state.start_function,
            "analysis": analysis,
            "errors": self.errors,
        }

    @staticmethod
    def _limits_dict(limits: Any) -> dict[str, Any]:
        return {
            "min": limits.minimum,
            "max": limits.maximum,
            "is_64": limits.is_64,
            "shared": limits.shared,
            "page_size_log2": limits.page_size_log2,
        }

    def _build_toolchain(self) -> dict[str, Any]:
        """Build the toolchain fingerprint block from custom sections."""
        producers = self.objdump_state.producers
        target_features = self.objdump_state.target_features
        return {
            "languages": [n for n, _ in producers.get("language", [])],
            "processed_by": [
                {"name": n, "version": v} for n, v in producers.get("processed-by", [])
            ],
            "sdks": [
                {"name": n, "version": v} for n, v in producers.get("sdk", [])
            ],
            "target_features": [
                {"enabled": enabled, "name": name} for enabled, name in target_features
            ],
        }

    def _build_analysis(
        self,
        functions: list[dict[str, Any]],
        types: list[dict[str, Any]],
        imports: list[dict[str, Any]],
        exports: list[dict[str, Any]],
        data_segments: list[dict[str, Any]],
        sections: list[dict[str, Any]],
        module_version: int | None,
        start_function: int | None,
        errors: list[str],
        strings_detection: dict[str, Any] | None = None,
        call_graph: dict[str, Any] | None = None,
        component_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        op_counts: dict[str, int] = {}
        loop_max_depth = 0
        loop_memory_ops = 0
        loop_branch_ops = 0
        indirect_call_ops = 0
        table_mutation_ops = 0
        callsite_conversion_ops = 0
        call_ref_unguarded_ops = 0
        memory_grow_ops = 0
        bulk_memory_ops = 0
        memory_access_ops = 0
        unknown_opcode_count = 0
        unknown_opcodes: set[str] = set()
        dynamic_funcs: set[int] = set()
        table_mutation_funcs: set[int] = set()
        loop_memory_funcs: set[int] = set()
        js_calling_funcs: set[int] = set()

        block_openers = {"block", "loop", "if", "try_table"}
        table_mutators = {
            "table.set",
            "table.grow",
            "table.fill",
            "table.copy",
            "table.init",
            "elem.drop",
        }
        bulk_memory = {"memory.init", "memory.copy", "memory.fill", "data.drop"}
        call_ops = {
            "call",
            "return_call",
            "call_indirect",
            "return_call_indirect",
            "call_ref",
            "return_call_ref",
        }
        call_ref_ops = {"call_ref", "return_call_ref"}
        js_import_indices = {
            int(imp.get("index", -1))
            for imp in imports
            if str(imp.get("kind", "")) == "func" and self._is_js_related_import(imp)
        }

        for fn in functions:
            active_loops = 0
            block_stack: list[str] = []
            instructions = fn.get("instructions", [])
            for ins_idx, ins in enumerate(instructions):
                op = ins.get("opcode", "")
                op_counts[op] = op_counts.get(op, 0) + 1

                if op.startswith("unknown_"):
                    unknown_opcode_count += 1
                    unknown_opcodes.add(op)

                if op in block_openers:
                    block_stack.append(op)
                    if op == "loop":
                        active_loops += 1
                        loop_max_depth = max(loop_max_depth, active_loops)
                elif op == "end" and block_stack:
                    if block_stack.pop() == "loop":
                        active_loops = max(0, active_loops - 1)

                is_memory_access = (
                    op.startswith("i32.load")
                    or op.startswith("i64.load")
                    or op.startswith("f32.load")
                    or op.startswith("f64.load")
                    or op.startswith("v128.load")
                    or op.startswith("i32.store")
                    or op.startswith("i64.store")
                    or op.startswith("f32.store")
                    or op.startswith("f64.store")
                    or op.startswith("v128.store")
                    or op.startswith("memory.")
                )
                if is_memory_access:
                    memory_access_ops += 1
                    if active_loops > 0:
                        loop_memory_ops += 1
                        loop_memory_funcs.add(fn.get("index", -1))

                if op in {"br", "br_if", "br_table"} and active_loops > 0:
                    loop_branch_ops += 1

                if op == "memory.grow":
                    memory_grow_ops += 1

                if op in bulk_memory:
                    bulk_memory_ops += 1

                if op in {
                    "call_indirect",
                    "return_call_indirect",
                    "call_ref",
                    "return_call_ref",
                }:
                    indirect_call_ops += 1
                    dynamic_funcs.add(fn.get("index", -1))

                if op in call_ops:
                    nearby = instructions[max(0, ins_idx - 3) : ins_idx]
                    callsite_conversion_ops += sum(
                        1
                        for nearby_ins in nearby
                        if self._is_conversion_opcode(str(nearby_ins.get("opcode", "")))
                    )

                if op in call_ref_ops:
                    nearby = instructions[max(0, ins_idx - 3) : ins_idx]
                    if not any(
                        self._is_call_ref_guard_opcode(
                            str(nearby_ins.get("opcode", ""))
                        )
                        for nearby_ins in nearby
                    ):
                        call_ref_unguarded_ops += 1

                if op in {"call", "return_call"} and ins.get("immediates"):
                    target = ins["immediates"][0]
                    if isinstance(target, int) and target in js_import_indices:
                        js_calling_funcs.add(fn.get("index", -1))

                if op in table_mutators:
                    table_mutation_ops += 1
                    table_mutation_funcs.add(fn.get("index", -1))

        capabilities = sorted(self._capabilities_from_imports(imports))
        wasi_detection = self._wasi_signals_from_imports(imports, component_info)
        js_interface_detection = self._js_interface_signals(
            imports=imports,
            exports=exports,
            types=types,
            functions=functions,
            start_function=start_function,
        )
        format_detection = self._format_signals(
            module_version=module_version,
            sections=sections,
            errors=errors,
            component_info=component_info,
        )
        exported_func_indices = {
            int(exp.get("ref_index", -1))
            for exp in exports
            if str(exp.get("kind", "")) == "func"
        }
        js_exposed_function_indices = set(js_calling_funcs)
        js_exposed_function_indices.update(i for i in exported_func_indices if i >= 0)
        if isinstance(start_function, int) and start_function >= 0:
            js_exposed_function_indices.add(start_function)
        js_dynamic_funcs = dynamic_funcs.intersection(js_exposed_function_indices)
        js_table_mutation_funcs = table_mutation_funcs.intersection(
            js_exposed_function_indices
        )
        paths_from_export: list[list[int]] = []
        if call_graph and js_dynamic_funcs:
            paths_from_export = sample_paths(
                call_graph, sorted(i for i in js_dynamic_funcs if i >= 0)
            )
        findings = self._build_findings(
            capabilities=capabilities,
            memory_grow_ops=memory_grow_ops,
            bulk_memory_ops=bulk_memory_ops,
            memory_access_ops=memory_access_ops,
            loop_max_depth=loop_max_depth,
            loop_memory_ops=loop_memory_ops,
            loop_branch_ops=loop_branch_ops,
            indirect_call_ops=indirect_call_ops,
            table_mutation_ops=table_mutation_ops,
            dynamic_funcs=dynamic_funcs,
            table_mutation_funcs=table_mutation_funcs,
            loop_memory_funcs=loop_memory_funcs,
            format_detection=format_detection,
            js_interface_detection=js_interface_detection,
            js_exposed_dynamic_funcs=js_dynamic_funcs,
            js_exposed_table_mutation_funcs=js_table_mutation_funcs,
            strings_detection=strings_detection,
            paths_from_export=paths_from_export,
        )

        cap_risk = {
            "fs.path": 10,
            "fs.io": 8,
            "network": 12,
            "process.terminate": 8,
            "crypto.random": 2,
            "clock.high_res": 4,
            "host.logging": 2,
            "host.memory": 3,
            "host.table": 3,
            "host.global": 2,
            "host.tag": 2,
            "js.host": 6,
        }
        capability_score = sum(cap_risk.get(cap, 0) for cap in capabilities)
        findings_score = sum(
            _HIGH_RISK_FINDING_WEIGHTS.get(f["id"], 5) for f in findings
        )
        risk_score = min(100, capability_score + findings_score)

        control_flow_profile: dict[str, Any] = {
            "indirect_call_ops": indirect_call_ops,
            "table_mutation_ops": table_mutation_ops,
            "callsite_conversion_ops": callsite_conversion_ops,
            "call_ref_unguarded_ops": call_ref_unguarded_ops,
        }
        if call_graph is not None:
            reachability = call_graph.get("reachability", {})
            control_flow_profile["export_reachable_functions"] = reachability.get(
                "reachable_count", 0
            )
            control_flow_profile["unreachable_functions"] = reachability.get(
                "unreachable_count", 0
            )

        detections: dict[str, Any] = {
            "wasi": wasi_detection,
            "js_interface": js_interface_detection,
            "format": format_detection,
        }
        if strings_detection is not None:
            detections["strings"] = strings_detection

        return {
            "summary": {
                "risk_score": risk_score,
                "risk_tier": _tier_from_score(risk_score),
                "finding_count": len(findings),
                "unknown_opcode_count": unknown_opcode_count,
                "unknown_opcodes": sorted(unknown_opcodes),
            },
            "detections": detections,
            "capabilities": capabilities,
            "profiles": {
                "memory": {
                    "memory_access_ops": memory_access_ops,
                    "memory_grow_ops": memory_grow_ops,
                    "bulk_memory_ops": bulk_memory_ops,
                    "data_segment_total_bytes": sum(
                        ds.get("size", 0) for ds in data_segments
                    ),
                },
                "control_flow": control_flow_profile,
                "compute": {
                    "max_loop_depth": loop_max_depth,
                    "loop_memory_ops": loop_memory_ops,
                    "loop_branch_ops": loop_branch_ops,
                },
            },
            "findings": findings,
        }

    def _wasi_signals_from_imports(
        self,
        imports: list[dict[str, Any]],
        component_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        wasi_modules = [
            str(imp.get("module", ""))
            for imp in imports
            if str(imp.get("module", "")).startswith("wasi")
        ]
        modules = sorted(set(wasi_modules))
        import_count = len(wasi_modules)

        variants: list[str] = []
        if "wasi_snapshot_preview1" in modules:
            variants.append("preview1")
        for module in modules:
            if not module.startswith("wasi:"):
                continue
            # Preview 2/3 declare versioned kebab-case interfaces such as
            # "wasi:cli/run@0.2.0"; the version decides the variant.
            if "@" in module:
                version = module.rsplit("@", 1)[1]
                if version.startswith("0.3"):
                    if "preview3" not in variants:
                        variants.append("preview3")
                    continue
            if "preview2" not in variants:
                variants.append("preview2")
        if any(module == "wasi_unstable" for module in modules):
            variants.append("legacy")
        if component_info:
            for variant in wasi_variants_from_interfaces(
                component_info.get("interfaces", [])
            ):
                if variant not in variants:
                    variants.append(variant)

        # Component interface imports already flow in as import records;
        # only interface names not seen there (e.g. export-only interfaces)
        # are added as extra modules.
        if component_info:
            extra = [
                iface
                for iface in component_info.get("interfaces", [])
                if iface.startswith("wasi:") and iface not in modules
            ]
            modules = sorted(set(modules) | set(extra))
            import_count += len(extra)

        confidence = "high" if modules else "none"
        return {
            "detected": bool(modules),
            "confidence": confidence,
            "import_modules": modules,
            "import_count": import_count,
            "variants": variants,
        }

    def _js_interface_signals(
        self,
        imports: list[dict[str, Any]],
        exports: list[dict[str, Any]],
        types: list[dict[str, Any]],
        functions: list[dict[str, Any]],
        start_function: int | None,
    ) -> dict[str, Any]:
        """Classify JavaScript-interface import/export signals from decoded descriptors."""
        signals: set[str] = set()
        js_imports: list[dict[str, str]] = []
        js_exports: list[dict[str, str]] = []
        # `wasm:*` namespaces are reserved for JS-API builtin-set wiring.
        builtin_sets = sorted(
            {
                str(imp.get("module", ""))[5:]
                for imp in imports
                if str(imp.get("module", "")).startswith("wasm:")
            }
        )

        for imp in imports:
            module = str(imp.get("module", ""))
            name = str(imp.get("name", ""))
            kind = str(imp.get("kind", ""))
            is_js_related = self._is_js_related_import(imp)

            if module in {"js", "wbg"}:
                signals.add("js_namespace_import")
            if module.startswith("wasm:"):
                signals.add("wasm_builtin_namespace_import")
            if module == "env" and any(
                token in name
                for token in (
                    "log",
                    "print",
                    "console",
                    "emscripten",
                    "invoke_",
                    "abort",
                )
            ):
                signals.add("env_glue_import")
            if name.startswith("__wbindgen") or name.startswith("__wbg_"):
                signals.add("wbindgen_pattern")
            if "emscripten" in name or name.startswith("invoke_"):
                signals.add("emscripten_pattern")

            if is_js_related:
                js_imports.append({"module": module, "name": name, "kind": kind})

        type_map = {
            int(t.get("index", -1)): t for t in types if isinstance(t.get("index"), int)
        }
        function_map = {
            int(fn.get("index", -1)): fn
            for fn in functions
            if isinstance(fn.get("index"), int)
        }
        import_type_map = {
            int(imp.get("index", -1)): imp.get("type_index")
            for imp in imports
            if str(imp.get("kind", "")) == "func" and isinstance(imp.get("index"), int)
        }

        signature_entries: list[dict[str, Any]] = []
        risky_import_signatures: list[dict[str, Any]] = []

        for imp in imports:
            if str(imp.get("kind", "")) != "func" or not self._is_js_related_import(
                imp
            ):
                continue
            sig = self._type_for_index(type_map, imp.get("type_index"))
            entry = {
                "source": "import",
                "module": str(imp.get("module", "")),
                "name": str(imp.get("name", "")),
                "type_index": imp.get("type_index"),
                "params": sig["params"],
                "results": sig["results"],
            }
            signature_entries.append(entry)
            reasons = self._signature_risk_reasons(sig["params"], sig["results"])
            if reasons:
                risky_import_signatures.append(
                    {
                        "module": entry["module"],
                        "name": entry["name"],
                        "type_index": entry["type_index"],
                        "params": entry["params"],
                        "results": entry["results"],
                        "reasons": reasons,
                    }
                )

        for exp in exports:
            name = str(exp.get("name", ""))
            kind = str(exp.get("kind", ""))
            is_js_related = False
            if name.startswith("__wbindgen") or name.startswith("__wbg_"):
                signals.add("wbindgen_pattern")
                is_js_related = True
            if "emscripten" in name:
                signals.add("emscripten_pattern")
                is_js_related = True
            if is_js_related:
                js_exports.append({"name": name, "kind": kind})

            if kind == "func":
                ref_index = exp.get("ref_index")
                type_index = import_type_map.get(ref_index)
                if type_index is None and isinstance(ref_index, int):
                    type_index = function_map.get(ref_index, {}).get("signature_index")
                sig = self._type_for_index(type_map, type_index)
                signature_entries.append(
                    {
                        "source": "export",
                        "name": name,
                        "index": ref_index,
                        "type_index": type_index,
                        "params": sig["params"],
                        "results": sig["results"],
                    }
                )

        has_externref = any(
            "externref" in (entry.get("params", []) + entry.get("results", []))
            for entry in signature_entries
        )
        has_i64 = any(
            "i64" in (entry.get("params", []) + entry.get("results", []))
            for entry in signature_entries
        )
        boundary_risks: set[str] = set()
        if has_externref and has_i64:
            boundary_risks.add("externref_i64_mix")
        if any(len(entry.get("results", [])) > 1 for entry in signature_entries):
            boundary_risks.add("multi_result_boundary")
        if any(
            self._has_ref_and_numeric_mix(
                entry.get("params", []),
                entry.get("results", []),
            )
            for entry in signature_entries
        ):
            boundary_risks.add("ref_numeric_mix")

        entry_trampolines = self._entry_trampoline_signals(
            exports=exports,
            start_function=start_function,
            functions=function_map,
        )

        # Confidence is tied to explicit namespace signals before name heuristics.
        if {"js_namespace_import", "wasm_builtin_namespace_import"}.intersection(
            signals
        ):
            confidence = "high"
        elif signals:
            confidence = "medium"
        else:
            confidence = "none"

        return {
            "detected": bool(signals),
            "confidence": confidence,
            "signals": sorted(signals),
            "import_modules": sorted({item["module"] for item in js_imports}),
            "import_count": len(js_imports),
            "export_count": len(js_exports),
            "builtin_sets": builtin_sets,
            "imports": js_imports,
            "exports": js_exports,
            "signature_surface": {
                "boundary_count": len(signature_entries),
                "risky_boundary_count": len(risky_import_signatures),
                "risks": sorted(boundary_risks),
                "entries": signature_entries,
            },
            "risky_import_signatures": risky_import_signatures,
            "entry_trampolines": entry_trampolines,
        }

    def _entry_trampoline_signals(
        self,
        exports: list[dict[str, Any]],
        start_function: int | None,
        functions: dict[int, dict[str, Any]],
    ) -> dict[str, Any]:
        candidate_names = {"run", "start", "main", "_start", "__wbindgen_start"}
        risky_ops = {
            "call_indirect",
            "return_call_indirect",
            "call_ref",
            "return_call_ref",
            "table.set",
            "table.grow",
            "table.fill",
            "table.copy",
            "table.init",
            "elem.drop",
        }
        trampolines: list[dict[str, Any]] = []
        seen: set[int] = set()

        candidate_indices = {
            int(exp.get("ref_index", -1))
            for exp in exports
            if str(exp.get("kind", "")) == "func"
            and str(exp.get("name", "")) in candidate_names
            and isinstance(exp.get("ref_index"), int)
        }
        if isinstance(start_function, int):
            candidate_indices.add(start_function)

        for index in sorted(i for i in candidate_indices if i >= 0):
            if index in seen or index not in functions:
                continue
            seen.add(index)
            fn = functions[index]
            instructions = fn.get("instructions", [])
            if len(instructions) > 10:
                continue
            fn_risky_ops = [
                str(ins.get("opcode", ""))
                for ins in instructions[:8]
                if str(ins.get("opcode", "")) in risky_ops
                or self._is_conversion_opcode(str(ins.get("opcode", "")))
            ]
            if fn_risky_ops:
                trampolines.append(
                    {
                        "index": index,
                        "name": str(fn.get("name", "")),
                        "instruction_count": len(instructions),
                        "risk_ops": fn_risky_ops,
                    }
                )

        return {
            "detected": bool(trampolines),
            "count": len(trampolines),
            "functions": trampolines,
        }

    def _is_js_related_import(self, imp: dict[str, Any]) -> bool:
        module = str(imp.get("module", ""))
        name = str(imp.get("name", ""))
        if module in {"js", "wbg"}:
            return True
        if module.startswith("wasm:"):
            return True
        if module == "env" and any(
            token in name
            for token in (
                "log",
                "print",
                "console",
                "emscripten",
                "invoke_",
                "abort",
            )
        ):
            return True
        if name.startswith("__wbindgen") or name.startswith("__wbg_"):
            return True
        return "emscripten" in name or name.startswith("invoke_")

    def _type_for_index(
        self, type_map: dict[int, dict[str, Any]], type_index: Any
    ) -> dict[str, list[str]]:
        if not isinstance(type_index, int) or type_index not in type_map:
            return {"params": [], "results": []}
        type_rec = type_map[type_index]
        return {
            "params": [str(v) for v in type_rec.get("params", [])],
            "results": [str(v) for v in type_rec.get("results", [])],
        }

    def _has_ref_and_numeric_mix(self, params: list[str], results: list[str]) -> bool:
        values = params + results
        has_ref = any(
            v in {"externref", "funcref", "anyref", "eqref", "i31ref"} for v in values
        )
        has_numeric = any(v in {"i32", "i64", "f32", "f64", "v128"} for v in values)
        return has_ref and has_numeric

    def _signature_risk_reasons(
        self, params: list[str], results: list[str]
    ) -> list[str]:
        reasons: list[str] = []
        values = params + results
        if "externref" in values and "i64" in values:
            reasons.append("externref_i64_mix")
        if len(results) > 1:
            reasons.append("multi_result_boundary")
        if self._has_ref_and_numeric_mix(params, results):
            reasons.append("ref_numeric_mix")
        return reasons

    def _is_conversion_opcode(self, opcode: str) -> bool:
        if opcode in {
            "i32.wrap_i64",
            "i64.extend_i32_s",
            "i64.extend_i32_u",
            "f32.demote_f64",
            "f64.promote_f32",
            "any.convert_extern",
            "extern.convert_any",
            "ref.cast",
            "ref.test",
            "br_on_cast",
            "br_on_cast_fail",
        }:
            return True
        return opcode.startswith(
            (
                "i32.trunc_",
                "i64.trunc_",
                "i32.extend",
                "f32.convert_",
                "f64.convert_",
                "i32.reinterpret_",
                "i64.reinterpret_",
                "f32.reinterpret_",
                "f64.reinterpret_",
            )
        )

    def _is_call_ref_guard_opcode(self, opcode: str) -> bool:
        return opcode in {
            "ref.is_null",
            "ref.test",
            "ref.cast",
            "br_on_null",
            "br_on_non_null",
            "br_on_cast",
            "br_on_cast_fail",
        }

    def _format_signals(
        self,
        module_version: int | None,
        sections: list[dict[str, Any]],
        errors: list[str],
        component_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        signals: list[str] = []
        custom_names = {
            str(sec.get("name", "")) for sec in sections if int(sec.get("id", -1)) == 0
        }

        if component_info is not None:
            signals.append("component_layer")
            if component_info.get("interfaces"):
                signals.append("component_interfaces")
            if component_info.get("errors"):
                signals.append("component_section_errors")
            return {
                "kind": "component",
                "confidence": "high",
                "signals": sorted(set(signals)),
                "module_version": module_version,
                "component_version": component_info.get("component_version"),
                "layer_version": component_info.get("layer_version"),
            }

        if module_version is None:
            signals.append("missing_module_version")
        elif module_version != 1:
            signals.append("non_core_version")

        # Common names seen in component-oriented binaries and toolchains.
        if {"component-type", "producers", "target_features"}.intersection(
            custom_names
        ):
            signals.append("component_or_toolchain_custom_section")

        if errors:
            signals.append("parse_errors")

        if module_version != 1 and errors:
            kind = "invalid-core"
            confidence = "high"
        elif module_version != 1:
            kind = "possible-component"
            confidence = "medium"
        elif errors:
            kind = "invalid-core"
            confidence = "medium"
        else:
            kind = "core"
            confidence = "high"

        return {
            "kind": kind,
            "confidence": confidence,
            "signals": sorted(set(signals)),
            "module_version": module_version,
        }

    def _capabilities_from_imports(self, imports: list[dict[str, Any]]) -> set[str]:
        capabilities: set[str] = set()
        for imp in imports:
            module = str(imp.get("module", ""))
            name = str(imp.get("name", ""))
            kind = str(imp.get("kind", ""))

            if kind == "memory":
                capabilities.add("host.memory")
            elif kind == "table":
                capabilities.add("host.table")
            elif kind == "global":
                capabilities.add("host.global")
            elif kind == "tag":
                capabilities.add("host.tag")

            if module == "wasi_snapshot_preview1":
                if name.startswith("path_"):
                    capabilities.add("fs.path")
                if name.startswith("fd_"):
                    capabilities.add("fs.io")
                if name.startswith("sock_"):
                    capabilities.add("network")
                if name == "random_get":
                    capabilities.add("crypto.random")
                if name == "proc_exit":
                    capabilities.add("process.terminate")
                if name in {"clock_time_get", "poll_oneoff"}:
                    capabilities.add("clock.high_res")
            elif module == "wasi_unstable":
                if name.startswith("fd_"):
                    capabilities.add("fs.io")
                if name.startswith("path_"):
                    capabilities.add("fs.path")
                if name == "proc_exit":
                    capabilities.add("process.terminate")
            elif module.startswith("wasi:"):
                # Preview2-style namespaces expose capability intent in names.
                if any(token in name for token in ("filesystem", "path", "descriptor")):
                    capabilities.add("fs.path")
                if any(token in name for token in ("read", "write", "stream")):
                    capabilities.add("fs.io")
                if any(token in name for token in ("socket", "network")):
                    capabilities.add("network")
                if "random" in name:
                    capabilities.add("crypto.random")
                if "exit" in name or "terminate" in name:
                    capabilities.add("process.terminate")
                if "clock" in name:
                    capabilities.add("clock.high_res")

            if module in {"env", "wbg", "js"}:
                if any(token in name for token in ("log", "print")):
                    capabilities.add("host.logging")
                if "abort" in name or name == "proc_exit":
                    capabilities.add("process.terminate")
            if module in {"wbg", "js"}:
                capabilities.add("js.host")
        return capabilities

    def _build_findings(self, **kwargs: Any) -> list[dict[str, Any]]:
        capabilities: list[str] = kwargs["capabilities"]
        indirect_call_ops: int = kwargs["indirect_call_ops"]
        table_mutation_ops: int = kwargs["table_mutation_ops"]
        dynamic_funcs: set[int] = kwargs["dynamic_funcs"]
        table_mutation_funcs: set[int] = kwargs["table_mutation_funcs"]
        memory_grow_ops: int = kwargs["memory_grow_ops"]
        loop_memory_ops: int = kwargs["loop_memory_ops"]
        loop_memory_funcs: set[int] = kwargs["loop_memory_funcs"]
        format_detection: dict[str, Any] = kwargs["format_detection"]
        loop_max_depth: int = kwargs["loop_max_depth"]
        js_interface_detection: dict[str, Any] = kwargs["js_interface_detection"]
        js_exposed_dynamic_funcs: set[int] = kwargs["js_exposed_dynamic_funcs"]
        js_exposed_table_mutation_funcs: set[int] = kwargs[
            "js_exposed_table_mutation_funcs"
        ]
        strings_detection: dict[str, Any] | None = kwargs.get("strings_detection")
        paths_from_export: list[list[int]] = kwargs.get("paths_from_export", [])

        findings: list[dict[str, Any]] = []

        if {"fs.path", "network"}.issubset(set(capabilities)):
            findings.append(
                {
                    "id": "WASM-CAP-001",
                    "title": "Filesystem and network host capabilities are both imported",
                    "severity": "high",
                    "confidence": "high",
                    "evidence": {"capabilities": ["fs.path", "network"]},
                    "remediation": "Review sandbox policy and restrict host imports to least privilege.",
                }
            )

        if indirect_call_ops > 0 and table_mutation_ops > 0:
            findings.append(
                {
                    "id": "WASM-CFG-002",
                    "title": "Dynamic dispatch surface includes mutable table operations",
                    "severity": "high",
                    "confidence": "medium",
                    "evidence": {
                        "indirect_call_ops": indirect_call_ops,
                        "table_mutation_ops": table_mutation_ops,
                        "dynamic_funcs": sorted(i for i in dynamic_funcs if i >= 0),
                        "table_mutation_funcs": sorted(
                            i for i in table_mutation_funcs if i >= 0
                        ),
                    },
                    "remediation": "Prefer immutable dispatch tables or add strict index validation around table mutations.",
                }
            )

        if memory_grow_ops > 0 and loop_memory_ops > 0:
            findings.append(
                {
                    "id": "WASM-DOS-003",
                    "title": "Memory growth occurs in loop context",
                    "severity": "high",
                    "confidence": "medium",
                    "evidence": {
                        "memory_grow_ops": memory_grow_ops,
                        "loop_memory_ops": loop_memory_ops,
                        "functions": sorted(i for i in loop_memory_funcs if i >= 0),
                    },
                    "remediation": "Apply growth limits and add explicit loop bounds when executing untrusted inputs.",
                }
            )

        if loop_max_depth >= 3:
            findings.append(
                {
                    "id": "WASM-LOOP-004",
                    "title": "Deep loop nesting increases computational amplification risk",
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence": {"max_loop_depth": loop_max_depth},
                    "remediation": "Add runtime fuel/step limits or watchdog timeouts for untrusted modules.",
                }
            )

        if format_detection.get("kind") in {"possible-component", "invalid-core"}:
            findings.append(
                {
                    "id": "WASM-FMT-005",
                    "title": "Module format may be non-core or parse-incompatible",
                    "severity": "medium",
                    "confidence": format_detection.get("confidence", "medium"),
                    "evidence": {
                        "kind": format_detection.get("kind"),
                        "signals": format_detection.get("signals", []),
                        "module_version": format_detection.get("module_version"),
                    },
                    "remediation": "Validate the artifact type and use a component-aware parser for component-model binaries.",
                }
            )

        if (
            js_interface_detection.get("detected")
            and indirect_call_ops > 0
            and table_mutation_ops > 0
            and js_exposed_dynamic_funcs
            and js_exposed_table_mutation_funcs
        ):
            evidence: dict[str, Any] = {
                "indirect_call_ops": indirect_call_ops,
                "table_mutation_ops": table_mutation_ops,
                "js_exposed_dynamic_funcs": sorted(
                    i for i in js_exposed_dynamic_funcs if i >= 0
                ),
                "js_exposed_table_mutation_funcs": sorted(
                    i for i in js_exposed_table_mutation_funcs if i >= 0
                ),
            }
            if paths_from_export:
                evidence["paths_from_export"] = paths_from_export
            findings.append(
                {
                    "id": "WASM-JSCFG-006",
                    "title": "JS-exposed entrypoints combine dynamic dispatch and mutable table operations",
                    "severity": "high",
                    "confidence": "medium",
                    "evidence": evidence,
                    "remediation": "Reduce mutable table writes in exported/JS-facing entrypoints and isolate dynamic dispatch behind strict validation.",
                }
            )

        if strings_detection is not None and strings_detection.get("detected"):
            # Only key/token/exfiltration-shaped signals justify high
            # severity; URLs and domains alone are routine in real binaries
            # (docs links, license text, crate metadata) and stay medium.
            high_severity_signals = {
                "aws_access_key",
                "jwt_token",
                "pem_private_key",
                "mining_indicator",
            }
            medium_severity_signals = {"url", "domain"}
            present = set(strings_detection.get("signals", []))
            hit_signals = sorted(
                (high_severity_signals | medium_severity_signals) & present
            )
            if hit_signals:
                findings.append(
                    {
                        "id": "WASM-STR-007",
                        "title": "Credential-like or IoC strings embedded in data segments",
                        "severity": "high"
                        if high_severity_signals & present
                        else "medium",
                        "confidence": "medium",
                        "evidence": {
                            "signals": hit_signals,
                            "counts": strings_detection.get("counts", {}),
                            "samples": strings_detection.get("samples", {}),
                        },
                        "remediation": "Review the embedded strings; confirm no secrets, C2/mining endpoints, or other indicators are baked into the binary.",
                    }
                )

        return findings


def _run_core_pipeline(
    data: bytes,
    filename: str = "<core-module>",
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> dict[str, Any]:
    """Run the two-pass core-module pipeline and return its full report."""
    options = ObjdumpOptions(mode=ObjdumpMode.RAW_DATA, filename=filename)
    state = ObjdumpState()

    # Pass 1: gather names, types, and all section metadata into shared state.
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

    # Pass 2: collect function bodies and instruction streams.
    collector = _BinaryReaderJsonCollector(filename, state)
    BinaryReader(data, collector).read_module()
    return collector.build_report(
        strings_min_len=strings_min_len,
        include_strings=include_strings,
        include_call_graph=include_call_graph,
    )


def _aggregate_core_reports(
    core_reports: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Merge per-core-module section lists into component-level lists.

    Merged entries carry the originating ``core_module`` index so consumers
    can attribute behavior back to the module that contains it.
    """
    keys = (
        "functions",
        "types",
        "imports",
        "exports",
        "globals",
        "tables",
        "memories",
        "data_segments",
        "elements",
        "tags",
    )
    merged: dict[str, list[dict[str, Any]]] = {key: [] for key in keys}
    for module_index, report in enumerate(core_reports):
        for key in keys:
            for entry in report.get(key, []):
                if isinstance(entry, dict):
                    entry = dict(entry)
                    entry["core_module"] = module_index
                merged[key].append(entry)
    return merged


def _build_component_report(
    data: bytes,
    filename: str,
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> dict[str, Any]:
    """Build a full triage report for a component-model binary.

    Nested core modules are decoded with the regular core pipeline and their
    section data is aggregated at the top level (each entry tagged with
    ``core_module``), so the analysis layer and downstream consumers see one
    combined behavior picture.
    """
    component = parse_component_bytes(
        data,
        core_parse=lambda payload: _run_core_pipeline(
            payload,
            strings_min_len=strings_min_len,
            include_strings=include_strings,
            include_call_graph=include_call_graph,
        ),
    )
    sections = component.pop("sections", [])
    component_errors = list(component.pop("errors", []))

    merged = _aggregate_core_reports(component.get("core_modules", []))
    functions = merged["functions"]
    types = merged["types"]
    imports = merged["imports"]
    exports = merged["exports"]
    globals_ = merged["globals"]
    tables = merged["tables"]
    memories = merged["memories"]
    data_segments = merged["data_segments"]
    elements = merged["elements"]
    tags = merged["tags"]

    # Surface component interface imports as import records so the WASI and
    # capability detections see the component's host demands.
    for entry in component.get("imports", []):
        imports.append(
            {
                "module": str(entry.get("name", "")),
                "name": "",
                "kind": "component-" + str(entry.get("kind", "unknown")),
                "core_module": None,
            }
        )

    errors = list(component_errors)
    for report in component.get("core_modules", []):
        errors.extend(report.get("errors", []))

    # Each core module report already contains its extracted strings; merge
    # them with a core_module tag so provenance survives aggregation. The
    # per-module extraction already honored strings_min_len/include_strings.
    strings: list[dict[str, Any]] = []
    strings_truncated = False
    if include_strings:
        for module_index, report in enumerate(component.get("core_modules", [])):
            for entry in report.get("strings", []):
                entry = dict(entry)
                entry["core_module"] = module_index
                strings.append(entry)
            strings_truncated = strings_truncated or bool(
                report.get("strings_truncated", False)
            )
    strings_detection = analyze_strings(strings)

    call_graph = None
    if include_call_graph:
        call_graph = build_call_graph(
            functions=functions,
            imports=imports,
            exports=exports,
            elements=elements,
            start_function=None,
        )

    module_version = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
    component_info = dict(component)
    component_info["interfaces"] = component.get("interfaces", [])

    analysis = _BinaryReaderJsonCollector(filename, ObjdumpState())._build_analysis(
        functions=functions,
        types=types,
        imports=imports,
        exports=exports,
        data_segments=data_segments,
        sections=sections,
        module_version=module_version,
        start_function=None,
        errors=errors,
        strings_detection=strings_detection,
        call_graph=call_graph,
        component_info=component_info,
    )

    toolchain = _component_toolchain(component)

    return {
        "file": filename,
        "module_version": module_version,
        "is_component": True,
        "section_count": len(sections),
        "sections": sections,
        "function_count": len(functions),
        "functions": functions,
        "types": types,
        "imports": imports,
        "exports": exports,
        "globals": globals_,
        "tables": tables,
        "memories": memories,
        "data_segments": data_segments,
        "elements": elements,
        "tags": tags,
        "strings": strings,
        "strings_truncated": strings_truncated,
        "call_graph": {
            k: v for k, v in call_graph.items() if not k.startswith("_")
        }
        if call_graph is not None
        else {},
        "toolchain": toolchain,
        "start_function": None,
        "component": component,
        "analysis": analysis,
        "errors": errors,
    }


def _component_toolchain(component: dict[str, Any]) -> dict[str, Any]:
    """Toolchain fingerprint from component producers, else first core module."""
    producers = component.get("producers") or {}
    if not producers:
        for report in component.get("core_modules", []):
            if report.get("toolchain", {}).get("languages") or report.get(
                "toolchain", {}
            ).get("processed_by"):
                return report["toolchain"]
    target_features = [
        {"enabled": enabled, "name": name}
        for enabled, name in component.get("target_features", [])
    ]
    return {
        "languages": [n for n, _ in producers.get("language", [])],
        "processed_by": [
            {"name": n, "version": v} for n, v in producers.get("processed-by", [])
        ],
        "sdks": [{"name": n, "version": v} for n, v in producers.get("sdk", [])],
        "target_features": target_features,
    }


def parse_wasm_bytes(
    data: bytes,
    filename: str = "<memory>",
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> dict[str, Any]:
    """Parse raw wasm bytes (core module or component) into a report.

    ``strings_min_len`` is the extraction threshold (must reach extraction to
    be effective below the default of 5); ``include_strings`` /
    ``include_call_graph`` opt out of the derived blocks for consumers that
    only need section data.
    """
    if detect_component(data) is not None:
        return _build_component_report(
            data,
            filename,
            strings_min_len=strings_min_len,
            include_strings=include_strings,
            include_call_graph=include_call_graph,
        )
    return _run_core_pipeline(
        data,
        filename=filename,
        strings_min_len=strings_min_len,
        include_strings=include_strings,
        include_call_graph=include_call_graph,
    )


def parse_wasm_file(
    path: str,
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> dict[str, Any]:
    """Read and parse a wasm file path into a structured report dictionary."""
    try:
        with open(path, "rb") as wasm_file:
            return parse_wasm_bytes(
                wasm_file.read(),
                filename=path,
                strings_min_len=strings_min_len,
                include_strings=include_strings,
                include_call_graph=include_call_graph,
            )
    except OSError as exc:
        return {
            "file": path,
            "module_version": None,
            "is_component": False,
            "section_count": 0,
            "sections": [],
            "function_count": 0,
            "functions": [],
            "strings": [],
            "strings_truncated": False,
            "call_graph": {},
            "toolchain": _EMPTY_TOOLCHAIN,
            "analysis": _empty_analysis(),
            "errors": [f"Error reading {path}: {exc}"],
        }


_EMPTY_TOOLCHAIN: dict[str, Any] = {
    "languages": [],
    "processed_by": [],
    "sdks": [],
    "target_features": [],
}


def _empty_analysis() -> dict[str, Any]:
    """Analysis shape returned when a file cannot be read at all."""
    return {
        "summary": {
            "risk_score": 0,
            "risk_tier": "none",
            "finding_count": 0,
            "unknown_opcode_count": 0,
            "unknown_opcodes": [],
        },
        "detections": {
            "wasi": {
                "detected": False,
                "confidence": "none",
                "import_modules": [],
                "import_count": 0,
                "variants": [],
            },
            "js_interface": {
                "detected": False,
                "confidence": "none",
                "signals": [],
                "import_modules": [],
                "import_count": 0,
                "export_count": 0,
                "builtin_sets": [],
                "imports": [],
                "exports": [],
                "signature_surface": {
                    "boundary_count": 0,
                    "risky_boundary_count": 0,
                    "risks": [],
                    "entries": [],
                },
                "risky_import_signatures": [],
                "entry_trampolines": {
                    "detected": False,
                    "count": 0,
                    "functions": [],
                },
            },
            "format": {
                "kind": "invalid-core",
                "confidence": "high",
                "signals": ["file_read_error"],
                "module_version": None,
            },
            "strings": {
                "detected": False,
                "signals": [],
                "counts": {},
                "samples": {},
                "string_count": 0,
            },
        },
        "capabilities": [],
        "profiles": {},
        "findings": [],
    }


def parse_wasm_bytes_json(
    data: bytes,
    filename: str = "<memory>",
    indent: int = 2,
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> str:
    """Parse wasm bytes and serialize the structured report as JSON text."""
    report = parse_wasm_bytes(
        data,
        filename=filename,
        strings_min_len=strings_min_len,
        include_strings=include_strings,
        include_call_graph=include_call_graph,
    )
    return json.dumps(report, ensure_ascii=False, indent=indent)


def parse_wasm_file_json(
    path: str,
    indent: int = 2,
    strings_min_len: int = 5,
    include_strings: bool = True,
    include_call_graph: bool = True,
) -> str:
    """Parse a wasm file and serialize the structured report as JSON text."""
    report = parse_wasm_file(
        path,
        strings_min_len=strings_min_len,
        include_strings=include_strings,
        include_call_graph=include_call_graph,
    )
    return json.dumps(report, ensure_ascii=False, indent=indent)
