"""Library-first JSON-friendly API for WebAssembly parsing results."""

from __future__ import annotations

import json
from typing import Any

from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState, SECTION_NAMES
from .parser import BinaryReader
from .visitor import BinaryReaderNop, BinaryReaderObjdumpPrepass


_HIGH_RISK_FINDING_WEIGHTS = {
    "WASM-CAP-001": 30,
    "WASM-CFG-002": 25,
    "WASM-DOS-003": 30,
    "WASM-LOOP-004": 15,
    "WASM-FMT-005": 10,
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

    def build_report(self) -> dict[str, Any]:
        """Build the final JSON-ready report for this module."""
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
                    rec["limits"] = {
                        "min": imp.table_limits.minimum,
                        "max": imp.table_limits.maximum,
                    }
            elif imp.kind == "memory":
                if imp.mem_limits:
                    rec["limits"] = {
                        "min": imp.mem_limits.minimum,
                        "max": imp.mem_limits.maximum,
                        "is_64": imp.mem_limits.is_64,
                    }
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
                "limits": {"min": t.limits.minimum, "max": t.limits.maximum},
            }
            for t in state.tables
            if t is not None
        ]

        memories = [
            {
                "index": m.index,
                "limits": {
                    "min": m.limits.minimum,
                    "max": m.limits.maximum,
                    "is_64": m.limits.is_64,
                },
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

        analysis = self._build_analysis(
            functions=functions,
            imports=imports,
            exports=exports,
            data_segments=data_segments,
            sections=self.sections,
            module_version=self.module_version,
            errors=self.errors,
        )

        return {
            "file": self.filename,
            "module_version": self.module_version,
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
            "start_function": state.start_function,
            "analysis": analysis,
            "errors": self.errors,
        }

    def _build_analysis(
        self,
        functions: list[dict[str, Any]],
        imports: list[dict[str, Any]],
        exports: list[dict[str, Any]],
        data_segments: list[dict[str, Any]],
        sections: list[dict[str, Any]],
        module_version: int | None,
        errors: list[str],
    ) -> dict[str, Any]:
        op_counts: dict[str, int] = {}
        loop_max_depth = 0
        loop_memory_ops = 0
        loop_branch_ops = 0
        indirect_call_ops = 0
        table_mutation_ops = 0
        memory_grow_ops = 0
        bulk_memory_ops = 0
        memory_access_ops = 0
        dynamic_funcs: set[int] = set()
        table_mutation_funcs: set[int] = set()
        loop_memory_funcs: set[int] = set()

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

        for fn in functions:
            active_loops = 0
            block_stack: list[str] = []
            for ins in fn.get("instructions", []):
                op = ins.get("opcode", "")
                op_counts[op] = op_counts.get(op, 0) + 1

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

                if op in table_mutators:
                    table_mutation_ops += 1
                    table_mutation_funcs.add(fn.get("index", -1))

        capabilities = sorted(self._capabilities_from_imports(imports))
        wasi_detection = self._wasi_signals_from_imports(imports)
        js_interface_detection = self._js_interface_signals(imports, exports)
        format_detection = self._format_signals(
            module_version=module_version,
            sections=sections,
            errors=errors,
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

        return {
            "summary": {
                "risk_score": risk_score,
                "risk_tier": _tier_from_score(risk_score),
                "finding_count": len(findings),
            },
            "detections": {
                "wasi": wasi_detection,
                "js_interface": js_interface_detection,
                "format": format_detection,
            },
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
                "control_flow": {
                    "indirect_call_ops": indirect_call_ops,
                    "table_mutation_ops": table_mutation_ops,
                },
                "compute": {
                    "max_loop_depth": loop_max_depth,
                    "loop_memory_ops": loop_memory_ops,
                    "loop_branch_ops": loop_branch_ops,
                },
            },
            "findings": findings,
        }

    def _wasi_signals_from_imports(
        self, imports: list[dict[str, Any]]
    ) -> dict[str, Any]:
        modules = sorted(
            {
                str(imp.get("module", ""))
                for imp in imports
                if str(imp.get("module", "")).startswith("wasi")
            }
        )
        import_count = sum(
            1 for imp in imports if str(imp.get("module", "")).startswith("wasi")
        )

        variants: list[str] = []
        if "wasi_snapshot_preview1" in modules:
            variants.append("preview1")
        if any(module.startswith("wasi:") for module in modules):
            variants.append("preview2-like")
        if any(module == "wasi_unstable" for module in modules):
            variants.append("legacy")

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
            is_js_related = False

            if module in {"js", "wbg"}:
                signals.add("js_namespace_import")
                is_js_related = True
            if module.startswith("wasm:"):
                signals.add("wasm_builtin_namespace_import")
                is_js_related = True
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
                is_js_related = True
            if name.startswith("__wbindgen") or name.startswith("__wbg_"):
                signals.add("wbindgen_pattern")
                is_js_related = True
            if "emscripten" in name or name.startswith("invoke_"):
                signals.add("emscripten_pattern")
                is_js_related = True

            if is_js_related:
                js_imports.append({"module": module, "name": name, "kind": kind})

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
        }

    def _format_signals(
        self,
        module_version: int | None,
        sections: list[dict[str, Any]],
        errors: list[str],
    ) -> dict[str, Any]:
        signals: list[str] = []
        custom_names = {
            str(sec.get("name", "")) for sec in sections if int(sec.get("id", -1)) == 0
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

        return findings


def parse_wasm_bytes(data: bytes, filename: str = "<memory>") -> dict[str, Any]:
    """Parse raw wasm bytes and return a structured report dictionary."""
    options = ObjdumpOptions(mode=ObjdumpMode.RAW_DATA, filename=filename)
    state = ObjdumpState()

    # Pass 1: gather names, types, and all section metadata into shared state.
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

    # Pass 2: collect function bodies and instruction streams.
    collector = _BinaryReaderJsonCollector(filename, state)
    BinaryReader(data, collector).read_module()
    return collector.build_report()


def parse_wasm_file(path: str) -> dict[str, Any]:
    """Read and parse a wasm file path into a structured report dictionary."""
    try:
        with open(path, "rb") as wasm_file:
            return parse_wasm_bytes(wasm_file.read(), filename=path)
    except OSError as exc:
        return {
            "file": path,
            "module_version": None,
            "section_count": 0,
            "sections": [],
            "function_count": 0,
            "functions": [],
            "analysis": {
                "summary": {"risk_score": 0, "risk_tier": "none", "finding_count": 0},
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
                    },
                    "format": {
                        "kind": "invalid-core",
                        "confidence": "high",
                        "signals": ["file_read_error"],
                        "module_version": None,
                    },
                },
                "capabilities": [],
                "profiles": {},
                "findings": [],
            },
            "errors": [f"Error reading {path}: {exc}"],
        }


def parse_wasm_bytes_json(
    data: bytes, filename: str = "<memory>", indent: int = 2
) -> str:
    """Parse wasm bytes and serialize the structured report as JSON text."""
    report = parse_wasm_bytes(data, filename=filename)
    return json.dumps(report, ensure_ascii=False, indent=indent)


def parse_wasm_file_json(path: str, indent: int = 2) -> str:
    """Parse a wasm file and serialize the structured report as JSON text."""
    report = parse_wasm_file(path)
    return json.dumps(report, ensure_ascii=False, indent=indent)
