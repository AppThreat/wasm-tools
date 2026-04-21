"""Library-first JSON-friendly API for WebAssembly parsing results."""

from __future__ import annotations

import json
from typing import Any

from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState, SECTION_NAMES
from .parser import BinaryReader
from .visitor import BinaryReaderNop, BinaryReaderObjdumpPrepass


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
            {"index": i,
             "params": list(t.params), "results": list(t.results)}
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
                    rec["limits"] = {"min": imp.table_limits.minimum, "max": imp.table_limits.maximum}
            elif imp.kind == "memory":
                if imp.mem_limits:
                    rec["limits"] = {"min": imp.mem_limits.minimum, "max": imp.mem_limits.maximum, "is_64": imp.mem_limits.is_64}
            elif imp.kind == "global":
                rec["valtype"] = imp.global_valtype
                rec["mutable"] = imp.global_mutable
            elif imp.kind == "tag":
                rec["type_index"] = imp.tag_type_index
            imports.append(rec)

        exports = [
            {"index": exp.index, "name": exp.name, "kind": exp.kind, "ref_index": exp.ref_index}
            for exp in state.exports if exp is not None
        ]

        globals_ = [
            {"index": g.index, "valtype": g.valtype, "mutable": g.mutable, "init": g.init_expr}
            for g in state.globals if g is not None
        ]

        tables = [
            {"index": t.index, "ref_type": t.ref_type,
             "limits": {"min": t.limits.minimum, "max": t.limits.maximum}}
            for t in state.tables if t is not None
        ]

        memories = [
            {"index": m.index,
             "limits": {"min": m.limits.minimum, "max": m.limits.maximum, "is_64": m.limits.is_64}}
            for m in state.memories if m is not None
        ]

        data_segments = [
            {"index": d.index, "mode": d.mode, "memory_index": d.memory_index,
             "offset": d.offset_expr, "size": d.size}
            for d in state.data_segments if d is not None
        ]

        elements = [
            {"index": e.index, "mode": e.mode, "ref_type": e.ref_type,
             "table_index": e.table_index, "offset": e.offset_expr,
             "count": e.count, "func_indices": list(e.func_indices)}
            for e in state.elements if e is not None
        ]

        tags = [
            {"index": tg.index, "type_index": tg.type_index}
            for tg in state.tags if tg is not None
        ]

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
            "errors": self.errors,
        }


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
            "errors": [f"Error reading {path}: {exc}"],
        }


def parse_wasm_bytes_json(data: bytes, filename: str = "<memory>", indent: int = 2) -> str:
    """Parse wasm bytes and serialize the structured report as JSON text."""
    report = parse_wasm_bytes(data, filename=filename)
    return json.dumps(report, ensure_ascii=False, indent=indent)


def parse_wasm_file_json(path: str, indent: int = 2) -> str:
    """Parse a wasm file and serialize the structured report as JSON text."""
    report = parse_wasm_file(path)
    return json.dumps(report, ensure_ascii=False, indent=indent)

