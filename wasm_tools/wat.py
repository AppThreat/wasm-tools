"""WAT text emission from decoded reports.

Faithful flat text (one instruction per line, explicit block/end
structure), not decompilation: the audience is diffing modules, writing
text-level rules, and the round-trip conformance harness, which recompiles
emitted WAT with wat2wasm and compares decoded instruction sequences. wasm-
decompile left the mainstream toolchain in wabt 1.0.42, and C-like output
stays with the Ghidra/Binary Ninja plugins and research decompilers.

Rendering follows the text format's grammar; unknown opcodes render as
comment lines and mark the emission ``incomplete`` rather than inventing
syntax. Data and element segment payloads need the original bytes (the
report deliberately carries segment metadata only), passed via ``source``;
without them those segments emit size comments.

Component binaries emit their nested core modules under per-module comment
headers; component-level WIT text is out of scope.
"""

from __future__ import annotations

import struct
from typing import Any, Optional

# Binary reftype names to their WAT spellings.
# Block-type SLEB encodings to their WAT result spellings.
_BLOCK_SIG_NAMES = {
    -64: "",  # 0x40: empty
    -1: " (result i32)",
    -2: " (result i64)",
    -3: " (result f32)",
    -4: " (result f64)",
    -5: " (result v128)",
}

_REFTYPE_NAMES = {
    "func": "funcref",
    "extern": "externref",
    "exn": "exnref",
    "any": "anyref",
    "eq": "eqref",
    "i31": "i31ref",
    "struct": "structref",
    "array": "arrayref",
    "nullexternref": "nullref",
    "nullfuncref": "nullfuncref",
}

_F32_ZERO = 0.0


def _f32_repr(value: float) -> str:
    packed = struct.pack("<f", value)
    if packed == b"\x00\x00\x00\x00" and not (value < 0 or value > 0):
        return "0x0p+0"
    return repr(value)


def _i32_repr(value: int) -> str:
    if 0 <= value < 0x80000000:
        return str(value)
    return str(value)


def _natural_width(opcode: str) -> int:
    """Byte width a memory access validates against naturally."""
    if opcode.startswith("v128."):
        return 16
    if "load8" in opcode or "store8" in opcode:
        return 1
    if "load16" in opcode or "store16" in opcode:
        return 2
    if opcode.startswith("i32.") or opcode.startswith("f32."):
        return 4
    if opcode.startswith("i64.") or opcode.startswith("f64."):
        return 8
    return 4


def _render_memarg(opcode: str, immediates: list) -> str:
    """Memarg from the collector: optional memory index, align, offset.

    Alignment renders only when it differs from the opcode's natural width;
    re-emitting the default is noise and explicit-but-equal alignment is
    what most compilers emit.
    """
    parts = []
    if not immediates:
        return ""
    if len(immediates) >= 3:
        parts.append(str(immediates[0]))
        align, offset = immediates[1], immediates[2]
    else:
        align, offset = immediates[0], immediates[1]
    natural_log2 = _natural_width(opcode).bit_length() - 1
    if align != natural_log2:
        parts.append(f"align={2 ** align}")
    if offset:
        parts.append(f"offset={offset}")
    return " ".join(parts)


def _type_ref_to_wat(text: str) -> str:
    """Translate the parser's ``type[N]`` heap-type spelling to WAT.

    (ref type[0]) renders as (ref 0); the parser emits ``type[N]`` for
    indexed heap types and the WAT grammar takes the bare index.
    """
    out = []
    rest = text
    while True:
        start = rest.find("type[")
        if start < 0:
            out.append(rest)
            break
        end = rest.find("]", start)
        if end < 0:
            out.append(rest)
            break
        out.append(rest[:start])
        out.append(rest[start + 5 : end])
        rest = rest[end + 1 :]
    return "".join(out)


def _init_expr_to_wat(text: str) -> str:
    """Convert read_init_expr's text form (i32=7, ref.func=0, ...) to WAT."""
    if "=" not in text:
        return text
    kind, _, value = text.partition("=")
    if kind == "i32":
        return f"i32.const {value}"
    if kind == "i64":
        return f"i64.const {value}"
    if kind == "f32":
        return f"f32.const {value}"
    if kind == "f64":
        return f"f64.const {value}"
    if kind == "ref.func":
        return f"ref.func {value}"
    if kind == "ref.null":
        heap = _REFTYPE_NAMES.get(value, value)
        return f"ref.null {heap}"
    if kind == "global.get":
        return f"global.get {value}"
    return text


# Canonical section order: DataCount (id 12) sits between element (9) and
# code (10) in the binary, so ordering uses positions, not raw ids.
_CANONICAL_ORDER = {
    1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 12: 10, 10: 11, 11: 12,
}


def _extract_data_payloads(source: bytes) -> dict[int, bytes]:
    """Locate the data section in the source and map segment payloads.

    Mirrors the section framing walk (carve.py) to find section 11, then
    decodes the vec(data) grammar: per segment, flags byte, then for active
    segments an offset expression (skipped to the 0x0B end), then the byte
    vector. Passive and declarative segments carry the vector directly.
    """
    payloads: dict[int, bytes] = {}
    if source is None or len(source) < 8:
        return payloads
    offset = 8
    size = len(source)
    last_canonical = -1
    while offset < size:
        if source[offset : offset + 4] == b"\x00asm":
            break
        section_id = source[offset]
        if section_id > 13:
            break
        if section_id != 0:
            position = _CANONICAL_ORDER.get(section_id)
            if position is None or position <= last_canonical:
                break
            last_canonical = position
        offset += 1
        section_size = 0
        shift = 0
        while True:
            if offset >= size:
                return payloads
            byte = source[offset]
            offset += 1
            section_size |= (byte & 0x7F) << shift
            shift += 7
            if shift > 35:
                return payloads
            if not (byte & 0x80):
                break
        if section_id == 11:
            end = offset + section_size
            cursor = offset + 1  # past the vec count
            index = 0
            while cursor < end:
                flags = source[cursor]
                cursor += 1
                if flags in (0, 2):
                    # Active: flags, memidx (flags 2), offset expr to 0x0B.
                    if flags == 2:
                        cursor += 1
                    # Skip the init expression to its end marker, honoring
                    # nested blocks (constant exprs have none in practice).
                    while cursor < end and source[cursor] != 0x0B:
                        cursor += 1
                    cursor += 1
                length = 0
                shift = 0
                while True:
                    if cursor >= end:
                        return payloads
                    byte = source[cursor]
                    cursor += 1
                    length |= (byte & 0x7F) << shift
                    shift += 7
                    if not (byte & 0x80):
                        break
                payloads[index] = source[cursor : cursor + length]
                cursor += length
                index += 1
            return payloads
        offset += section_size
    return payloads


def _data_literal(payload: bytes) -> str:
    """Render a byte payload as a WAT string literal with escapes."""
    out = ['"']
    for byte in payload:
        if byte == 0x22:
            out.append('\\"')
        elif byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x09:
            out.append("\\t")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:02x}")
    out.append('"')
    return "".join(out)


class WatEmitter:
    def __init__(self, report: dict[str, Any], source: Optional[bytes]) -> None:
        self.report = report
        self.source = source
        self.lines: list[str] = []
        self.incomplete = False
        self.data_payloads = _extract_data_payloads(source) if source else {}

    def emit(self) -> str:
        self._emit_module()
        if self.incomplete:
            self.lines.append(";; emission incomplete: unknown opcodes present")
        return "\n".join(self.lines) + "\n"

    # ── helpers ───────────────────────────────────────────────────────────

    def _comment_unknown(self, instruction: dict[str, Any]) -> None:
        self.incomplete = True
        self.lines.append(
            f"    ;; unknown opcode {instruction.get('opcode', '?')} "
            f"at offset {instruction.get('offset')}"
        )

    def _instruction(self, ins: dict[str, Any]) -> None:
        opcode = str(ins.get("opcode", ""))
        immediates = list(ins.get("immediates") or [])
        if opcode.startswith("unknown_"):
            self._comment_unknown(ins)
            return
        text = self._render_instruction(opcode, immediates, ins)
        if text is None:
            self._comment_unknown(ins)
            return
        self.lines.append(f"    {text}")

    def _render_instruction(
        self, opcode: str, immediates: list, ins: dict[str, Any]
    ) -> Optional[str]:
        if opcode == "end":
            return "end"
        if opcode == "else":
            return "else"
        if opcode in ("block", "loop", "if"):
            sig = immediates[0] if immediates else -64
            if isinstance(sig, int) and sig >= 0:
                # A positive blocktype is a function type index: blocks with
                # parameters render through the type.
                return f"{opcode} (type {sig})"
            suffix = _BLOCK_SIG_NAMES.get(sig)
            if suffix is None:
                return None
            return f"{opcode}{suffix}"
        if opcode == "try_table":
            return self._render_try_table(immediates, ins)
        if opcode in ("br", "br_if"):
            if immediates:
                return f"{opcode} {immediates[0]}"
            return opcode
        if opcode == "br_table":
            if immediates:
                return "br_table " + " ".join(str(v) for v in immediates)
            return "br_table"
        if opcode in ("return", "unreachable", "nop", "drop"):
            return opcode
        if opcode in ("call", "return_call", "ref.null", "br_on_null", "call_ref",
                      "return_call_ref"):
            suffix = ""
            if opcode == "ref.null" and immediates:
                # Heap types render in their short form (extern, func, ...);
                # the parser already emits those names.
                suffix = f" {_type_ref_to_wat(str(immediates[0]))}"
            elif immediates and opcode in ("call", "return_call", "call_ref",
                                           "return_call_ref"):
                suffix = f" {immediates[0]}"
            return opcode + suffix
        if opcode in ("call_indirect", "return_call_indirect"):
            # Immediates: (type_idx, table_idx).
            if len(immediates) >= 2 and immediates[1] == 0:
                return f"{opcode} (type {immediates[0]})"
            if len(immediates) >= 2:
                return f"{opcode} {immediates[1]} (type {immediates[0]})"
            return None
        if opcode == "table.init":
            # Binary order is (elem_idx, table_idx); the text format takes
            # the table index first.
            if len(immediates) >= 2:
                return f"table.init {immediates[1]} {immediates[0]}"
            if immediates:
                return f"table.init 0 {immediates[0]}"
            return None
        if opcode == "table.copy":
            if len(immediates) >= 2:
                return f"table.copy {immediates[0]} {immediates[1]}"
            return None
        if opcode in (
            "local.get", "local.set", "local.tee", "global.get", "global.set",
            "table.get", "table.set", "table.grow", "table.size", "table.fill",
            "ref.func", "elem.drop", "data.drop", "memory.fill",
        ):
            if immediates:
                return f"{opcode} {immediates[0]}"
            return None
        if opcode == "memory.init":
            # Collector records (mem_idx, data_idx) in that order.
            if len(immediates) >= 2:
                mem_idx, data_idx = immediates[0], immediates[1]
                if mem_idx == 0:
                    return f"memory.init {data_idx}"
                return f"memory.init {data_idx} {mem_idx}"
            return None
        if opcode == "memory.copy":
            if len(immediates) >= 2:
                return f"memory.copy {immediates[0]} {immediates[1]}"
            return None
        if opcode in ("i32.const",):
            if immediates:
                return f"i32.const {immediates[0]}"
            return None
        if opcode in ("i64.const",):
            if immediates:
                return f"i64.const {immediates[0]}"
            return None
        if opcode == "f32.const":
            if immediates:
                return f"f32.const {_f32_repr(float(immediates[0]))}"
            return None
        if opcode == "f64.const":
            if immediates:
                return f"f64.const {immediates[0]}"
            return None
        if opcode == "v128.const":
            if len(immediates) == 16:
                lanes = [
                    struct.unpack("<I", bytes(immediates[i : i + 4]))[0]
                    for i in range(0, 16, 4)
                ]
                return "v128.const i32x4 " + " ".join(f"0x{lane:08x}" for lane in lanes)
            return None
        if opcode == "v128.shuffle":
            if len(immediates) == 16:
                return "v128.shuffle " + " ".join(str(v) for v in immediates)
            return None
        if opcode == "select" or opcode == "select_t":
            if opcode == "select_t" and immediates:
                return "select (result " + " ".join(str(t) for t in immediates) + ")"
            return "select"
        if opcode.startswith("br_on_cast"):
            if len(immediates) >= 4:
                return f"{opcode} {immediates[1]} (ref {immediates[2]}) (ref {immediates[3]})"
            return None
        if opcode.endswith("_lane"):
            # v128.load*/store*_lane: (align, offset, lane) via
            # on_opcode_memarg_lane. wat2wasm's lane-operand parser wants
            # the offset before the alignment.
            if len(immediates) >= 3:
                align, offset, lane = immediates[0], immediates[1], immediates[2]
                parts = []
                if offset:
                    parts.append(f"offset={offset}")
                parts.append(f"align={2 ** align}")
                parts.append(str(lane))
                return f"{opcode} " + " ".join(parts)
            return None
        if opcode.endswith("_lane"):
            # v128.load*/store*_lane: (align, offset, lane) via
            # on_opcode_memarg_lane. wat2wasm's lane-operand parser wants
            # the offset before the alignment.
            if len(immediates) >= 3:
                align, offset, lane = immediates[0], immediates[1], immediates[2]
                parts = []
                if offset:
                    parts.append(f"offset={offset}")
                parts.append(f"align={2 ** align}")
                parts.append(str(lane))
                return f"{opcode} " + " ".join(parts)
            return None
        if opcode.startswith(("i32.load", "i64.load", "f32.load", "f64.load",
                              "v128.load", "i32.store", "i64.store", "f32.store",
                              "f64.store", "v128.store", "i32.atomic.", "i64.atomic.",
                              "memory.atomic.")):
            memarg = _render_memarg(opcode, immediates)
            return f"{opcode} {memarg}".rstrip()
        if opcode.startswith(("struct.", "array.")):
            if immediates:
                return f"{opcode} (type {immediates[0]})"
            return None
        if opcode in ("ref.cast", "ref.test", "ref.as_non_null", "br_on_cast_fail"):
            if immediates:
                return f"{opcode} (ref {immediates[0]})"
            return opcode
        if opcode == "delegate":
            if immediates:
                return f"delegate {immediates[0]}"
            return None
        if opcode == "throw" or opcode == "throw_ref":
            if immediates:
                return f"throw {immediates[0]}"
            return opcode
        if opcode.startswith(("catch", "try")):
            return opcode
        if opcode in ("memory.grow", "memory.size"):
            return opcode
        # Every remaining opcode in the table is immediate-free (numeric,
        # conversion, SIMD arithmetic, GC accessors).
        return opcode

    def _render_try_table(
        self, immediates: list, ins: dict[str, Any]
    ) -> Optional[str]:
        catches = ins.get("catches") or []
        parts = []
        for clause in catches:
            kind = clause[0]
            if kind == 0x00 and len(clause) >= 3:  # catch
                parts.append(f"catch {clause[1]} {clause[2]}")
            elif kind == 0x01 and len(clause) >= 3:  # catch_ref
                parts.append(f"catch_ref {clause[1]} {clause[2]}")
            elif kind == 0x02 and len(clause) >= 2:  # catch_all <label>
                parts.append(f"catch_all {clause[1]}")
            elif kind == 0x03:  # catch_all_ref: no label
                parts.append("catch_all_ref")
            else:
                return None
        sig = immediates[0] if immediates else -64
        sig_text = _BLOCK_SIG_NAMES.get(sig, "")
        if sig_text is None:
            return None
        # wat2wasm expects parenthesized catch clauses.
        return (
            "try_table"
            + sig_text
            + (" " + " ".join(f"({part})" for part in parts) if parts else "")
        )

    # ── module skeleton ────────────────────────────────────────────────────

    def _emit_module(self) -> None:
        report = self.report
        self.lines.append("(module")
        self._emit_types(report.get("types", []))
        self._emit_imports(report.get("imports", []))
        self._emit_functions(report)
        self._emit_tables(report.get("tables", []))
        self._emit_memories(report.get("memories", []))
        self._emit_globals(report.get("globals", []))
        self._emit_exports(report.get("exports", []))
        self._emit_elements(report.get("elements", []))
        self._emit_data(report.get("data_segments", []))
        if report.get("start_function") is not None:
            self.lines.append(f"  (start {report['start_function']})")
        self._emit_tags(report.get("tags", []))
        self.lines.append(")")

    def _emit_types(self, types: list) -> None:
        for t in types:
            index = t.get("index")
            kind = str(t.get("kind", "func"))
            if kind != "func":
                self.lines.append(f"  (type (;{index};) (sub (struct)))  ;; kind {kind}")
                self.incomplete = True
                continue
            params = " ".join(
                _type_ref_to_wat(str(p)) for p in t.get("params", [])
            )
            results = " ".join(
                _type_ref_to_wat(str(r)) for r in t.get("results", [])
            )
            param_text = f" (param {params})" if params else ""
            result_text = f" (result {results})" if results else ""
            self.lines.append(
                f"  (type (;{index};) (func{param_text}{result_text}))"
            )

    def _emit_imports(self, imports: list) -> None:
        func_index = 0
        for imp in imports:
            kind = str(imp.get("kind", ""))
            module = str(imp.get("module", ""))
            name = str(imp.get("name", ""))
            if kind == "func":
                type_index = imp.get("type_index")
                self.lines.append(
                    f'  (import "{module}" "{name}" (func (;{func_index};) '
                    f"(type {type_index})))"
                )
                func_index += 1
            elif kind == "memory":
                limits = imp.get("limits", {})
                index_type = "i64" if limits.get("is_64") else "i32"
                self.lines.append(
                    f'  (import "{module}" "{name}" (memory {index_type} '
                    f'{limits.get("min", 0)}))'
                )
            elif kind == "table":
                limits = imp.get("limits", {})
                ref_type = _REFTYPE_NAMES.get(
                    str(imp.get("ref_type", "funcref")), str(imp.get("ref_type", "funcref"))
                )
                self.lines.append(
                    f'  (import "{module}" "{name}" (table {limits.get("min", 0)} {ref_type}))'
                )
            elif kind == "global":
                valtype = _type_ref_to_wat(str(imp.get("valtype", "")))
                mut = f" (mut {valtype})" if imp.get("mutable") else ""
                self.lines.append(
                    f'  (import "{module}" "{name}" (global {valtype}{mut}))'
                )
            elif kind == "tag":
                self.lines.append(
                    f'  (import "{module}" "{name}" (tag (type {imp.get("type_index")})))'
                )

    def _emit_functions(self, report: dict[str, Any]) -> None:
        imports = report.get("imports", [])
        imported_func_count = sum(1 for i in imports if str(i.get("kind", "")) == "func")
        types = {
            t.get("index"): t for t in report.get("types", []) if t.get("kind") == "func"
        }
        for fn in report.get("functions", []):
            index = fn.get("index")
            signature_index = fn.get("signature_index")
            signature = types.get(signature_index, {})
            params = " ".join(
                _type_ref_to_wat(str(p)) for p in signature.get("params", [])
            )
            results = " ".join(
                _type_ref_to_wat(str(r)) for r in signature.get("results", [])
            )
            # The text format places the type use first: (func (type N)
            # (param ...) (result ...)).
            header = f"  (func (;{index};) (type {signature_index})"
            if params:
                header += f" (param {params})"
            if results:
                header += f" (result {results})"
            self.lines.append(header)
            # Local declarations follow the type use: (local N type ...).
            for decl in fn.get("local_decls") or []:
                count, ltype = decl
                rendered = _type_ref_to_wat(str(ltype))
                self.lines.append(f"    (local {' '.join([rendered] * int(count))})")
            if fn.get("instructions_omitted"):
                self.lines.append(
                    f"    ;; instruction stream omitted (instruction_count "
                    f"{fn.get('instruction_count')})"
                )
            elif fn.get("instructions"):
                # The report includes the function-body's final end; in WAT
                # the closing paren is that end, so track depth and skip it.
                depth = 1
                for ins in fn["instructions"]:
                    opcode = str(ins.get("opcode", ""))
                    if opcode in ("block", "loop", "if", "try_table", "try"):
                        depth += 1
                    elif opcode == "end":
                        depth -= 1
                        if depth == 0:
                            continue  # function-closing end: skip
                    elif opcode == "delegate":
                        # Legacy delegate closes its try like an end.
                        depth -= 1
                    self._instruction(ins)
            self.lines.append("  )")

    def _emit_tables(self, tables: list) -> None:
        for t in tables:
            limits = t.get("limits", {})
            ref_type = _REFTYPE_NAMES.get(
                str(t.get("ref_type", "funcref")), str(t.get("ref_type", "funcref"))
            )
            min_pages = limits.get("min", 0)
            max_pages = limits.get("max")
            limit_text = str(min_pages) if max_pages is None else f"{min_pages} {max_pages}"
            index_type = "i64" if limits.get("is_64") else "i32"
            self.lines.append(
                f"  (table (;{t.get('index')};) {index_type} {limit_text} {ref_type})"
            )

    def _emit_memories(self, memories: list) -> None:
        for m in memories:
            limits = m.get("limits", {})
            min_pages = limits.get("min", 0)
            max_pages = limits.get("max")
            limit_text = str(min_pages) if max_pages is None else f"{min_pages} {max_pages}"
            index_type = "i64" if limits.get("is_64") else "i32"
            if limits.get("shared"):
                limit_text += " shared"
            self.lines.append(
                f"  (memory (;{m.get('index')};) {index_type} {limit_text})"
            )

    def _emit_globals(self, globals_: list) -> None:
        for g in globals_:
            valtype = _REFTYPE_NAMES.get(
                str(g.get("valtype", "")), str(g.get("valtype", ""))
            )
            valtype = _type_ref_to_wat(valtype)
            type_text = (
                f"(mut {valtype})" if g.get("mutable") else valtype
            )
            init = _init_expr_to_wat(str(g.get("init", "i32=0")))
            self.lines.append(
                f"  (global (;{g.get('index')};) {type_text} ({init}))"
            )

    def _emit_exports(self, exports: list) -> None:
        kind_map = {
            "func": "func",
            "memory": "memory",
            "table": "table",
            "global": "global",
            "tag": "tag",
        }
        for exp in exports:
            kind = kind_map.get(str(exp.get("kind", "")))
            if kind is None:
                continue
            self.lines.append(
                f'  (export "{exp.get("name", "")}" ({kind} {exp.get("ref_index")}))'
            )

    def _emit_elements(self, elements: list) -> None:
        for e in elements:
            mode = str(e.get("mode", ""))
            func_indices = e.get("func_indices", [])
            if mode == "active":
                offset = _init_expr_to_wat(str(e.get("offset", "i32=0")))
                self.lines.append(
                    f"  (elem (;{e.get('index')};) (table {e.get('table_index', 0)}) "
                    f"({offset}) func {' '.join(str(i) for i in func_indices)})"
                )
            elif mode == "declarative":
                self.lines.append(
                    f"  (elem (;{e.get('index')};) declare func "
                    f"{' '.join(str(i) for i in func_indices)})"
                )
            elif mode == "passive":
                self.lines.append(
                    f"  (elem (;{e.get('index')};) func "
                    f"{' '.join(str(i) for i in func_indices)})"
                )
            else:
                self.lines.append(
                    f"  ;; elem[{e.get('index')}] mode {mode} with "
                    f"{len(func_indices)} entries (payload not emitted)"
                )
                self.incomplete = True

    def _emit_data(self, segments: list) -> None:
        for d in segments:
            index = d.get("index")
            mode = str(d.get("mode", ""))
            payload = self.data_payloads.get(index)
            if payload is None:
                # Without the source bytes the payload cannot be emitted;
                # placeholders keep the segment structure visible.
                self.lines.append(
                    f"  ;; data[{index}] mode {mode} size {d.get('size', 0)}"
                    " (payload not emitted)"
                )
                self.incomplete = True
                continue
            literal = _data_literal(payload)
            if mode == "active":
                offset = _init_expr_to_wat(str(d.get("offset", "i32=0")))
                memory_index = d.get("memory_index", 0)
                memory_text = (
                    f"(memory {memory_index})" if memory_index else ""
                )
                self.lines.append(
                    f"  (data (;{index};) {memory_text} ({offset}) {literal})"
                )
            else:
                self.lines.append(f"  (data (;{index};) {literal})")

    def _emit_tags(self, tags: list) -> None:
        for tag in tags:
            self.lines.append(
                f"  (tag (;{tag.get('index')};) (type {tag.get('type_index')}))"
            )


def emit_wat(
    report: dict[str, Any],
    source: Optional[bytes] = None,
    style: str = "flat",
) -> str:
    """Emit WAT text for a report's decoded module (flat style)."""
    if style != "flat":
        raise ValueError(f"unsupported WAT style {style!r}")
    if report.get("is_component"):
        return _emit_component_wat(report)
    return WatEmitter(report, source).emit()


def _emit_component_wat(report: dict[str, Any]) -> str:
    lines = [
        f";; component (version {report.get('module_version'):#x} layer 1)",
        ";; component-level WAT emission covers the nested core modules only",
    ]
    for module_index, module in enumerate(report.get("component", {}).get("core_modules", [])):
        lines.append(f";; core module #{module_index}")
        lines.append(WatEmitter(module, None).emit())
    return "\n".join(lines) + "\n"
