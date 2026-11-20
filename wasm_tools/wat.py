"""WAT text emission from decoded reports.

Faithful flat text (one instruction per line, explicit block/end
structure), not decompilation: the audience is diffing modules, writing
text-level rules, and the round-trip conformance harness, which recompiles
emitted WAT with wat2wasm and the Rust wasm-tools and compares the decoded
modules. wasm-decompile left the mainstream toolchain in wabt 1.0.42, and
C-like output stays with the Ghidra/Binary Ninja plugins and research
decompilers.

Rendering is driven by each opcode's immediate type from the opcode table,
so an instruction either renders with every immediate it carries or is
replaced by a comment line that marks the emission ``incomplete``. The
emitter never drops an immediate silently and never invents syntax.

The report deliberately carries segment metadata only, and its constant
expression text is rounded for floats. When the caller passes the original
bytes as ``source``, global initializers, element segments and data
segments are decoded from those bytes (with the parser's own primitive
readers) so they render exactly; without them the emitter falls back to
the report and marks anything it cannot reproduce as incomplete.

Inputs are untrusted, so output size stays linear in the binary size: the
text format has no count syntax for locals, so local groups expand only up
to a per-function cap and a module-wide budget, and a group beyond either
renders as a comment and marks the emission incomplete.

Component binaries emit their nested core modules under per-module comment
headers; component-level WIT text is out of scope.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Optional

from .opcodes import OPCODES, ImmType
from .parser import BinaryReader, WasmParseError

# Immediate type per mnemonic. ``select`` appears twice in the table (bare
# 0x1B and typed 0x1C) and is rendered by its immediates instead.
_IMM_BY_NAME: dict[str, int] = {name: imm for name, imm in OPCODES.values()}

# Block types are a signed LEB: -64 (0x40) is empty, small negative values
# are single value types, non-negative values are type indices.
_BLOCK_VALTYPES = {
    -1: "i32",
    -2: "i64",
    -3: "f32",
    -4: "f64",
    -5: "v128",
    -12: "nullexnref",
    -13: "nullfuncref",
    -14: "nullexternref",
    -15: "nullref",
    -16: "funcref",
    -17: "externref",
    -18: "anyref",
    -19: "eqref",
    -20: "i31ref",
    -21: "structref",
    -22: "arrayref",
    -23: "exnref",
}

# Abstract heap type names (as the parser spells them) to the shorthand
# reference type each names when used as a table or element type.
_HEAP_SHORTHAND = {
    "func": "funcref",
    "extern": "externref",
    "exn": "exnref",
    "any": "anyref",
    "eq": "eqref",
    "i31": "i31ref",
    "struct": "structref",
    "array": "arrayref",
    "none": "nullref",
    "noextern": "nullexternref",
    "nofunc": "nullfuncref",
    "noexn": "nullexnref",
}

_ABS_HEAP_NAMES = frozenset(_HEAP_SHORTHAND)

# The text format has no repeat count for locals, so a hostile module can
# declare 2**32 - 1 locals in a few bytes. Expansion stops at the engines'
# per-function limit (V8 and the wasm-tools validator both reject more than
# 50,000 locals, so a larger group cannot belong to a loadable module) and at
# a module-wide budget proportional to the code size.
_MAX_LOCALS_PER_FUNCTION = 50_000
_LOCAL_BUDGET_BASE = 50_000
_LOCAL_BUDGET_PER_BODY_BYTE = 64

# WAT idchars: names made only of these render as plain ``$name`` ids;
# anything else renders as a quoted ``$"..."`` id.
_IDCHARS_RE = re.compile(r"^[0-9A-Za-z!#$%&'*+\-./:<=>?@\\^_`|~]+$")

# Escapes for WAT string literals: printable ASCII stays, quote and
# backslash are escaped, everything else (controls, DEL, every byte of a
# non-ASCII UTF-8 sequence) becomes a two-digit hex escape.
_STRING_ESCAPES = []
for _byte in range(256):
    if _byte == 0x22:
        _STRING_ESCAPES.append('\\"')
    elif _byte == 0x5C:
        _STRING_ESCAPES.append("\\\\")
    elif _byte == 0x09:
        _STRING_ESCAPES.append("\\t")
    elif _byte == 0x0A:
        _STRING_ESCAPES.append("\\n")
    elif _byte == 0x0D:
        _STRING_ESCAPES.append("\\r")
    elif 0x20 <= _byte <= 0x7E:
        _STRING_ESCAPES.append(chr(_byte))
    else:
        _STRING_ESCAPES.append(f"\\{_byte:02x}")
del _byte


def _wat_string(payload: bytes) -> str:
    """Render bytes as a WAT string literal (data payloads and names)."""
    escapes = _STRING_ESCAPES
    return '"' + "".join([escapes[b] for b in payload]) + '"'


def _wat_name(name: str) -> str:
    """Render an import, export or module field name as a string literal."""
    return _wat_string(name.encode("utf-8", errors="replace"))


def _wat_id(name: str) -> str:
    if _IDCHARS_RE.match(name):
        return "$" + name
    return "$" + _wat_name(name)


def _hexfloat(value: float) -> str:
    """Exact hex float spelling with the redundant mantissa zeros trimmed."""
    text = value.hex()
    mantissa, _, exponent = text.partition("p")
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    return f"{mantissa}p{exponent}"


def _f32_text(bits: int) -> str:
    sign = "-" if bits >> 31 else ""
    exponent = (bits >> 23) & 0xFF
    mantissa = bits & 0x7FFFFF
    if exponent == 0xFF:
        if mantissa == 0:
            return f"{sign}inf"
        return f"{sign}nan:0x{mantissa:x}"
    return _hexfloat(struct.unpack("<f", struct.pack("<I", bits))[0])


def _f64_text(bits: int) -> str:
    sign = "-" if bits >> 63 else ""
    exponent = (bits >> 52) & 0x7FF
    mantissa = bits & 0xFFFFFFFFFFFFF
    if exponent == 0x7FF:
        if mantissa == 0:
            return f"{sign}inf"
        return f"{sign}nan:0x{mantissa:x}"
    return _hexfloat(struct.unpack("<d", struct.pack("<Q", bits))[0])


def _f32_bits(value: Any) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _f64_bits(value: Any) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(value)))[0]


def _natural_log2(opcode: str) -> int:
    """log2 of the byte width a memory access is naturally aligned to."""
    if opcode in ("memory.atomic.notify", "memory.atomic.wait32"):
        return 2
    if opcode == "memory.atomic.wait64":
        return 3
    if opcode in ("f32.load_f16", "f32.store_f16"):
        return 1
    if opcode.startswith("v128."):
        rest = opcode[5:]
        if rest.startswith(("load8x8", "load16x4", "load32x2")):
            return 3
        match = re.match(r"(?:load|store)(8|16|32|64)_", rest)
        if match:
            return {"8": 0, "16": 1, "32": 2, "64": 3}[match.group(1)]
        return 4
    match = re.search(r"(?:load|store|rmw)(8|16|32)", opcode)
    if match:
        return {"8": 0, "16": 1, "32": 2}[match.group(1)]
    if opcode.startswith(("i64.", "f64.")):
        return 3
    return 2


def _memarg_text(opcode: str, align: Any, offset: Any) -> Optional[str]:
    """``offset=`` before ``align=``, as the text grammar requires.

    Alignment renders only when it differs from the natural width.
    """
    if not isinstance(align, int) or not isinstance(offset, int):
        return None
    if align < 0 or align > 63 or offset < 0:
        return None
    parts = []
    if offset:
        parts.append(f"offset={offset}")
    if align != _natural_log2(opcode):
        parts.append(f"align={2 ** align}")
    return " ".join(parts)


def _heap_type(text: Any) -> Optional[str]:
    """Parser heap-type spelling (``func``, ``type[3]``) to WAT."""
    text = str(text)
    if text in _ABS_HEAP_NAMES:
        return text
    match = re.fullmatch(r"type\[(\d+)\]", text)
    if match:
        return match.group(1)
    return None


def _type_ref_to_wat(text: str) -> str:
    """Translate the parser's ``type[N]`` heap-type spelling to WAT.

    (ref type[0]) renders as (ref 0); the parser emits ``type[N]`` for
    indexed heap types and the WAT grammar takes the bare index.
    """
    return re.sub(r"type\[(\d+)\]", r"\1", text)


_VALTYPE_RE = re.compile(
    r"i32|i64|f32|f64|v128|(?:null)?(?:func|extern|exn)ref|nullref|"
    r"(?:any|eq|i31|struct|array)ref|"
    r"\(ref (?:null )?(?:\d+|func|extern|exn|any|eq|i31|struct|array|none|"
    r"noextern|nofunc|noexn)\)"
)


def _valtype(text: Any) -> Optional[str]:
    """A value type in WAT spelling, or None for one the parser could not name."""
    wat = _type_ref_to_wat(str(text))
    return wat if _VALTYPE_RE.fullmatch(wat) else None


def _reftype(text: Any) -> str:
    """Table, element and import reference types to WAT."""
    text = str(text)
    if text in _HEAP_SHORTHAND:
        return _HEAP_SHORTHAND[text]
    return _type_ref_to_wat(text)


def _blocktype(sig: Any, ref_type: Any = None) -> Optional[str]:
    if ref_type is not None:
        valtype = _valtype(ref_type)
        return None if valtype is None else f" (result {valtype})"
    if not isinstance(sig, int):
        return None
    if sig == -64:
        return ""
    if sig >= 0:
        return f" (type {sig})"
    valtype = _BLOCK_VALTYPES.get(sig)
    if valtype is None:
        return None
    return f" (result {valtype})"


def _ints(values: list, count: int) -> bool:
    return len(values) == count and all(
        isinstance(v, int) and not isinstance(v, bool) for v in values
    )


def _init_expr_to_wat(text: str) -> Optional[str]:
    """Convert read_init_expr's text form (i32=7, ref.func=0, ...) to WAT.

    Used only when the source bytes are unavailable; float values in this
    form are rounded by the parser, so exact output needs ``source``.
    """
    kind, sep, value = str(text).partition("=")
    if not sep:
        return None
    if kind in ("i32", "i64", "f32", "f64"):
        return f"{kind}.const {value}"
    if kind in ("ref.func", "global.get"):
        return f"{kind} {value}"
    if kind == "ref.null":
        heap = _heap_type(value)
        return None if heap is None else f"ref.null {heap}"
    return None


# ─── Exact decoding of constant expressions and segments from source ────────

# Constant-expression opcodes beyond the MVP (extended-const arithmetic).
_CONST_BINOPS = {
    0x6A: "i32.add",
    0x6B: "i32.sub",
    0x6C: "i32.mul",
    0x7C: "i64.add",
    0x7D: "i64.sub",
    0x7E: "i64.mul",
}

# GC constant-expression opcodes (0xFB prefix) with their immediate counts.
_CONST_GC = {
    0: ("struct.new", 1),
    1: ("struct.new_default", 1),
    6: ("array.new", 1),
    7: ("array.new_default", 1),
    8: ("array.new_fixed", 2),
    26: ("any.convert_extern", 0),
    27: ("extern.convert_any", 0),
    28: ("ref.i31", 0),
}


def _read_const_expr(reader: BinaryReader, end: int) -> list[str]:
    """Decode a constant expression up to its 0x0B end into WAT instructions.

    An opcode outside the constant-expression set raises: its immediates
    are unknown, so the end of the expression (and of every later entry in
    the section) cannot be found, and the caller falls back to the report.
    """
    out: list[str] = []
    while reader.offset < end:
        opcode = reader.read_u8()
        if opcode == 0x0B:
            return out
        if opcode == 0x41:
            out.append(f"i32.const {reader.read_leb128(signed=True, max_bits=32)}")
        elif opcode == 0x42:
            out.append(f"i64.const {reader.read_leb128(signed=True, max_bits=64)}")
        elif opcode == 0x43:
            raw = reader.read_bytes(4)
            out.append(f"f32.const {_f32_text(struct.unpack('<I', raw)[0])}")
        elif opcode == 0x44:
            raw = reader.read_bytes(8)
            out.append(f"f64.const {_f64_text(struct.unpack('<Q', raw)[0])}")
        elif opcode == 0x23:
            out.append(f"global.get {reader.read_leb128(max_bits=32)}")
        elif opcode == 0xD2:
            out.append(f"ref.func {reader.read_leb128(max_bits=32)}")
        elif opcode == 0xD0:
            heap = _heap_type(reader.read_heaptype())
            if heap is None:
                raise WasmParseError("unknown heap type in constant expression")
            out.append(f"ref.null {heap}")
        elif opcode in _CONST_BINOPS:
            out.append(_CONST_BINOPS[opcode])
        elif opcode == 0xFD:
            if reader.read_leb128(max_bits=32) != 12:
                raise WasmParseError("unsupported constant expression opcode")
            raw = reader.read_bytes(16)
            lanes = struct.unpack("<4I", raw)
            out.append("v128.const i32x4 " + " ".join(f"0x{v:08x}" for v in lanes))
        elif opcode == 0xFB:
            sub = reader.read_leb128(max_bits=32)
            if sub not in _CONST_GC:
                raise WasmParseError("unsupported constant expression opcode")
            name, count = _CONST_GC[sub]
            args = [str(reader.read_leb128(max_bits=32)) for _ in range(count)]
            out.append(" ".join([name] + args))
        else:
            raise WasmParseError("unsupported constant expression opcode")
    raise WasmParseError("constant expression runs past its section")


def _expr_text(instrs: list[str]) -> str:
    """Folded form for one instruction, flat sequence otherwise."""
    if len(instrs) == 1:
        return f"({instrs[0]})"
    return " ".join(instrs)


def _offset_text(instrs: list[str]) -> str:
    if len(instrs) == 1:
        return f"({instrs[0]})"
    return "(offset " + " ".join(instrs) + ")"


class _SourceSections:
    """Global initializers, element and data segments decoded from source.

    Each attribute stays None when its section is absent or fails to
    decode, and the emitter then falls back to the report.
    """

    def __init__(self, source: bytes) -> None:
        self.globals: Optional[list[dict[str, Any]]] = None
        self.elements: Optional[list[dict[str, Any]]] = None
        self.data: Optional[list[dict[str, Any]]] = None
        self.globals_seen = False
        self.data_seen = False
        self.elements_seen = False
        reader = BinaryReader(source, None)
        spans: dict[int, tuple[int, int]] = {}
        try:
            reader.offset = 8
            while reader.offset < reader.size:
                section_id = reader.read_u8()
                size = reader.read_leb128(max_bits=32)
                start = reader.offset
                end = start + size
                if end > reader.size:
                    break
                if section_id in (6, 9, 11) and section_id not in spans:
                    spans[section_id] = (start, end)
                reader.offset = end
        except WasmParseError:
            pass
        if 6 in spans:
            self.globals_seen = True
            self.globals = self._decode(reader, spans[6], self._global)
        if 9 in spans:
            self.elements_seen = True
            self.elements = self._decode(reader, spans[9], self._element)
        if 11 in spans:
            self.data_seen = True
            self.data = self._decode(reader, spans[11], self._data)

    @staticmethod
    def _decode(reader: BinaryReader, span: tuple[int, int], one) -> Optional[list]:
        """Decode a whole section or nothing: entries are not self-delimiting."""
        start, end = span
        reader.offset = start
        try:
            count = reader.read_leb128(max_bits=32)
            out = []
            for _ in range(count):
                if reader.offset >= end:
                    return None
                out.append(one(reader, end))
                if reader.offset > end:
                    return None
            return out
        except (WasmParseError, ValueError, KeyError):
            return None

    @staticmethod
    def _global(reader: BinaryReader, end: int) -> dict[str, Any]:
        valtype, mutable = reader.read_globaltype()
        return {
            "valtype": valtype,
            "mutable": mutable,
            "init": _read_const_expr(reader, end),
        }

    @staticmethod
    def _element(reader: BinaryReader, end: int) -> dict[str, Any]:
        flags = reader.read_leb128(max_bits=32)
        if flags > 7:
            raise WasmParseError("unknown element segment flags")
        entry: dict[str, Any] = {"flags": flags, "table": 0, "offset": None}
        if flags & 0x01:
            entry["mode"] = "declarative" if flags & 0x02 else "passive"
        else:
            entry["mode"] = "active"
            if flags & 0x02:
                entry["table"] = reader.read_leb128(max_bits=32)
            entry["offset"] = _read_const_expr(reader, end)
        uses_exprs = bool(flags & 0x04)
        if flags in (0, 4):
            entry["kind"] = "func" if flags == 0 else "funcref"
        elif uses_exprs:
            entry["kind"] = _reftype(reader.read_reftype())
        else:
            entry["kind"] = "func" if reader.read_u8() == 0x00 else None
        count = reader.read_leb128(max_bits=32)
        items: list[str] = []
        for _ in range(count):
            if reader.offset >= end:
                raise WasmParseError("element segment truncated")
            if uses_exprs:
                items.append("(item " + " ".join(_read_const_expr(reader, end)) + ")")
            else:
                items.append(str(reader.read_leb128(max_bits=32)))
        entry["items"] = items
        return entry

    @staticmethod
    def _data(reader: BinaryReader, end: int) -> dict[str, Any]:
        flags = reader.read_leb128(max_bits=32)
        if flags > 2:
            raise WasmParseError("unknown data segment flags")
        entry: dict[str, Any] = {"memory": 0, "offset": None}
        if flags == 1:
            entry["mode"] = "passive"
        else:
            entry["mode"] = "active"
            if flags == 2:
                entry["memory"] = reader.read_leb128(max_bits=32)
            entry["offset"] = _read_const_expr(reader, end)
        length = reader.read_leb128(max_bits=32)
        if reader.offset + length > end:
            raise WasmParseError("data segment truncated")
        entry["payload"] = reader.read_bytes(length)
        return entry


class WatEmitter:
    def __init__(self, report: dict[str, Any], source: Optional[bytes]) -> None:
        self.report = report
        self.source = source
        self.lines: list[str] = []
        self.incomplete_reasons: list[str] = []
        self.sections = _SourceSections(source) if source else None

    @property
    def incomplete(self) -> bool:
        return bool(self.incomplete_reasons)

    def _mark_incomplete(self, reason: str) -> None:
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def _vt(self, text: Any) -> str:
        """Value type text; one the parser could not name marks the output."""
        wat = _valtype(text)
        if wat is None:
            self._mark_incomplete("value types the parser could not name")
            return "unknown_type"
        return wat

    def emit(self) -> str:
        if self.report.get("errors"):
            self._mark_incomplete("the report carries parse errors")
        self._emit_module()
        if self.incomplete_reasons:
            self.lines.append(
                ";; emission incomplete: " + "; ".join(self.incomplete_reasons)
            )
        return "\n".join(self.lines) + "\n"

    # ── instructions ──────────────────────────────────────────────────────

    def _instruction(self, ins: dict[str, Any]) -> None:
        opcode = str(ins.get("opcode", ""))
        immediates = list(ins.get("immediates") or [])
        text = None
        if not opcode.startswith("unknown_") and not ins.get("decode_incomplete"):
            try:
                text = self._render_instruction(opcode, immediates, ins)
            except (TypeError, ValueError, IndexError, KeyError, struct.error):
                text = None
        if text is None:
            self._mark_incomplete("instructions that cannot be rendered")
            offset = ins.get("offset")
            offset_text = offset if isinstance(offset, int) else "?"
            name = opcode if re.fullmatch(r"[0-9a-z_.]+", opcode) else "?"
            self.lines.append(
                f"    ;; unrenderable instruction {name} at offset {offset_text}"
            )
            return
        self.lines.append(f"    {text}")

    def _source_float_bits(self, ins: dict[str, Any], marker: int, width: int):
        """Exact float bits from the source when the offset points at them.

        The parser widens floats to Python doubles, which quiets signalling
        NaNs; the source bytes keep the payload.
        """
        source = self.source
        offset = ins.get("offset")
        if (
            source is None
            or not isinstance(offset, int)
            or offset < 0
            or offset + 1 + width > len(source)
            or source[offset] != marker
        ):
            return None
        fmt = "<I" if width == 4 else "<Q"
        return struct.unpack_from(fmt, source, offset + 1)[0]

    def _lane_memory_from_source(self, ins: dict[str, Any]) -> Optional[int]:
        """Memory index of a lane access, read from the source bytes.

        Collectors that predate the multi-memory lane memarg record only
        align, offset and lane; the memory index (present when bit 6 of the
        alignment field is set) is read back from the instruction bytes so
        it is not lost.
        """
        offset = ins.get("offset")
        if self.source is None or not isinstance(offset, int) or offset < 0:
            return None
        reader = BinaryReader(self.source, None)
        reader.offset = offset
        try:
            if reader.read_u8() != 0xFD:
                return None
            reader.read_leb128(max_bits=32)
            align = reader.read_leb128(max_bits=32)
            if align & 0x40:
                return reader.read_leb128(max_bits=32)
        except WasmParseError:
            return None
        return None

    def _render_instruction(
        self, opcode: str, imm: list, ins: dict[str, Any]
    ) -> Optional[str]:
        if opcode == "select":
            if not imm:
                return "select"
            if not all(isinstance(t, str) for t in imm):
                return None
            return "select (result " + " ".join(self._vt(t) for t in imm) + ")"
        kind = _IMM_BY_NAME.get(opcode)
        if kind is None:
            return None
        if kind == ImmType.NONE:
            return opcode if not imm else None
        if kind == ImmType.ATOMIC_FENCE:
            return opcode if not imm else None
        if kind == ImmType.BLOCK_SIG:
            if len(imm) != 1:
                return None
            sig = _blocktype(imm[0], ins.get("block_type"))
            return None if sig is None else opcode + sig
        if kind == ImmType.TRY_TABLE_BLOCK:
            return self._render_try_table(imm, ins)
        if kind in (ImmType.INDEX, ImmType.DELEGATE_LABEL, ImmType.LANE_IDX):
            if not _ints(imm, 1):
                return None
            if opcode in ("memory.size", "memory.grow", "memory.fill") and imm[0] == 0:
                # The default memory index is implicit in the text format.
                return opcode
            return f"{opcode} {imm[0]}"
        if kind in (ImmType.I32, ImmType.I64):
            return f"{opcode} {imm[0]}" if _ints(imm, 1) else None
        if kind == ImmType.F32:
            if len(imm) != 1:
                return None
            bits = self._source_float_bits(ins, 0x43, 4)
            if bits is None:
                bits = _f32_bits(imm[0])
            return f"f32.const {_f32_text(bits)}"
        if kind == ImmType.F64:
            if len(imm) != 1:
                return None
            bits = self._source_float_bits(ins, 0x44, 8)
            if bits is None:
                bits = _f64_bits(imm[0])
            return f"f64.const {_f64_text(bits)}"
        if kind == ImmType.MEMARG:
            if _ints(imm, 3):
                memory, align, offset = imm
                prefix = f" {memory}"
            elif _ints(imm, 2):
                align, offset = imm
                prefix = ""
            else:
                return None
            memarg = _memarg_text(opcode, align, offset)
            if memarg is None:
                return None
            return f"{opcode}{prefix} {memarg}".rstrip()
        if kind == ImmType.MEMARG_LANE:
            if _ints(imm, 4):
                memory, align, offset, lane = imm
            elif _ints(imm, 3):
                align, offset, lane = imm
                memory = self._lane_memory_from_source(ins)
            else:
                return None
            memarg = _memarg_text(opcode, align, offset)
            if memarg is None:
                return None
            memory_text = str(memory) if memory else ""
            return " ".join(p for p in (opcode, memory_text, memarg, str(lane)) if p)
        if kind == ImmType.BR_TABLE:
            if not imm or not _ints(imm, len(imm)):
                return None
            return "br_table " + " ".join(str(v) for v in imm)
        if kind == ImmType.CALL_INDIRECT:
            # Immediates: (type_idx, table_idx).
            if not _ints(imm, 2):
                return None
            if imm[1] == 0:
                return f"{opcode} (type {imm[0]})"
            return f"{opcode} {imm[1]} (type {imm[0]})"
        if kind == ImmType.MEMORY_INIT:
            # Collector records (mem_idx, data_idx); text is memidx? dataidx.
            if not _ints(imm, 2):
                return None
            memory, data = imm
            if memory == 0:
                return f"memory.init {data}"
            return f"memory.init {memory} {data}"
        if kind in (ImmType.MEMORY_COPY, ImmType.TABLE_COPY, ImmType.TWO_INDICES):
            if not _ints(imm, 2):
                return None
            return f"{opcode} {imm[0]} {imm[1]}"
        if kind == ImmType.TABLE_INIT:
            # Binary order is (elem_idx, table_idx); text takes the table first.
            if not _ints(imm, 2):
                return None
            return f"table.init {imm[1]} {imm[0]}"
        if kind == ImmType.HEAP_TYPE:
            if len(imm) != 1:
                return None
            heap = _heap_type(imm[0])
            if heap is None:
                return None
            if opcode == "ref.null":
                return f"ref.null {heap}"
            if opcode in ("ref.test", "ref.cast"):
                return f"{opcode} (ref {heap})"
            if opcode in ("ref.test_null", "ref.cast_null"):
                return f"{opcode[:-5]} (ref null {heap})"
            return None
        if kind == ImmType.BR_ON_CAST:
            if len(imm) != 4 or not _ints(imm[:2], 2):
                return None
            flags, label = imm[0], imm[1]
            heap1, heap2 = _heap_type(imm[2]), _heap_type(imm[3])
            if heap1 is None or heap2 is None or flags & ~0x03:
                return None
            null1 = "null " if flags & 0x01 else ""
            null2 = "null " if flags & 0x02 else ""
            return f"{opcode} {label} (ref {null1}{heap1}) (ref {null2}{heap2})"
        if kind == ImmType.V128_CONST:
            if not _ints(imm, 16) or any(not 0 <= v <= 255 for v in imm):
                return None
            lanes = struct.unpack("<4I", bytes(imm))
            return "v128.const i32x4 " + " ".join(f"0x{v:08x}" for v in lanes)
        if kind == ImmType.V128_SHUFFLE:
            if not _ints(imm, 16):
                return None
            return f"{opcode} " + " ".join(str(v) for v in imm)
        return None

    def _render_try_table(self, imm: list, ins: dict[str, Any]) -> Optional[str]:
        if not imm:
            return None
        sig = _blocktype(imm[0], ins.get("block_type"))
        if sig is None:
            return None
        parts = []
        for clause in ins.get("catches") or []:
            clause = list(clause)
            if not clause:
                return None
            kind = clause[0]
            if kind == 0x00 and _ints(clause, 3):
                parts.append(f"(catch {clause[1]} {clause[2]})")
            elif kind == 0x01 and _ints(clause, 3):
                parts.append(f"(catch_ref {clause[1]} {clause[2]})")
            elif kind == 0x02 and _ints(clause, 2):
                parts.append(f"(catch_all {clause[1]})")
            elif kind == 0x03 and _ints(clause, 2):
                parts.append(f"(catch_all_ref {clause[1]})")
            else:
                return None
        return "try_table" + sig + "".join(" " + p for p in parts)

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
            self.lines.append(f"  (start {int(report['start_function'])})")
        self._emit_tags(report.get("tags", []))
        self.lines.append(")")

    def _emit_types(self, types: list) -> None:
        for t in types:
            index = t.get("index")
            kind = str(t.get("kind", "func"))
            if kind != "func":
                # The report carries no struct or array field types. A
                # placeholder keeps later type indices in place; the
                # incomplete marker says it is not the real definition.
                label = kind if re.fullmatch(r"[a-z_]+", kind) else "unknown"
                self.lines.append(
                    f"  (type (;{index};) (struct))  ;; placeholder for a {label} type"
                )
                self._mark_incomplete("struct and array types are not emitted")
                continue
            params = " ".join(self._vt(p) for p in t.get("params", []))
            results = " ".join(self._vt(r) for r in t.get("results", []))
            param_text = f" (param {params})" if params else ""
            result_text = f" (result {results})" if results else ""
            self.lines.append(f"  (type (;{index};) (func{param_text}{result_text}))")

    @staticmethod
    def _limits_text(limits: dict[str, Any]) -> str:
        parts = ["i64" if limits.get("is_64") else "i32", str(int(limits.get("min", 0)))]
        if limits.get("max") is not None:
            parts.append(str(int(limits["max"])))
        if limits.get("shared"):
            parts.append("shared")
        if limits.get("page_size_log2") is not None:
            parts.append(f"(pagesize {2 ** int(limits['page_size_log2'])})")
        return " ".join(parts)

    def _emit_imports(self, imports: list) -> None:
        counters = {"func": 0, "table": 0, "memory": 0, "global": 0, "tag": 0}
        for imp in imports:
            kind = str(imp.get("kind", ""))
            names = f"{_wat_name(str(imp.get('module', '')))} {_wat_name(str(imp.get('name', '')))}"
            if kind not in counters:
                self.lines.append("  ;; import of an unknown kind not emitted")
                self._mark_incomplete("imports of unknown kinds")
                continue
            index = counters[kind]
            counters[kind] += 1
            if kind == "func":
                desc = f"(func (;{index};) (type {int(imp.get('type_index', 0))}))"
            elif kind == "memory":
                limits = imp.get("limits") or {}
                desc = f"(memory (;{index};) {self._limits_text(limits)})"
            elif kind == "table":
                limits = imp.get("limits") or {}
                ref_type = _reftype(imp.get("ref_type", "funcref"))
                desc = f"(table (;{index};) {self._limits_text(limits)} {ref_type})"
            elif kind == "global":
                valtype = self._vt(imp.get("valtype", ""))
                global_type = f"(mut {valtype})" if imp.get("mutable") else valtype
                desc = f"(global (;{index};) {global_type})"
            else:
                desc = f"(tag (;{index};) (type {int(imp.get('type_index', 0))}))"
            self.lines.append(f"  (import {names} {desc})")

    def _emit_functions(self, report: dict[str, Any]) -> None:
        types = {
            t.get("index"): t for t in report.get("types", []) if t.get("kind") == "func"
        }
        functions = report.get("functions", [])
        budget = _LOCAL_BUDGET_BASE + _LOCAL_BUDGET_PER_BODY_BYTE * sum(
            int(fn.get("body_size") or 0) for fn in functions
        )
        used_ids: set[str] = set()
        for fn in functions:
            index = fn.get("index")
            signature_index = fn.get("signature_index")
            signature = types.get(signature_index, {})
            params = " ".join(self._vt(p) for p in signature.get("params", []))
            results = " ".join(self._vt(r) for r in signature.get("results", []))
            name = fn.get("name")
            id_text = ""
            if isinstance(name, str) and name and name not in used_ids:
                used_ids.add(name)
                id_text = f" {_wat_id(name)}"
            # The text format places the type use first: (func (type N)
            # (param ...) (result ...)).
            header = f"  (func{id_text} (;{index};) (type {signature_index})"
            if params:
                header += f" (param {params})"
            if results:
                header += f" (result {results})"
            self.lines.append(header)
            budget = self._emit_locals(fn, budget)
            if fn.get("instructions_omitted"):
                self.lines.append(
                    f"    ;; instruction stream omitted (instruction_count "
                    f"{int(fn.get('instruction_count') or 0)})"
                )
                self._mark_incomplete("instruction streams omitted from the report")
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

    def _emit_locals(self, fn: dict[str, Any], budget: int) -> int:
        """Expand local groups within the per-function cap and module budget.

        A group that does not fit stops expansion for the function: later
        groups would otherwise take the wrong local indices.
        """
        declared = 0
        decls = list(fn.get("local_decls") or [])
        for position, decl in enumerate(decls):
            count, ltype = int(decl[0]), self._vt(decl[1])
            if count <= 0:
                continue
            if declared + count > _MAX_LOCALS_PER_FUNCTION or count > budget:
                remaining = sum(int(d[0]) for d in decls[position:])
                self.lines.append(
                    f"    ;; {remaining} locals in {len(decls) - position} groups "
                    "not expanded (local limit exceeded)"
                )
                self._mark_incomplete("local declarations beyond the expansion limit")
                break
            declared += count
            budget -= count
            self.lines.append("    (local " + " ".join([ltype] * count) + ")")
        return budget

    def _emit_tables(self, tables: list) -> None:
        for t in tables:
            limits = t.get("limits") or {}
            ref_type = _reftype(t.get("ref_type", "funcref"))
            self.lines.append(
                f"  (table (;{t.get('index')};) {self._limits_text(limits)} {ref_type})"
            )

    def _emit_memories(self, memories: list) -> None:
        for m in memories:
            limits = m.get("limits") or {}
            self.lines.append(f"  (memory (;{m.get('index')};) {self._limits_text(limits)})")

    def _emit_globals(self, globals_: list) -> None:
        decoded = self.sections.globals if self.sections else None
        if self.sections and self.sections.globals_seen and decoded is None:
            self._mark_incomplete("global section could not be decoded")
        if decoded is not None:
            # The source decode is exact: the report rounds float
            # initializers and keeps only the first instruction of an
            # extended constant expression.
            imported = sum(
                1 for i in self.report.get("imports", []) if str(i.get("kind")) == "global"
            )
            for position, g in enumerate(decoded):
                self._emit_global(
                    imported + position, g["valtype"], g["mutable"], _expr_text(g["init"])
                )
            return
        for g in globals_:
            expr = _init_expr_to_wat(str(g.get("init", "")))
            if expr is not None and expr.startswith(("f32.", "f64.")):
                # The report rounds float initializers to six digits.
                self._mark_incomplete("float initializers need the source bytes")
            self._emit_global(
                g.get("index"),
                g.get("valtype", ""),
                g.get("mutable"),
                None if expr is None else f"({expr})",
            )

    def _emit_global(self, index: Any, valtype: Any, mutable: Any, init: Optional[str]) -> None:
        valtype_text = _valtype(valtype)
        if init is None or valtype_text is None:
            self.lines.append(f"  ;; global {index}: cannot be rendered")
            self._mark_incomplete("globals that cannot be rendered")
            return
        type_text = f"(mut {valtype_text})" if mutable else valtype_text
        self.lines.append(f"  (global (;{index};) {type_text} {init})")

    def _emit_exports(self, exports: list) -> None:
        for exp in exports:
            kind = str(exp.get("kind", ""))
            if kind not in ("func", "memory", "table", "global", "tag"):
                self.lines.append("  ;; export of an unknown kind not emitted")
                self._mark_incomplete("exports of unknown kinds")
                continue
            self.lines.append(
                f"  (export {_wat_name(str(exp.get('name', '')))} "
                f"({kind} {int(exp.get('ref_index', 0))}))"
            )

    def _emit_elements(self, elements: list) -> None:
        decoded = self.sections.elements if self.sections else None
        if self.sections and self.sections.elements_seen and decoded is None:
            self._mark_incomplete("element section could not be decoded")
        if decoded is not None:
            for index, entry in enumerate(decoded):
                self._emit_decoded_element(index, entry)
            return
        for e in elements:
            # Report fallback: only function-index segments are recoverable.
            func_indices = [int(i) for i in e.get("func_indices", [])]
            mode = str(e.get("mode", ""))
            index = e.get("index")
            if int(e.get("count", 0)) != len(func_indices) or str(
                e.get("ref_type", "funcref")
            ) not in ("funcref", "func"):
                self.lines.append(f"  ;; elem {index}: expression items not emitted")
                self._mark_incomplete("element segments that need the source bytes")
                continue
            items = " ".join(str(i) for i in func_indices)
            if mode == "active":
                offset = _init_expr_to_wat(str(e.get("offset", "")))
                if offset is None:
                    self.lines.append(f"  ;; elem {index}: offset cannot be rendered")
                    self._mark_incomplete("element segments that need the source bytes")
                    continue
                self.lines.append(
                    f"  (elem (;{index};) (table {int(e.get('table_index', 0))}) "
                    f"({offset}) func {items})".replace(" )", ")")
                )
            elif mode == "declarative":
                self.lines.append(f"  (elem (;{index};) declare func {items})".replace(" )", ")"))
            elif mode == "passive":
                self.lines.append(f"  (elem (;{index};) func {items})".replace(" )", ")"))
            else:
                self.lines.append(f"  ;; elem {index}: unknown mode not emitted")
                self._mark_incomplete("element segments that need the source bytes")

    def _emit_decoded_element(self, index: int, entry: dict[str, Any]) -> None:
        items = entry["items"]
        kind = entry["kind"]
        if kind is None or (kind != "func" and _valtype(kind) is None):
            self.lines.append(f"  ;; elem {index}: cannot be rendered")
            self._mark_incomplete("element segments that cannot be rendered")
            return
        parts = [f"(elem (;{index};)"]
        if entry["mode"] == "active":
            if entry["flags"] & 0x02:
                parts.append(f"(table {entry['table']})")
            parts.append(_offset_text(entry["offset"]))
        elif entry["mode"] == "declarative":
            parts.append("declare")
        parts.append(kind)
        parts.extend(items)
        self.lines.append("  " + " ".join(parts) + ")")

    def _emit_data(self, segments: list) -> None:
        decoded = self.sections.data if self.sections else None
        if self.sections and self.sections.data_seen and decoded is None:
            self._mark_incomplete("data section could not be decoded")
        if decoded is not None:
            for index, entry in enumerate(decoded):
                literal = _wat_string(entry["payload"])
                if entry["mode"] == "passive":
                    self.lines.append(f"  (data (;{index};) {literal})")
                    continue
                memory = f" (memory {entry['memory']})" if entry["memory"] else ""
                self.lines.append(
                    f"  (data (;{index};){memory} {_offset_text(entry['offset'])} {literal})"
                )
            return
        for d in segments:
            # Without the source bytes the payload cannot be emitted;
            # placeholders keep the segment structure visible.
            self.lines.append(
                f"  ;; data {d.get('index')}: mode {d.get('mode')} size "
                f"{int(d.get('size', 0))} (payload not emitted)"
            )
            self._mark_incomplete("data payloads need the source bytes")

    def _emit_tags(self, tags: list) -> None:
        for tag in tags:
            self.lines.append(
                f"  (tag (;{tag.get('index')};) (type {int(tag.get('type_index', 0))}))"
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
        f";; component (version {int(report.get('module_version') or 0):#x} layer 1)",
        ";; component-level WAT emission covers the nested core modules only",
    ]
    for module_index, module in enumerate(report.get("component", {}).get("core_modules", [])):
        lines.append(f";; core module #{module_index}")
        lines.append(WatEmitter(module, None).emit())
    return "\n".join(lines) + "\n"
