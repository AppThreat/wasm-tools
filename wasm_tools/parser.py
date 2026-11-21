import inspect
import struct
from typing import Any, List, Optional, Tuple

from .customsections import (
    parse_branch_hints,
    parse_component_type,
    parse_dylink,
    parse_dylink_legacy,
    parse_linking,
)
from .models import BinarySection
from .opcodes import OPCODES, ImmType


class WasmParseError(Exception):
    """Raised for malformed or truncated WebAssembly binary input."""

    pass


_KEYWORD_SUPPORT: dict = {}


def _accepts_keyword(method: Any, keyword: str) -> bool:
    """Return True when a delegate callback takes ``keyword``.

    Delegates written before an optional immediate existed keep their
    positional signature; the parser only passes the new keyword to the
    ones that declare it (or take ``**kwargs``). Results are cached per
    underlying function.
    """
    func = getattr(method, "__func__", method)
    key = (func, keyword)
    cached = _KEYWORD_SUPPORT.get(key)
    if cached is None:
        try:
            params = inspect.signature(method).parameters
        except (TypeError, ValueError):
            cached = False
        else:
            cached = keyword in params or any(
                p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
            )
        _KEYWORD_SUPPORT[key] = cached
    return cached


class MockOpcode:
    def __init__(self, name: str) -> None:
        """Wrap a decoded opcode name for delegate callbacks."""
        self.name = name


def _format_const_immediate(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return " ".join(_format_const_immediate(v) for v in value)
    return str(value)


class _ConstExprRecorder:
    """Delegate that collects the instructions of one constant expression.

    ``read_init_expr`` swaps it in while it runs the normal instruction
    decoder, so the module delegate never sees constant-expression
    instructions as part of a function body. Every ``on_opcode_*`` callback
    records its arguments as the current instruction's immediates.
    """

    def __init__(self) -> None:
        self.instructions: List[Tuple[str, List[Any]]] = []
        self.closed = False
        self.offset = 0
        self.current_opcode: Any = None

    def on_opcode(self, opcode: MockOpcode) -> None:
        # An unknown opcode's immediates cannot be skipped, so the end of the
        # expression (and every later entry in the section) would be lost.
        if opcode.name.startswith("unknown_"):
            raise WasmParseError(
                f"Unsupported opcode {opcode.name} in constant expression"
            )
        self.instructions.append((opcode.name, []))

    def on_end_expr(self) -> None:
        # The decoder reports ``end`` through on_opcode first; drop it so
        # only the expression's own instructions remain.
        if self.instructions and self.instructions[-1][0] == "end":
            self.instructions.pop()
        self.closed = True

    def _record(self, *args: Any, **kwargs: Any) -> None:
        if self.instructions:
            self.instructions[-1][1].extend(args)
            self.instructions[-1][1].extend(kwargs.values())

    def __getattr__(self, name: str) -> Any:
        # One shared bound method, so the per-function keyword cache in
        # _accepts_keyword holds a single entry for every callback name.
        if not name.startswith("on_opcode_"):
            raise AttributeError(name)
        return self._record

    def result(self) -> Tuple[str, Optional[int]]:
        insns = self.instructions
        if len(insns) == 1:
            name, imms = insns[0]
            if len(imms) == 1:
                imm = imms[0]
                if name in ("i32.const", "i64.const"):
                    return f"{name[:3]}={imm}", int(imm)
                if name in ("f32.const", "f64.const"):
                    return f"{name[:3]}={imm:.6g}", None
                if name in ("ref.func", "ref.null", "global.get"):
                    return f"{name}={imm}", None
        parts = []
        for name, imms in insns:
            parts.append(
                " ".join([name] + [_format_const_immediate(v) for v in imms])
            )
        return " ".join(parts), None


# Absolute heap-type byte → name (§5.2)
_ABS_HEAP_TYPES = {
    0x69: "exn",
    0x6A: "array",
    0x6B: "struct",
    0x6C: "i31",
    0x6D: "eq",
    0x6E: "any",
    0x6F: "extern",
    0x70: "func",
    0x71: "none",
    0x72: "noextern",
    0x73: "nofunc",
    0x74: "noexn",
}

# Valtype byte → name (§5.2)
_VAL_TYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
    # GC compact ref types (listed via reftype grammar)
    0x6E: "anyref",
    0x6D: "eqref",
    0x6C: "i31ref",
    0x6B: "structref",
    0x6A: "arrayref",
    0x69: "exnref",
    0x71: "nullref",
    0x72: "nullexternref",
    0x73: "nullfuncref",
    0x74: "nullexnref",
    # explicit nullable/non-nullable reference prefixes handled elsewhere
    0x63: "ref_null",
    0x64: "ref",
}


class BinaryReader:
    def __init__(self, data: bytes, delegate: Any) -> None:
        """Create a binary reader that forwards parse events to a delegate."""
        self.data = data
        self.size = len(data)
        self.offset = 0
        self.delegate = delegate
        # Imported entities shift indices for locally-defined section entries.
        self.imported_function_count = 0
        self.imported_table_count = 0
        self.imported_memory_count = 0
        self.imported_global_count = 0
        self.imported_tag_count = 0
        # End of the section being decoded; bounds constant expressions.
        self._section_end = self.size

    # ─── Primitive readers ───────────────────────────────────────────────────

    def _ensure(self, n: int) -> None:
        if self.offset + n > self.size:
            raise WasmParseError("Unexpected end of file")

    def read_u8(self) -> int:
        self._ensure(1)
        val = self.data[self.offset]
        self.offset += 1
        return val

    def peek_u8(self) -> int:
        """Return the byte at the cursor without consuming it.

        Bounds-checked on purpose: peeking past the end must raise
        ``WasmParseError`` like every other reader, so section decoders report
        truncation through ``on_error`` instead of leaking an ``IndexError``
        into the generic per-section handler, which swallows it silently.
        """
        self._ensure(1)
        return self.data[self.offset]

    def read_u32(self) -> int:
        self._ensure(4)
        val = struct.unpack_from("<I", self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_leb128(self, signed: bool = False, max_bits: int = 64) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if shift > max_bits + 7:
                raise WasmParseError("LEB128 exceeds maximum allowed length")
            if not (byte & 0x80):
                if signed and (byte & 0x40):
                    result |= ~0 << shift
                break
        if signed and result >= (1 << (max_bits - 1)):
            result -= 1 << max_bits
        return result

    def read_f32(self) -> float:
        self._ensure(4)
        val = struct.unpack_from("<f", self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_f64(self) -> float:
        self._ensure(8)
        val = struct.unpack_from("<d", self.data, self.offset)[0]
        self.offset += 8
        return val

    def read_string(self) -> str:
        length = self.read_leb128(max_bits=32)
        self._ensure(length)
        s_bytes = self.data[self.offset : self.offset + length]
        self.offset += length
        return s_bytes.decode("utf-8", errors="replace")

    def read_bytes(self, n: int) -> bytes:
        self._ensure(n)
        b = self.data[self.offset : self.offset + n]
        self.offset += n
        return b

    # ─── Type helpers ────────────────────────────────────────────────────────

    def read_heaptype(self) -> str:
        """Read a heaptype (abs byte or s33 type index)."""
        byte = self.peek_u8()
        if byte in _ABS_HEAP_TYPES:
            self.offset += 1
            return _ABS_HEAP_TYPES[byte]
        # s33: positive value means a type index
        idx = self.read_leb128(signed=True, max_bits=33)
        if idx >= 0:
            return f"type[{idx}]"
        # fallback: map negative bytes used as shorthand abs heap types
        raw = idx & 0xFF
        return _ABS_HEAP_TYPES.get(raw, f"heaptype({raw:#x})")

    def read_reftype(self) -> str:
        """Read a reference type (§5.2 Breftype)."""
        byte = self.peek_u8()
        if byte == 0x63:
            self.offset += 1
            ht = self.read_heaptype()
            return f"(ref null {ht})"
        if byte == 0x64:
            self.offset += 1
            ht = self.read_heaptype()
            return f"(ref {ht})"
        # abs heap type shorthand (nullable by default per spec)
        if byte in _ABS_HEAP_TYPES:
            self.offset += 1
            return _ABS_HEAP_TYPES.get(byte, f"ref({byte:#x})")
        # fallthrough to abs heap type
        return self.read_heaptype()

    def read_valtype(self) -> str:
        """Read one value type byte and return its name."""
        byte = self.peek_u8()
        if byte in _VAL_TYPES:
            self.offset += 1
            name = _VAL_TYPES[byte]
            if name == "ref_null":
                ht = self.read_heaptype()
                return f"(ref null {ht})"
            if name == "ref":
                ht = self.read_heaptype()
                return f"(ref {ht})"
            return name
        # GC reftype
        return self.read_reftype()

    def read_blocktype(self) -> Tuple[int, Optional[str]]:
        """Read a block type; return (signed integer, reference type or None).

        A block type is 0x40 (empty), a value type, or an s33 type index.
        Reference value types (0x63 ``ref null`` and 0x64 ``ref``) carry a
        heap type after the prefix byte. It is consumed here so the decoder
        stays in sync; the integer is the prefix's signed value (-29 or -28)
        and the second element names the full type, for example
        ``(ref null type[0])``.
        """
        byte = self.peek_u8()
        if byte in (0x63, 0x64):
            return byte - 0x80, self.read_valtype()
        return self.read_leb128(signed=True, max_bits=33), None

    def read_limits(self) -> Tuple[int, Any, bool, bool, Optional[int]]:
        """Return (minimum, maximum_or_None, is_64, shared, page_size_log2_or_None).

        Limits flags are a bitfield:
          bit0 => has max, bit1 => shared, bit2 => 64-bit index type,
          bit3 => custom page size present (custom-page-sizes proposal),
        in which case a u32 ``page_size_log2`` follows the limits.
        """
        flag = self.read_u8()
        has_max = bool(flag & 0x01)
        shared = bool(flag & 0x02)
        is_64 = bool(flag & 0x04)
        has_page_size = bool(flag & 0x08)
        minimum = self.read_leb128(max_bits=64)
        maximum = None
        if has_max:
            maximum = self.read_leb128(max_bits=64)
        page_size_log2 = None
        if has_page_size:
            page_size_log2 = self.read_leb128(max_bits=32)
        return minimum, maximum, is_64, shared, page_size_log2

    def read_globaltype(self) -> Tuple[str, bool]:
        """Return (valtype_name, mutable)."""
        vt = self.read_valtype()
        mut = self.read_u8()
        return vt, bool(mut)

    def read_init_expr(
        self, end_offset: Optional[int] = None
    ) -> Tuple[str, Optional[int]]:
        """Read a constant expression up to its matching 0x0B ``end``.

        The expression is decoded with the normal instruction decoder, so
        extended-const arithmetic (``i32.add`` of two operands) and GC
        constructors (``struct.new``, ``array.new_fixed``, ``ref.i31``) keep
        the section in sync. Decoding stops at ``end_offset`` (the enclosing
        section end by default) and raises when no ``end`` is found before it.

        Returns (readable text, numeric value or None). A lone constant keeps
        the short forms ``i32=7``, ``i64=7``, ``f32=1.5``, ``f64=1.5``,
        ``ref.func=3``, ``ref.null=func`` and ``global.get=0``; any other
        expression is its instructions in WAT order separated by spaces, for
        example ``i32.const 1 global.get 0 i32.add``. The value is set only
        for a lone ``i32.const`` or ``i64.const``, which data segments need
        for their offset.
        """
        if end_offset is None:
            end_offset = self._section_end
        end_offset = min(end_offset, self.size)
        recorder = _ConstExprRecorder()
        saved = self.delegate
        self.delegate = recorder
        try:
            self.read_instructions(end_offset)
        finally:
            self.delegate = saved
        if not recorder.closed or self.offset > end_offset:
            raise WasmParseError("Constant expression is not terminated by end")
        return recorder.result()

    # ─── Public entry points ─────────────────────────────────────────────────

    def read_module(self) -> None:
        try:
            self._do_read_module()
        except WasmParseError as e:
            if hasattr(self.delegate, "on_error"):
                self.delegate.on_error(str(e))

    def _do_read_module(self) -> None:
        if self.size < 8:
            raise WasmParseError("File too small to be a WebAssembly module")
        if self.read_u32() != 0x6D736100:
            raise WasmParseError("Bad magic value")
        version = self.read_u32()
        self.delegate.begin_module(version)

        section_index = 0
        while self.offset < self.size:
            section_id = self.read_u8()
            section_size = self.read_leb128(max_bits=32)
            end_offset = self.offset + section_size
            if end_offset > self.size:
                raise WasmParseError("Section length extends beyond file boundary")

            self.delegate.offset = self.offset
            self.delegate.begin_section(section_index, section_id, section_size)
            self._section_end = end_offset

            try:
                self._decode_section(section_index, section_id, end_offset)
            except WasmParseError:
                raise
            except Exception:
                pass  # skip broken sections gracefully

            self.offset = end_offset
            section_index += 1

    def _decode_section(
        self, section_index: int, section_id: int, end_offset: int
    ) -> None:
        if section_id == BinarySection.CUSTOM:
            self._decode_custom(section_index, end_offset)
        elif section_id == BinarySection.TYPE:
            self._decode_type(end_offset)
        elif section_id == BinarySection.IMPORT:
            self._decode_import(end_offset)
        elif section_id == BinarySection.FUNCTION:
            self._decode_function(end_offset)
        elif section_id == BinarySection.TABLE:
            self._decode_table(end_offset)
        elif section_id == BinarySection.MEMORY:
            self._decode_memory(end_offset)
        elif section_id == BinarySection.GLOBAL:
            self._decode_global(end_offset)
        elif section_id == BinarySection.EXPORT:
            self._decode_export(end_offset)
        elif section_id == BinarySection.START:
            self._decode_start(end_offset)
        elif section_id == BinarySection.ELEMENT:
            self._decode_element(end_offset)
        elif section_id == BinarySection.CODE:
            self._decode_code(end_offset)
        elif section_id == BinarySection.DATA:
            self._decode_data(end_offset)
        elif section_id == BinarySection.DATA_COUNT:
            self._decode_data_count(end_offset)
        elif section_id == BinarySection.TAG:
            self._decode_tag(end_offset)

    # ─── Section decoders ────────────────────────────────────────────────────

    def _decode_custom(self, section_index: int, end_offset: int) -> None:
        name = self.read_string()
        self.delegate.begin_custom_section(
            section_index, end_offset - self.offset, name
        )
        if name == "name":
            while self.offset < end_offset:
                sub_id = self.read_u8()
                sub_size = self.read_leb128(max_bits=32)
                sub_end = self.offset + sub_size
                if sub_id == 1:  # function names
                    count = self.read_leb128(max_bits=32)
                    for _ in range(count):
                        idx = self.read_leb128(max_bits=32)
                        fname = self.read_string()
                        if hasattr(self.delegate, "on_function_name"):
                            self.delegate.on_function_name(idx, fname)
                elif sub_id == 2:  # local names
                    count = self.read_leb128(max_bits=32)
                    for _ in range(count):
                        func_idx = self.read_leb128(max_bits=32)
                        local_count = self.read_leb128(max_bits=32)
                        for _ in range(local_count):
                            local_idx = self.read_leb128(max_bits=32)
                            lname = self.read_string()
                            if hasattr(self.delegate, "on_local_name"):
                                self.delegate.on_local_name(func_idx, local_idx, lname)
                self.offset = sub_end
        elif name == "producers":
            # Tool-conventions ProducersSection.md:
            #   vec(field); field ::= field_name:str vec((name:str, version:str))
            try:
                field_count = self.read_leb128(max_bits=32)
                for _ in range(field_count):
                    field_name = self.read_string()
                    entry_count = self.read_leb128(max_bits=32)
                    entries = []
                    for _ in range(entry_count):
                        prod_name = self.read_string()
                        prod_version = self.read_string()
                        entries.append((prod_name, prod_version))
                    if hasattr(self.delegate, "on_producers_field"):
                        self.delegate.on_producers_field(field_name, entries)
            except WasmParseError:
                pass  # malformed producers section: abandon rest of payload
        elif name == "target_features":
            # Tool-conventions Linking.md:
            #   vec(feature); feature ::= prefix:byte name:str
            #   prefix 0x2B ('+') = feature used, 0x2D ('-') = feature not used.
            try:
                feature_count = self.read_leb128(max_bits=32)
                for _ in range(feature_count):
                    prefix = self.read_u8()
                    feature_name = self.read_string()
                    enabled = prefix == 0x2B
                    if hasattr(self.delegate, "on_target_feature"):
                        self.delegate.on_target_feature(enabled, feature_name)
            except WasmParseError:
                pass  # malformed target_features section: abandon rest of payload
        elif name.startswith(".debug_") and hasattr(self.delegate, "on_debug_section"):
            # DWARF debug sections are stored verbatim; the name is enough for
            # detection, and .debug_str payloads feed string extraction. The
            # payload is handed over as a zero-copy memoryview because DWARF
            # dominates unstripped builds (tens of MB in ffmpeg-class
            # binaries); delegates that keep a payload must copy it themselves.
            self.delegate.on_debug_section(
                name, memoryview(self.data)[self.offset : end_offset]
            )
        elif name == "metadata.code.branch_hint" and hasattr(
            self.delegate, "on_branch_hints"
        ):
            # Branch hinting proposal (tool-conventions CodeMetadata.md).
            # Full decode lives in the custom section catalog; a malformed
            # payload degrades to an error string without costing the rest
            # of the module.
            info = parse_branch_hints(self.data[self.offset : end_offset])
            if info is not None:
                info["name"] = name
                self.delegate.on_branch_hints(info)
            else:
                self.delegate.on_error(
                    "malformed metadata.code.branch_hint custom section"
                )
        elif name in ("dylink.0", "dylink") and hasattr(
            self.delegate, "on_dylink_section"
        ):
            # Emscripten dynamic linking ABI (tool-conventions
            # DynamicLinking.md). The needed-libraries list is a literal
            # dependency declaration, so a parse failure is reported but the
            # module keeps walking.
            payload = self.data[self.offset : end_offset]
            info = (
                parse_dylink(payload)
                if name == "dylink.0"
                else parse_dylink_legacy(payload)
            )
            if info is not None:
                info["name"] = name
                self.delegate.on_dylink_section(info)
            else:
                self.delegate.on_error(f"malformed {name} custom section")
        elif name == "linking" and hasattr(self.delegate, "on_linking_section"):
            # LLVM/lld object-file wasm (tool-conventions Linking.md): the
            # symbol table is the only name source in object files built
            # without a name section.
            info = parse_linking(self.data[self.offset : end_offset])
            if info is not None:
                info["name"] = name
                self.delegate.on_linking_section(info)
            else:
                self.delegate.on_error("malformed linking custom section")
        elif (name == "component-type" or name.startswith("component-type:")) and hasattr(
            self.delegate, "on_component_type_section"
        ):
            info = parse_component_type(self.data[self.offset : end_offset])
            if info is not None:
                info["name"] = name
                self.delegate.on_component_type_section(info)
        elif name == "core" and hasattr(self.delegate, "on_core_coredump"):
            # Coredump convention (tool-conventions Coredump.md): presence
            # alone is the signal; the payload is runtime-specific.
            self.delegate.on_core_coredump()

    def _read_comptype(self) -> Tuple[str, List[str], List[str]]:
        """Read one subtype/composite type; return (kind, params, results).

        ``kind`` is ``func``, ``struct``, or ``array``; composite kinds carry
        no signature, so params/results are empty for them.
        """
        tag = self.read_u8()
        if tag == 0x60:
            param_count = self.read_leb128(max_bits=32)
            params = [self.read_valtype() for _ in range(param_count)]
            result_count = self.read_leb128(max_bits=32)
            results = [self.read_valtype() for _ in range(result_count)]
            return "func", params, results
        if tag in (0x4F, 0x50):  # sub (final), sub (open)
            supertype_count = self.read_leb128(max_bits=32)
            for _ in range(supertype_count):
                self.read_leb128(max_bits=32)  # typeidx
            return self._read_comptype()
        if tag == 0x5E:  # array
            self.read_valtype()
            self.read_u8()  # mut
            return "array", [], []
        if tag == 0x5F:  # struct
            field_count = self.read_leb128(max_bits=32)
            for _ in range(field_count):
                self.read_valtype()
                self.read_u8()
            return "struct", [], []
        raise WasmParseError(f"unknown type definition tag {tag:#x}")

    def _read_rectype(
        self, end_offset: Optional[int] = None
    ) -> List[Tuple[str, List[str], List[str]]]:
        """Read one type-section entry, flattening GC rec groups.

        Every member of a rec group occupies its own slot in the module's
        type index space, so a rec entry expands to one result per member.
        Rec groups do not nest (their members are subtypes), so members are
        read as plain composite types; that also bounds recursion depth.
        """
        limit = self.size if end_offset is None else min(end_offset, self.size)
        if self.offset >= limit:
            raise WasmParseError("ended before the next type entry")
        if self.peek_u8() == 0x4E:  # rec
            self.read_u8()
            count = self.read_leb128(max_bits=32)
            entries: List[Tuple[str, List[str], List[str]]] = []
            for _ in range(count):
                if self.offset >= limit:
                    raise WasmParseError("rec group ended before its last member")
                entries.append(self._read_comptype())
            return entries
        return [self._read_comptype()]

    def _decode_type(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        index = 0
        try:
            for _ in range(count):
                for kind, params, results in self._read_rectype(end_offset):
                    if hasattr(self.delegate, "on_type_kind"):
                        self.delegate.on_type_kind(index, kind)
                    if hasattr(self.delegate, "on_type"):
                        self.delegate.on_type(index, params, results)
                    index += 1
        except WasmParseError as exc:
            # An unknown composite form or truncated payload makes the rest
            # of the section undecodable; report and skip to the section end
            # instead of desynchronizing every later type index.
            if hasattr(self.delegate, "on_error"):
                self.delegate.on_error(f"type section: {exc}")
            self.offset = end_offset

    def _decode_import(self, end_offset: int) -> None:
        """Decode the import section, including compact import groups.

        The compact-imports proposal adds two grouped encodings after the
        module name, both introduced by an empty item name: ``0x7F`` followed
        by a vector of (name, externtype) pairs, and ``0x7E`` followed by one
        externtype shared by a vector of names. Each item in a group is
        reported to the delegate as an ordinary import, numbered in order.
        """
        count = self.read_leb128(max_bits=32)
        counters = {"func": 0, "table": 0, "memory": 0, "global": 0, "tag": 0}
        import_index = 0

        def emit(module: str, name: str, kind: str, extra: dict) -> None:
            nonlocal import_index
            if kind in counters:
                extra["entity_index"] = counters[kind]
                counters[kind] += 1
            if hasattr(self.delegate, "on_import"):
                self.delegate.on_import(import_index, module, name, kind, **extra)
            import_index += 1

        for _ in range(count):
            module = self.read_string()
            name = self.read_string()
            if name == "" and self.peek_u8() in (0x7E, 0x7F):
                form = self.read_u8()
                if form == 0x7F:
                    n = self.read_leb128(max_bits=32)
                    for _ in range(n):
                        item_name = self.read_string()
                        kind, extra = self._read_externtype()
                        emit(module, item_name, kind, extra)
                else:
                    kind, extra = self._read_externtype()
                    n = self.read_leb128(max_bits=32)
                    for _ in range(n):
                        emit(module, self.read_string(), kind, dict(extra))
                continue
            kind, extra = self._read_externtype()
            emit(module, name, kind, extra)
        self.imported_function_count = counters["func"]
        self.imported_table_count = counters["table"]
        self.imported_memory_count = counters["memory"]
        self.imported_global_count = counters["global"]
        self.imported_tag_count = counters["tag"]

    def _read_externtype(self) -> Tuple[str, dict]:
        """Read an import's external type; return (kind name, details)."""
        kind_byte = self.read_u8()
        kind = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}.get(
            kind_byte, "unknown"
        )
        extra: dict = {}
        if kind_byte == 0:
            extra["type_index"] = self.read_leb128(max_bits=32)
        elif kind_byte == 1:
            extra["ref_type"] = self.read_reftype()
            mn, mx, is64, shared, ps_log2 = self.read_limits()
            extra["limits_min"] = mn
            extra["limits_max"] = mx
            extra["limits_64"] = is64
            extra["limits_shared"] = shared
            extra["limits_page_size_log2"] = ps_log2
        elif kind_byte == 2:
            mn, mx, is64, shared, ps_log2 = self.read_limits()
            extra["limits_min"] = mn
            extra["limits_max"] = mx
            extra["limits_64"] = is64
            extra["limits_shared"] = shared
            extra["limits_page_size_log2"] = ps_log2
        elif kind_byte == 3:
            vt, mut = self.read_globaltype()
            extra["valtype"] = vt
            extra["mutable"] = mut
        elif kind_byte == 4:
            self.read_u8()  # 0x00 attribute
            extra["type_index"] = self.read_leb128(max_bits=32)
        return kind, extra

    def _decode_function(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            sig_idx = self.read_leb128(max_bits=32)
            if hasattr(self.delegate, "on_function"):
                self.delegate.on_function(self.imported_function_count + i, sig_idx)

    def _decode_table(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            # MVP: just reftype + limits; MVP2 allows 0x40 0x00 prefix + init
            # A table with an explicit initializer is 0x40 0x00 tabletype
            # expr (function-references proposal).
            has_init = self.peek_u8() == 0x40
            if has_init:
                self.read_u8()  # 0x40
                if self.read_u8() != 0x00:
                    raise WasmParseError("Malformed table initializer prefix")
            ref_type = self.read_reftype()
            mn, mx, is64, shared, ps_log2 = self.read_limits()
            init_expr = self.read_init_expr()[0] if has_init else None
            if hasattr(self.delegate, "on_table"):
                kwargs: dict = {"shared": shared, "page_size_log2": ps_log2}
                if init_expr is not None and _accepts_keyword(
                    self.delegate.on_table, "init_expr"
                ):
                    kwargs["init_expr"] = init_expr
                self.delegate.on_table(
                    self.imported_table_count + i,
                    ref_type,
                    mn,
                    mx,
                    is64,
                    **kwargs,
                )

    def _decode_memory(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            mn, mx, is64, shared, ps_log2 = self.read_limits()
            if hasattr(self.delegate, "on_memory"):
                self.delegate.on_memory(
                    self.imported_memory_count + i,
                    mn,
                    mx,
                    is64,
                    shared=shared,
                    page_size_log2=ps_log2,
                )

    def _decode_global(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            vt, mut = self.read_globaltype()
            init_expr, _ = self.read_init_expr()
            if hasattr(self.delegate, "on_global"):
                self.delegate.on_global(
                    self.imported_global_count + i, vt, mut, init_expr
                )

    def _decode_export(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            name = self.read_string()
            kind_byte = self.read_u8()
            kind = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}.get(
                kind_byte, "unknown"
            )
            ref_index = self.read_leb128(max_bits=32)
            if hasattr(self.delegate, "on_export"):
                self.delegate.on_export(i, name, kind, ref_index)

    def _decode_start(self, end_offset: int) -> None:
        func_idx = self.read_leb128(max_bits=32)
        if hasattr(self.delegate, "on_start"):
            self.delegate.on_start(func_idx)

    def _decode_element(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            seg_type = self.read_leb128(max_bits=32)
            mode = "active"
            table_idx = 0
            offset_expr = "i32=0"
            ref_type = "funcref"
            func_indices: List[int] = []

            if seg_type == 0:
                offset_expr, _ = self.read_init_expr()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 1:
                mode = "passive"
                _kind = self.read_u8()  # elemkind (0x00 = funcref)
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 2:
                table_idx = self.read_leb128(max_bits=32)
                offset_expr, _ = self.read_init_expr()
                _kind = self.read_u8()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 3:
                mode = "declarative"
                _kind = self.read_u8()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 4:
                offset_expr, _ = self.read_init_expr()
                n = self.read_leb128(max_bits=32)
                ref_type = "funcref"
                # each entry is an init expr
                for _ in range(n):
                    self.read_init_expr()
            elif seg_type == 5:
                mode = "passive"
                ref_type = self.read_reftype()
                n = self.read_leb128(max_bits=32)
                for _ in range(n):
                    self.read_init_expr()
            elif seg_type == 6:
                table_idx = self.read_leb128(max_bits=32)
                offset_expr, _ = self.read_init_expr()
                ref_type = self.read_reftype()
                n = self.read_leb128(max_bits=32)
                for _ in range(n):
                    self.read_init_expr()
            elif seg_type == 7:
                mode = "declarative"
                ref_type = self.read_reftype()
                n = self.read_leb128(max_bits=32)
                for _ in range(n):
                    self.read_init_expr()
            else:
                n = 0

            if hasattr(self.delegate, "on_element"):
                self.delegate.on_element(
                    i,
                    mode,
                    ref_type,
                    table_idx,
                    offset_expr,
                    len(func_indices),
                    func_indices,
                )

    def _decode_code(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            body_size = self.read_leb128(max_bits=32)
            b_end = self.offset + body_size
            func_idx = self.imported_function_count + i
            # The body's file offset (the locals vector, just past the size
            # field) is where DWARF low_pc and line rows point; delegates
            # read it as an attribute, so the callback signature is unchanged.
            self.delegate.function_body_offset = self.offset
            if hasattr(self.delegate, "begin_function_body"):
                self.delegate.begin_function_body(func_idx, body_size)

            local_decl_count = self.read_leb128(max_bits=32)
            locals_list: List[Tuple[int, str]] = []
            for _ in range(local_decl_count):
                lcount = self.read_leb128(max_bits=32)
                ltype = self.read_valtype()
                locals_list.append((lcount, ltype))
                if hasattr(self.delegate, "on_local_decl"):
                    self.delegate.on_local_decl(
                        func_idx, len(locals_list) - 1, lcount, ltype
                    )

            self.read_instructions(b_end)
            if hasattr(self.delegate, "end_function_body"):
                self.delegate.end_function_body(func_idx)

    def _decode_data(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            seg_type = self.read_leb128(max_bits=32)
            mem_idx = 0
            offset_expr = "i32=0"
            offset_value: Optional[int] = None
            if seg_type == 0:
                offset_expr, offset_value = self.read_init_expr()
            elif seg_type == 1:
                pass  # passive
            elif seg_type == 2:
                mem_idx = self.read_leb128(max_bits=32)
                offset_expr, offset_value = self.read_init_expr()
            n = self.read_leb128(max_bits=32)
            data_bytes = self.read_bytes(n)
            mode = "passive" if seg_type == 1 else "active"
            if hasattr(self.delegate, "on_data"):
                self.delegate.on_data(
                    i,
                    mode,
                    mem_idx,
                    offset_expr,
                    n,
                    data_bytes,
                    offset_value=offset_value,
                )

    def _decode_data_count(self, end_offset: int) -> None:
        n = self.read_leb128(max_bits=32)
        if hasattr(self.delegate, "on_data_count"):
            self.delegate.on_data_count(n)

    def _decode_tag(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            self.read_u8()  # attribute (always 0x00)
            type_idx = self.read_leb128(max_bits=32)
            if hasattr(self.delegate, "on_tag"):
                self.delegate.on_tag(self.imported_tag_count + i, type_idx)

    # ─── Instruction decoder ─────────────────────────────────────────────────

    def read_instructions(self, end_offset: int) -> None:
        """Decode instructions until the function body expression is closed."""
        depth = 1
        while self.offset < end_offset:
            self.delegate.offset = self.offset
            byte = self.read_u8()
            # Prefixed opcode families: next u32 LEB is the sub-opcode.
            prefix = byte if byte in (0xFB, 0xFC, 0xFD, 0xFE) else 0
            if prefix:
                byte = self.read_leb128(max_bits=32)

            op_name, imm_type = OPCODES.get(
                (prefix, byte), (f"unknown_{prefix:02x}_{byte:02x}", ImmType.NONE)
            )

            mock_op = MockOpcode(op_name)
            self.delegate.current_opcode = mock_op
            if hasattr(self.delegate, "on_opcode"):
                self.delegate.on_opcode(mock_op)

            # ── Immediate dispatch ───────────────────────────────────────────
            if imm_type == ImmType.NONE:
                if byte == 0x0B and prefix == 0:  # END
                    depth -= 1
                    if hasattr(self.delegate, "on_end_expr"):
                        self.delegate.on_end_expr()
                    if depth == 0:
                        break
                else:
                    if hasattr(self.delegate, "on_opcode_bare"):
                        self.delegate.on_opcode_bare()

            elif imm_type == ImmType.BLOCK_SIG:
                depth += 1
                sig, sig_ref = self.read_blocktype()
                if hasattr(self.delegate, "on_opcode_block_sig"):
                    if sig_ref is not None and _accepts_keyword(
                        self.delegate.on_opcode_block_sig, "ref_type"
                    ):
                        self.delegate.on_opcode_block_sig(sig, ref_type=sig_ref)
                    else:
                        self.delegate.on_opcode_block_sig(sig)

            elif imm_type == ImmType.INDEX:
                idx = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_index"):
                    self.delegate.on_opcode_index(idx)

            elif imm_type == ImmType.I32:
                val = self.read_leb128(signed=True, max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32"):
                    self.delegate.on_opcode_uint32(val)

            elif imm_type == ImmType.I64:
                val = self.read_leb128(signed=True, max_bits=64)
                if hasattr(self.delegate, "on_opcode_uint64"):
                    self.delegate.on_opcode_uint64(val)

            elif imm_type == ImmType.F32:
                val = self.read_f32()
                if hasattr(self.delegate, "on_opcode_f32"):
                    self.delegate.on_opcode_f32(val)

            elif imm_type == ImmType.F64:
                val = self.read_f64()
                if hasattr(self.delegate, "on_opcode_f64"):
                    self.delegate.on_opcode_f64(val)

            elif imm_type == ImmType.MEMARG:
                # Multi-memory: bit 6 of the align field signals an explicit
                # memory index that follows (multi-memory proposal).
                align = self.read_leb128(max_bits=32)
                mem_idx = None
                if align & 0x40:
                    align &= ~0x40
                    mem_idx = self.read_leb128(max_bits=32)
                # memory64 extends memarg offsets from u32 to u64.
                mem_offset = self.read_leb128(max_bits=64)
                if hasattr(self.delegate, "on_opcode_memarg"):
                    self.delegate.on_opcode_memarg(align, mem_offset, mem_idx)
                elif hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(align, mem_offset)

            elif imm_type == ImmType.BR_TABLE:
                n = self.read_leb128(max_bits=32)
                targets = [self.read_leb128(max_bits=32) for _ in range(n)]
                default = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_br_table"):
                    self.delegate.on_opcode_br_table(targets, default)
                elif hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()

            elif imm_type == ImmType.CALL_INDIRECT:
                sig_idx = self.read_leb128(max_bits=32)
                table_idx = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_call_indirect_expr"):
                    self.delegate.on_call_indirect_expr(sig_idx, table_idx)

            elif imm_type == ImmType.MEMORY_INIT:
                data_idx = self.read_leb128(max_bits=32)
                mem_idx = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(mem_idx, data_idx)

            elif imm_type == ImmType.MEMORY_COPY:
                d = self.read_leb128(max_bits=32)
                s = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(d, s)

            elif imm_type == ImmType.SELECT_T:
                # typed select: vec of val types
                n = self.read_leb128(max_bits=32)
                types = [self.read_valtype() for _ in range(n)]
                if hasattr(self.delegate, "on_opcode_select_t"):
                    self.delegate.on_opcode_select_t(types)
                elif hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()

            elif imm_type == ImmType.HEAP_TYPE:
                ht = self.read_heaptype()
                if hasattr(self.delegate, "on_opcode_heap_type"):
                    self.delegate.on_opcode_heap_type(ht)
                elif hasattr(self.delegate, "on_opcode_index"):
                    self.delegate.on_opcode_index(0)

            elif imm_type == ImmType.TWO_INDICES:
                a = self.read_leb128(max_bits=32)
                b = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(a, b)

            elif imm_type == ImmType.TABLE_INIT:
                elem_idx = self.read_leb128(max_bits=32)
                table_idx = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(elem_idx, table_idx)

            elif imm_type == ImmType.TABLE_COPY:
                dst = self.read_leb128(max_bits=32)
                src = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(dst, src)

            elif imm_type == ImmType.V128_CONST:
                raw = self.read_bytes(16)
                if hasattr(self.delegate, "on_opcode_v128"):
                    self.delegate.on_opcode_v128(raw)
                elif hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()

            elif imm_type == ImmType.V128_SHUFFLE:
                lanes = list(self.read_bytes(16))
                if hasattr(self.delegate, "on_opcode_v128_shuffle"):
                    self.delegate.on_opcode_v128_shuffle(lanes)
                elif hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()

            elif imm_type == ImmType.LANE_IDX:
                lane = self.read_u8()
                if hasattr(self.delegate, "on_opcode_lane_idx"):
                    self.delegate.on_opcode_lane_idx(lane)
                elif hasattr(self.delegate, "on_opcode_index"):
                    self.delegate.on_opcode_index(lane)

            elif imm_type == ImmType.MEMARG_LANE:
                # The lane forms carry a full memarg, so the multi-memory
                # bit 6 applies here exactly as on plain loads and stores:
                # align, then the memory index when the bit is set, then the
                # offset, then the lane byte.
                align = self.read_leb128(max_bits=32)
                mem_idx = None
                if align & 0x40:
                    align &= ~0x40
                    mem_idx = self.read_leb128(max_bits=32)
                mem_offset = self.read_leb128(max_bits=64)
                lane = self.read_u8()
                if hasattr(self.delegate, "on_opcode_memarg_lane"):
                    if mem_idx is not None and _accepts_keyword(
                        self.delegate.on_opcode_memarg_lane, "mem_idx"
                    ):
                        self.delegate.on_opcode_memarg_lane(
                            align, mem_offset, lane, mem_idx=mem_idx
                        )
                    else:
                        self.delegate.on_opcode_memarg_lane(align, mem_offset, lane)
                elif hasattr(self.delegate, "on_opcode_uint32_uint32"):
                    self.delegate.on_opcode_uint32_uint32(align, mem_offset)

            elif imm_type == ImmType.BR_ON_CAST:
                flags = self.read_u8()
                label = self.read_leb128(max_bits=32)
                ht1 = self.read_heaptype()
                ht2 = self.read_heaptype()
                if hasattr(self.delegate, "on_opcode_br_on_cast"):
                    self.delegate.on_opcode_br_on_cast(flags, label, ht1, ht2)
                elif hasattr(self.delegate, "on_opcode_index"):
                    self.delegate.on_opcode_index(label)

            elif imm_type == ImmType.TRY_TABLE_BLOCK:
                depth += 1
                sig, sig_ref = self.read_blocktype()
                catch_count = self.read_leb128(max_bits=32)
                catches = []
                for _ in range(catch_count):
                    catch_op = self.read_u8()
                    # Catch clause kinds: 0x00 catch, 0x01 catch_ref (both
                    # carry a tag index), 0x02 catch_all, 0x03
                    # catch_all_ref. Anything else is malformed; reading a
                    # label for it would desynchronise the decoder.
                    if catch_op in (0x00, 0x01):
                        tag_idx = self.read_leb128(max_bits=32)
                        lbl = self.read_leb128(max_bits=32)
                        catches.append((catch_op, tag_idx, lbl))
                    elif catch_op in (0x02, 0x03):
                        lbl = self.read_leb128(max_bits=32)
                        catches.append((catch_op, lbl))
                    else:
                        raise WasmParseError(
                            f"unknown try_table catch kind {catch_op:#04x}"
                        )
                if hasattr(self.delegate, "on_opcode_try_table"):
                    if sig_ref is not None and _accepts_keyword(
                        self.delegate.on_opcode_try_table, "ref_type"
                    ):
                        self.delegate.on_opcode_try_table(
                            sig, catches, ref_type=sig_ref
                        )
                    else:
                        self.delegate.on_opcode_try_table(sig, catches)
                elif hasattr(self.delegate, "on_opcode_block_sig"):
                    self.delegate.on_opcode_block_sig(sig)

            elif imm_type == ImmType.ATOMIC_FENCE:
                self.read_u8()  # reserved byte 0x00
                if hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()

            elif imm_type == ImmType.DELEGATE_LABEL:
                # Legacy `delegate` terminates its try block like `end` does,
                # but carries a label index for the enclosing handler depth.
                idx = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_index"):
                    self.delegate.on_opcode_index(idx)
                depth -= 1
                if depth == 0:
                    break
