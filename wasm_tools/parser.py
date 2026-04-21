import struct
from typing import Any, List, Tuple

from .models import BinarySection
from .opcodes import OPCODES, ImmType


class WasmParseError(Exception):
    """Raised for malformed or truncated WebAssembly binary input."""

    pass


class MockOpcode:
    def __init__(self, name: str) -> None:
        """Wrap a decoded opcode name for delegate callbacks."""
        self.name = name


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

    # ─── Primitive readers ───────────────────────────────────────────────────

    def _ensure(self, n: int) -> None:
        if self.offset + n > self.size:
            raise WasmParseError("Unexpected end of file")

    def read_u8(self) -> int:
        self._ensure(1)
        val = self.data[self.offset]
        self.offset += 1
        return val

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
        byte = self.data[self.offset]
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
        byte = self.data[self.offset]
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
        byte = self.data[self.offset]
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

    def read_limits(self) -> Tuple[int, Any, bool]:
        """Return (minimum, maximum_or_None, is_64)."""
        flag = self.read_u8()
        is_64 = flag in (0x04, 0x05)
        minimum = self.read_leb128(max_bits=64)
        maximum = None
        if flag in (0x01, 0x05):
            maximum = self.read_leb128(max_bits=64)
        return minimum, maximum, is_64

    def read_globaltype(self) -> Tuple[str, bool]:
        """Return (valtype_name, mutable)."""
        vt = self.read_valtype()
        mut = self.read_u8()
        return vt, bool(mut)

    def read_init_expr(self) -> str:
        """Read a constant expression (ends at 0x0B) and return a readable string."""
        opcode = self.read_u8()
        if opcode == 0x41:
            val = self.read_leb128(signed=True, max_bits=32)
            self.read_u8()  # 0x0B end
            return f"i32={val}"
        if opcode == 0x42:
            val = self.read_leb128(signed=True, max_bits=64)
            self.read_u8()
            return f"i64={val}"
        if opcode == 0x43:
            val = self.read_f32()
            self.read_u8()
            return f"f32={val:.6g}"
        if opcode == 0x44:
            val = self.read_f64()
            self.read_u8()
            return f"f64={val:.6g}"
        if opcode == 0xD2:
            idx = self.read_leb128(max_bits=32)
            self.read_u8()
            return f"ref.func={idx}"
        if opcode == 0xD0:
            ht = self.read_heaptype()
            self.read_u8()
            return f"ref.null={ht}"
        if opcode == 0x23:
            idx = self.read_leb128(max_bits=32)
            self.read_u8()
            return f"global.get={idx}"
        if opcode == 0xFB:
            sub = self.read_leb128(max_bits=32)
            # ref.i31 / struct.new_default etc. - skip remainder to 0x0B
            # scan forward for end
            while self.offset < self.size:
                b = self.read_u8()
                if b == 0x0B:
                    break
            return f"gc.{sub}"
        # Unknown: scan to 0x0B
        parts = [f"0x{opcode:02x}"]
        while self.offset < self.size:
            b = self.read_u8()
            if b == 0x0B:
                break
            parts.append(f"0x{b:02x}")
        return " ".join(parts)

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

    def _read_functype(self) -> Tuple[List[str], List[str]]:
        """Read one function type (0x60 prefix + param vec + result vec)."""
        tag = self.read_u8()
        if tag == 0x60:
            param_count = self.read_leb128(max_bits=32)
            params = [self.read_valtype() for _ in range(param_count)]
            result_count = self.read_leb128(max_bits=32)
            results = [self.read_valtype() for _ in range(result_count)]
            return params, results
        # GC composite types: SUB / REC wrappers - skip to find 0x60
        # For now, skip sub-type header and recurse
        if tag in (0x4E, 0x4F, 0x50):  # rec, sub final, sub open
            if tag == 0x4E:  # rec: list of subtypes
                count = self.read_leb128(max_bits=32)
                params, results = [], []
                for _ in range(count):
                    params, results = self._read_functype()
                return params, results
            # sub: supertype list + comptype
            count = self.read_leb128(max_bits=32)
            for _ in range(count):
                self.read_leb128(max_bits=32)  # typeidx
            return self._read_functype()
        # comptype array/struct: skip
        if tag == 0x5E:  # array
            self.read_valtype()
            self.read_u8()  # mut
            return [], []
        if tag == 0x5F:  # struct
            count = self.read_leb128(max_bits=32)
            for _ in range(count):
                self.read_valtype()
                self.read_u8()
            return [], []
        return [], []

    def _decode_type(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            params, results = self._read_functype()
            if hasattr(self.delegate, "on_type"):
                self.delegate.on_type(i, params, results)

    def _decode_import(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        func_idx = 0
        table_idx = 0
        mem_idx = 0
        global_idx = 0
        tag_idx = 0
        for i in range(count):
            module = self.read_string()
            name = self.read_string()
            kind_byte = self.read_u8()
            kind = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}.get(
                kind_byte, "unknown"
            )
            extra: dict = {}
            if kind_byte == 0:
                extra["type_index"] = self.read_leb128(max_bits=32)
                extra["entity_index"] = func_idx
                func_idx += 1
            elif kind_byte == 1:
                extra["ref_type"] = self.read_reftype()
                mn, mx, is64 = self.read_limits()
                extra["limits_min"] = mn
                extra["limits_max"] = mx
                extra["limits_64"] = is64
                extra["entity_index"] = table_idx
                table_idx += 1
            elif kind_byte == 2:
                mn, mx, is64 = self.read_limits()
                extra["limits_min"] = mn
                extra["limits_max"] = mx
                extra["limits_64"] = is64
                extra["entity_index"] = mem_idx
                mem_idx += 1
            elif kind_byte == 3:
                vt, mut = self.read_globaltype()
                extra["valtype"] = vt
                extra["mutable"] = mut
                extra["entity_index"] = global_idx
                global_idx += 1
            elif kind_byte == 4:
                self.read_u8()  # 0x00 attribute
                extra["type_index"] = self.read_leb128(max_bits=32)
                extra["entity_index"] = tag_idx
                tag_idx += 1
            if hasattr(self.delegate, "on_import"):
                self.delegate.on_import(i, module, name, kind, **extra)
        self.imported_function_count = func_idx
        self.imported_table_count = table_idx
        self.imported_memory_count = mem_idx
        self.imported_global_count = global_idx
        self.imported_tag_count = tag_idx

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
            byte = self.data[self.offset]
            if byte == 0x40:
                self.read_u8()  # 0x40
                self.read_u8()  # 0x00
            ref_type = self.read_reftype()
            mn, mx, is64 = self.read_limits()
            if hasattr(self.delegate, "on_table"):
                self.delegate.on_table(
                    self.imported_table_count + i, ref_type, mn, mx, is64
                )

    def _decode_memory(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            mn, mx, is64 = self.read_limits()
            if hasattr(self.delegate, "on_memory"):
                self.delegate.on_memory(self.imported_memory_count + i, mn, mx, is64)

    def _decode_global(self, end_offset: int) -> None:
        count = self.read_leb128(max_bits=32)
        for i in range(count):
            vt, mut = self.read_globaltype()
            init_expr = self.read_init_expr()
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
                offset_expr = self.read_init_expr()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 1:
                mode = "passive"
                _kind = self.read_u8()  # elemkind (0x00 = funcref)
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 2:
                table_idx = self.read_leb128(max_bits=32)
                offset_expr = self.read_init_expr()
                _kind = self.read_u8()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 3:
                mode = "declarative"
                _kind = self.read_u8()
                n = self.read_leb128(max_bits=32)
                func_indices = [self.read_leb128(max_bits=32) for _ in range(n)]
            elif seg_type == 4:
                offset_expr = self.read_init_expr()
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
                offset_expr = self.read_init_expr()
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
            if seg_type == 0:
                offset_expr = self.read_init_expr()
            elif seg_type == 1:
                pass  # passive
            elif seg_type == 2:
                mem_idx = self.read_leb128(max_bits=32)
                offset_expr = self.read_init_expr()
            n = self.read_leb128(max_bits=32)
            data_bytes = self.read_bytes(n)
            mode = "passive" if seg_type == 1 else "active"
            if hasattr(self.delegate, "on_data"):
                self.delegate.on_data(i, mode, mem_idx, offset_expr, n, data_bytes)

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
                sig = self.read_leb128(signed=True, max_bits=32)
                if hasattr(self.delegate, "on_opcode_block_sig"):
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
                align = self.read_leb128(max_bits=32)
                mem_offset = self.read_leb128(max_bits=32)
                if hasattr(self.delegate, "on_opcode_uint32_uint32"):
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
                align = self.read_leb128(max_bits=32)
                mem_offset = self.read_leb128(max_bits=32)
                lane = self.read_u8()
                if hasattr(self.delegate, "on_opcode_memarg_lane"):
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
                sig = self.read_leb128(signed=True, max_bits=32)
                catch_count = self.read_leb128(max_bits=32)
                catches = []
                for _ in range(catch_count):
                    catch_op = self.read_u8()
                    if catch_op in (0x00, 0x01):
                        tag_idx = self.read_leb128(max_bits=32)
                        lbl = self.read_leb128(max_bits=32)
                        catches.append((catch_op, tag_idx, lbl))
                    else:
                        lbl = self.read_leb128(max_bits=32)
                        catches.append((catch_op, lbl))
                if hasattr(self.delegate, "on_opcode_try_table"):
                    self.delegate.on_opcode_try_table(sig, catches)
                elif hasattr(self.delegate, "on_opcode_block_sig"):
                    self.delegate.on_opcode_block_sig(sig)

            elif imm_type == ImmType.ATOMIC_FENCE:
                self.read_u8()  # reserved byte 0x00
                if hasattr(self.delegate, "on_opcode_bare"):
                    self.delegate.on_opcode_bare()
