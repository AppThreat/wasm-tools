from typing import Any, List, Optional

from .models import (
    SECTION_NAMES,
    BinarySection,
    DataEntry,
    ElementEntry,
    ExportEntry,
    FuncType,
    GlobalEntry,
    ImportEntry,
    Limits,
    MemoryEntry,
    ObjdumpMode,
    ObjdumpOptions,
    ObjdumpState,
    TableEntry,
    TagEntry,
)


class BinaryReaderNop:
    def begin_module(self, version: int) -> None:
        pass

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        pass

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        pass


class BinaryReaderObjdumpBase(BinaryReaderNop):
    def __init__(
        self, data: bytes, options: ObjdumpOptions, state: ObjdumpState
    ) -> None:
        self.options = options
        self.objdump_state = state
        self.offset = 0
        self.section_starts: dict = {}
        self.current_opcode: Any = None

    def begin_module(self, version: int) -> None:
        if self.options.mode == ObjdumpMode.DETAILS:
            print("\nSection Details:\n")
        elif self.options.mode == ObjdumpMode.DISASSEMBLE:
            print("\nCode Disassembly:\n")
        elif self.options.mode == ObjdumpMode.PREPASS:
            base = self.options.filename or "<stdin>"
            print(f"{base}:\tfile format wasm {version:#x}")

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        self.section_starts[section_code] = self.offset

    def get_print_offset(self, offset: int) -> int:
        if self.options.section_offsets:
            return offset - self.section_starts.get(BinarySection.CODE, 0)
        return offset


class BinaryReaderObjdumpPrepass(BinaryReaderObjdumpBase):
    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        super().begin_section(section_index, section_code, size)
        if section_code != BinarySection.CUSTOM:
            self.objdump_state.section_names[section_index] = SECTION_NAMES.get(
                section_code, "Unknown"
            )

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        self.objdump_state.section_names[section_index] = section_name

    def on_function_name(self, index: int, name: str) -> None:
        self.objdump_state.function_names[index] = name

    def on_local_name(self, func_idx: int, local_idx: int, name: str) -> None:
        self.objdump_state.local_names[(func_idx, local_idx)] = name

    def on_type_kind(self, index: int, kind: str) -> None:
        self.objdump_state.type_kinds[index] = kind

    def on_type(self, index: int, params: List[str], results: List[str]) -> None:
        ft = FuncType(
            params=params,
            results=results,
            kind=self.objdump_state.type_kinds.get(index, "func"),
        )
        # ensure list is big enough
        while len(self.objdump_state.types) <= index:
            self.objdump_state.types.append(FuncType())
        self.objdump_state.types[index] = ft

    def on_import(
        self, index: int, module: str, name: str, kind: str, **kwargs: Any
    ) -> None:
        if kind == "func":
            self.objdump_state.imported_function_count += 1
        elif kind == "table":
            self.objdump_state.imported_table_count += 1
        elif kind == "memory":
            self.objdump_state.imported_memory_count += 1
        elif kind == "global":
            self.objdump_state.imported_global_count += 1
        elif kind == "tag":
            self.objdump_state.imported_tag_count += 1

        entry = ImportEntry(
            index=index,
            module=module,
            name=name,
            kind=kind,
            type_index=kwargs.get("type_index"),
            table_ref_type=kwargs.get("ref_type"),
            table_limits=Limits(
                minimum=kwargs["limits_min"],
                maximum=kwargs.get("limits_max"),
                is_64=kwargs.get("limits_64", False),
                shared=kwargs.get("limits_shared", False),
                page_size_log2=kwargs.get("limits_page_size_log2"),
            )
            if kind == "table"
            else None,
            mem_limits=Limits(
                minimum=kwargs["limits_min"],
                maximum=kwargs.get("limits_max"),
                is_64=kwargs.get("limits_64", False),
                shared=kwargs.get("limits_shared", False),
                page_size_log2=kwargs.get("limits_page_size_log2"),
            )
            if kind == "memory"
            else None,
            global_valtype=kwargs.get("valtype"),
            global_mutable=kwargs.get("mutable", False),
            tag_type_index=kwargs.get("type_index") if kind == "tag" else None,
        )
        while len(self.objdump_state.imports) <= index:
            self.objdump_state.imports.append(None)  # type: ignore
        self.objdump_state.imports[index] = entry

    def on_function(self, index: int, sig_index: int) -> None:
        self.objdump_state.function_types[index] = sig_index

    def on_table(
        self,
        index: int,
        ref_type: str,
        mn: int,
        mx: Any,
        is64: bool,
        shared: bool = False,
        page_size_log2: Optional[int] = None,
    ) -> None:
        entry = TableEntry(
            index=index,
            ref_type=ref_type,
            limits=Limits(mn, mx, is64, shared=shared, page_size_log2=page_size_log2),
        )
        while len(self.objdump_state.tables) <= index:
            self.objdump_state.tables.append(None)  # type: ignore
        self.objdump_state.tables[index] = entry

    def on_memory(
        self,
        index: int,
        mn: int,
        mx: Any,
        is64: bool,
        shared: bool = False,
        page_size_log2: Optional[int] = None,
    ) -> None:
        entry = MemoryEntry(
            index=index,
            limits=Limits(mn, mx, is64, shared=shared, page_size_log2=page_size_log2),
        )
        while len(self.objdump_state.memories) <= index:
            self.objdump_state.memories.append(None)  # type: ignore
        self.objdump_state.memories[index] = entry

    def on_global(
        self, index: int, valtype: str, mutable: bool, init_expr: str
    ) -> None:
        entry = GlobalEntry(
            index=index, valtype=valtype, mutable=mutable, init_expr=init_expr
        )
        while len(self.objdump_state.globals) <= index:
            self.objdump_state.globals.append(None)  # type: ignore
        self.objdump_state.globals[index] = entry

    def on_export(self, index: int, name: str, kind: str, ref_index: int) -> None:
        entry = ExportEntry(index=index, name=name, kind=kind, ref_index=ref_index)
        while len(self.objdump_state.exports) <= index:
            self.objdump_state.exports.append(None)  # type: ignore
        self.objdump_state.exports[index] = entry

    def on_start(self, func_idx: int) -> None:
        self.objdump_state.start_function = func_idx

    def on_element(
        self,
        index: int,
        mode: str,
        ref_type: str,
        table_idx: int,
        offset_expr: str,
        count: int,
        func_indices: List[int],
    ) -> None:
        entry = ElementEntry(
            index=index,
            mode=mode,
            ref_type=ref_type,
            table_index=table_idx,
            offset_expr=offset_expr,
            count=count,
            func_indices=func_indices,
        )
        while len(self.objdump_state.elements) <= index:
            self.objdump_state.elements.append(None)  # type: ignore
        self.objdump_state.elements[index] = entry

    def on_data(
        self,
        index: int,
        mode: str,
        mem_idx: int,
        offset_expr: str,
        size: int,
        data: bytes,
        offset_value: Optional[int] = None,
    ) -> None:
        entry = DataEntry(
            index=index,
            mode=mode,
            memory_index=mem_idx,
            offset_expr=offset_expr,
            size=size,
            data=data,
            offset_value=offset_value,
        )
        while len(self.objdump_state.data_segments) <= index:
            self.objdump_state.data_segments.append(None)  # type: ignore
        self.objdump_state.data_segments[index] = entry

    def on_tag(self, index: int, type_index: int) -> None:
        entry = TagEntry(index=index, type_index=type_index)
        while len(self.objdump_state.tags) <= index:
            self.objdump_state.tags.append(None)  # type: ignore
        self.objdump_state.tags[index] = entry

    def on_data_count(self, count: int) -> None:
        self.objdump_state.data_count = count

    def on_producers_field(self, field: str, entries: List[tuple]) -> None:
        self.objdump_state.producers[field] = [
            (str(n), str(v)) for n, v in entries
        ]

    def on_target_feature(self, enabled: bool, name: str) -> None:
        self.objdump_state.target_features.append((enabled, name))

    # DWARF payloads the source-mapping layer needs. Unstripped builds ship
    # multi-megabyte DWARF, so retention stops at the documented cap.
    _RETAINED_DEBUG_SECTIONS = (".debug_line", ".debug_line_str", ".debug_info")
    _MAX_DWARF_RETENTION = 8 * 1024 * 1024

    def on_debug_section(self, name: str, payload: memoryview) -> None:
        # .debug_str carries analyst-useful strings; the line-mapping layer
        # needs .debug_line, .debug_line_str and .debug_info. The parser
        # hands over a zero-copy view, so retained payloads are copied.
        if name == ".debug_str":
            self.objdump_state.debug_str_payload = bytes(payload)
            return
        if name not in type(self)._RETAINED_DEBUG_SECTIONS:
            return
        retained = getattr(self.objdump_state, "debug_payloads", None)
        if retained is None:
            retained = {}
            self.objdump_state.debug_payloads = retained
        # The budget covers the section being added: one oversized section
        # is skipped (no source mapping) rather than copied in full.
        used = sum(len(value) for value in retained.values())
        if used + len(payload) > type(self)._MAX_DWARF_RETENTION:
            return
        retained[name] = bytes(payload)

    def on_branch_hints(self, info: dict) -> None:
        self.objdump_state.branch_hints = info

    def on_dylink_section(self, info: dict) -> None:
        self.objdump_state.dylink = info

    def on_linking_section(self, info: dict) -> None:
        self.objdump_state.linking = info

    def on_component_type_section(self, info: dict) -> None:
        self.objdump_state.component_type = info

    def on_core_coredump(self) -> None:
        self.objdump_state.coredump = True


class BinaryReaderObjdumpHeaders(BinaryReaderObjdumpBase):
    """Emit a section-header table (wasm-objdump -h style)."""

    def __init__(
        self, data: bytes, options: ObjdumpOptions, state: ObjdumpState
    ) -> None:
        super().__init__(data, options, state)
        self._section_count = 0

    def begin_module(self, version: int) -> None:
        print("\nSections:\n")
        print(f"  {'id':>3} {'name':<16} {'size':>6}  {'offset'}")
        print(f"  {'-' * 3} {'-' * 16} {'-' * 6}  {'-' * 8}")

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        super().begin_section(section_index, section_code, size)
        name = SECTION_NAMES.get(section_code, "Unknown")
        # Custom section names come from the prepass state; wasm-objdump
        # appends the quoted name so DWARF/toolchain sections are identifiable.
        suffix = ""
        if section_code == BinarySection.CUSTOM:
            custom_name = self.objdump_state.section_names.get(section_index)
            if custom_name:
                suffix = f' name: "{custom_name}"'
        off = self.offset
        print(f"  {section_code:3d} {name:<16} {size:6d}  {off:08x}{suffix}")
        self._section_count += 1


class BinaryReaderObjdumpDetails(BinaryReaderObjdumpBase):
    """Print detailed section contents (wasm-objdump -x style)."""

    # ── module banner ──────────────────────────────────────────────────────

    def _count_non_none(self, values: list[Any]) -> int:
        return sum(1 for v in values if v is not None)

    def _section_entry_count(self, section_code: int) -> int:
        state = self.objdump_state
        if section_code == BinarySection.TYPE:
            return self._count_non_none(state.types)
        if section_code == BinarySection.IMPORT:
            return self._count_non_none(state.imports)
        if section_code == BinarySection.FUNCTION:
            return len(state.function_types)
        if section_code == BinarySection.TABLE:
            return self._count_non_none(state.tables)
        if section_code == BinarySection.MEMORY:
            return self._count_non_none(state.memories)
        if section_code == BinarySection.GLOBAL:
            return self._count_non_none(state.globals)
        if section_code == BinarySection.EXPORT:
            return self._count_non_none(state.exports)
        if section_code == BinarySection.START:
            return 1 if state.start_function is not None else 0
        if section_code == BinarySection.ELEMENT:
            return self._count_non_none(state.elements)
        if section_code == BinarySection.CODE:
            return len(state.function_types)
        if section_code == BinarySection.DATA:
            return self._count_non_none(state.data_segments)
        if section_code == BinarySection.DATA_COUNT:
            return 1 if state.data_count is not None else 0
        if section_code == BinarySection.TAG:
            return self._count_non_none(state.tags)
        return 0

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        print(f'\nCustom[{section_index}] "{section_name}":')

    # ── type section ──────────────────────────────────────────────────────

    def on_type(self, index: int, params: List[str], results: List[str]) -> None:
        kind = self.objdump_state.type_kinds.get(index, "func")
        if kind != "func":
            print(f" - type[{index}]: {kind}")
            return
        p = ", ".join(params) if params else ""
        r = ", ".join(results) if results else ""
        print(f" - type[{index}]: ({p}) -> ({r})")

    # ── toolchain custom sections ─────────────────────────────────────────

    def on_producers_field(self, field: str, entries: List[tuple]) -> None:
        for prod_name, prod_version in entries:
            print(f' - {field}: "{prod_name}" "{prod_version}"')

    def on_target_feature(self, enabled: bool, name: str) -> None:
        sign = "+" if enabled else "-"
        print(f" - {sign}{name}")

    # ── import section ────────────────────────────────────────────────────

    def on_import(
        self, index: int, module: str, name: str, kind: str, **kwargs: Any
    ) -> None:
        eidx = kwargs.get("entity_index", index)
        if kind == "func":
            sig = kwargs.get("type_index", "?")
            print(f' - func[{eidx}] sig={sig} <"{module}"."{name}">')
        elif kind == "table":
            rt = kwargs.get("ref_type", "funcref")
            mn = kwargs.get("limits_min", 0)
            mx = kwargs.get("limits_max")
            mx_str = f" max={mx}" if mx is not None else ""
            print(f' - table[{eidx}] {rt} min={mn}{mx_str} <"{module}"."{name}">')
        elif kind == "memory":
            mn = kwargs.get("limits_min", 0)
            mx = kwargs.get("limits_max")
            mx_str = f" max={mx}" if mx is not None else ""
            print(
                f' - memory[{eidx}] pages: initial={mn}{mx_str} <"{module}"."{name}">'
            )
        elif kind == "global":
            vt = kwargs.get("valtype", "?")
            mut = "mutable" if kwargs.get("mutable") else "const"
            print(f' - global[{eidx}] {vt} {mut} <"{module}"."{name}">')
        elif kind == "tag":
            sig = kwargs.get("type_index", "?")
            print(f' - tag[{eidx}] sig={sig} <"{module}"."{name}">')

    # ── function section ──────────────────────────────────────────────────

    def on_function(self, index: int, sig_index: int) -> None:
        name = self.objdump_state.function_names.get(index, "")
        name_str = f" <{name}>" if name else ""
        print(f" - func[{index}]: sig={sig_index}{name_str}")

    # ── table section ─────────────────────────────────────────────────────

    def on_table(
        self,
        index: int,
        ref_type: str,
        mn: int,
        mx: Any,
        is64: bool,
        shared: bool = False,
        page_size_log2: Optional[int] = None,
    ) -> None:
        mx_str = f" max={mx}" if mx is not None else ""
        extra = " shared" if shared else ""
        if page_size_log2 is not None:
            extra += f" pagesize=2^{page_size_log2}"
        print(f" - table[{index}]: {ref_type} min={mn}{mx_str}{extra}")

    # ── memory section ────────────────────────────────────────────────────

    def on_memory(
        self,
        index: int,
        mn: int,
        mx: Any,
        is64: bool,
        shared: bool = False,
        page_size_log2: Optional[int] = None,
    ) -> None:
        mx_str = f" max={mx}" if mx is not None else ""
        addr = " i64" if is64 else ""
        extra = " shared" if shared else ""
        if page_size_log2 is not None:
            extra += f" pagesize=2^{page_size_log2}"
        print(f" - memory[{index}]: pages: initial={mn}{mx_str}{addr}{extra}")

    # ── global section ────────────────────────────────────────────────────

    def on_global(
        self, index: int, valtype: str, mutable: bool, init_expr: str
    ) -> None:
        mut_str = "mutable" if mutable else "const"
        print(f" - global[{index}]: {valtype} {mut_str} - init {init_expr}")

    # ── export section ────────────────────────────────────────────────────

    def on_export(self, index: int, name: str, kind: str, ref_index: int) -> None:
        print(f' - export[{index}]: {kind}[{ref_index}] -> "{name}"')

    # ── start section ─────────────────────────────────────────────────────

    def on_start(self, func_idx: int) -> None:
        print(f"\nStart[8]:")
        print(f" - start func[{func_idx}]")

    # ── element section ───────────────────────────────────────────────────

    def on_element(
        self,
        index: int,
        mode: str,
        ref_type: str,
        table_idx: int,
        offset_expr: str,
        count: int,
        func_indices: List[int],
    ) -> None:
        if mode == "active":
            items = ", ".join(str(fi) for fi in func_indices)
            print(
                f" - segment[{index}]: {mode} table={table_idx} offset={offset_expr} count={count} [{items}]"
            )
        else:
            print(f" - segment[{index}]: {mode} count={count}")

    # ── data section ──────────────────────────────────────────────────────

    def on_data(
        self,
        index: int,
        mode: str,
        mem_idx: int,
        offset_expr: str,
        size: int,
        data: bytes,
        offset_value: Optional[int] = None,
    ) -> None:
        if mode == "active":
            print(
                f" - segment[{index}]: {mode} memory={mem_idx} offset={offset_expr} size={size}"
            )
        else:
            print(f" - segment[{index}]: {mode} size={size}")

    # ── tag section ───────────────────────────────────────────────────────

    def on_tag(self, index: int, type_index: int) -> None:
        print(f" - tag[{index}]: sig={type_index}")

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        super().begin_section(section_index, section_code, size)
        if section_code == BinarySection.CUSTOM:
            return
        name = SECTION_NAMES.get(section_code, f"Unknown_{section_code}")
        if section_code == BinarySection.DATA_COUNT:
            print("\nDataCount:")
            return
        print(f"\n{name}[{self._section_entry_count(section_code)}]:")

    # ── code section ─────────────────────────────────────────────────────

    def begin_function_body(self, index: int, size: int) -> None:
        name = self.objdump_state.function_names.get(index, "")
        sig_idx = self.objdump_state.function_types.get(index, "?")
        name_str = f" <{name}>" if name else ""
        print(f" - func[{index}]: size={size} sig={sig_idx}{name_str}")

    def on_data_count(self, count: int) -> None:
        print(f" - data count: {count}")


class BinaryReaderObjdumpDisassemble(BinaryReaderObjdumpBase):
    def begin_function_body(self, index: int, size: int) -> None:
        print_off = self.get_print_offset(self.offset)
        name = self.objdump_state.function_names.get(index, "")
        name_str = f" <{name}>" if name else ""
        print(f"{print_off:06x} func[{index}]{name_str}:")

    def on_opcode(self, opcode: Any) -> None:
        pass

    def _log_opcode(self, fmt_str: str = "") -> None:
        print_off = self.get_print_offset(self.offset)
        op_name = self.current_opcode.name if self.current_opcode else "unknown"
        print(f" {print_off:06x}: | {op_name} {fmt_str}".rstrip())

    def on_opcode_bare(self) -> None:
        self._log_opcode()

    def on_end_expr(self) -> None:
        self._log_opcode()

    def on_opcode_block_sig(self, sig: int, ref_type: Optional[str] = None) -> None:
        self._log_opcode(f"sig={ref_type if ref_type is not None else sig}")

    def on_opcode_index(self, idx: int) -> None:
        self._log_opcode(f"{idx}")

    def on_opcode_uint32(self, val: int) -> None:
        self._log_opcode(f"{val}")

    def on_opcode_uint64(self, val: int) -> None:
        self._log_opcode(f"{val}")

    def on_opcode_f32(self, val: float) -> None:
        self._log_opcode(f"{val:.6g}")

    def on_opcode_f64(self, val: float) -> None:
        self._log_opcode(f"{val:.6g}")

    def on_opcode_uint32_uint32(self, v1: int, v2: int) -> None:
        self._log_opcode(f"{v1} {v2}")

    def on_call_indirect_expr(self, sig: int, tab: int) -> None:
        self._log_opcode(f"{sig} {tab}")

    def on_opcode_heap_type(self, ht: str) -> None:
        self._log_opcode(f"{ht}")

    def on_opcode_lane_idx(self, lane: int) -> None:
        self._log_opcode(f"{lane}")

    def on_opcode_memarg(self, align: int, mem_offset: int, mem_idx=None) -> None:
        # Multi-memory modules carry an explicit memory index; render it
        # first to match the index order the other multi-index ops use.
        if mem_idx is not None:
            self._log_opcode(f"{mem_idx} {align} {mem_offset}")
        else:
            self._log_opcode(f"{align} {mem_offset}")

    def on_opcode_memarg_lane(
        self, align: int, mem_offset: int, lane: int, mem_idx=None
    ) -> None:
        prefix = f"{mem_idx} " if mem_idx is not None else ""
        self._log_opcode(f"{prefix}{align} {mem_offset} lane={lane}")

    def on_opcode_v128(self, raw: bytes) -> None:
        self._log_opcode("0x" + raw.hex())

    def on_opcode_v128_shuffle(self, lanes: List[int]) -> None:
        self._log_opcode(" ".join(str(l) for l in lanes))

    def on_opcode_br_table(self, targets: List[int], default: int) -> None:
        tgts = " ".join(str(t) for t in targets)
        self._log_opcode(f"{tgts} {default}")

    def on_opcode_br_on_cast(self, flags: int, label: int, ht1: str, ht2: str) -> None:
        self._log_opcode(f"{label} {ht1} {ht2}")

    def on_opcode_try_table(
        self, sig: int, catches: list, ref_type: Optional[str] = None
    ) -> None:
        shown = ref_type if ref_type is not None else sig
        self._log_opcode(f"sig={shown} catches={len(catches)}")

    def on_opcode_select_t(self, types: List[str]) -> None:
        self._log_opcode(f"({', '.join(types)})")


class BinaryReaderObjdumpRaw(BinaryReaderObjdumpBase):
    """Hexdump section payloads (objdump -s style), one 16-byte row at a time."""

    def __init__(
        self, data: bytes, options: ObjdumpOptions, state: ObjdumpState
    ) -> None:
        super().__init__(data, options, state)
        self.data = data

    def begin_module(self, version: int) -> None:
        print("\nSection contents (hexdump):\n")

    def _hexdump(self, payload: bytes, base_offset: int) -> None:
        for row in range(0, len(payload), 16):
            chunk = payload[row : row + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(
                chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk
            )
            print(f"  {base_offset + row:06x}: {hex_part:<47}  {ascii_part}")

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        super().begin_section(section_index, section_code, size)
        name = SECTION_NAMES.get(section_code, f"Unknown_{section_code}")
        if section_code == BinarySection.CUSTOM:
            custom_name = self.objdump_state.section_names.get(
                section_index, ""
            )
            name = f'Custom "{custom_name}"' if custom_name else 'Custom "?"'
        payload_start = self.offset
        print(f"\n{name}[{section_index}] ({size} bytes):")
        if size <= 0:
            return
        payload = self.data[payload_start : payload_start + size]
        self._hexdump(payload, payload_start)


class SectionFilter:
    """Wrap a delegate and forward callbacks only for the selected sections.

    ``wanted_ids`` are section codes (for canonical sections) and
    ``wanted_custom`` are custom section names; everything else is reduced to
    no-ops so ``-x`` and ``-d`` output can be scoped without touching the
    pinned wording of the real visitors. ``on_error`` always passes through.
    """

    # Attributes the parser assigns on its delegate; they must land on the
    # wrapped visitor, not on this wrapper.
    _PROXIED = {"offset", "current_opcode", "function_body_offset"}

    def __init__(
        self,
        inner: Any,
        wanted_ids: set[int],
        wanted_custom: set[str],
    ) -> None:
        self._inner = inner
        self._wanted_ids = wanted_ids
        self._wanted_custom = wanted_custom
        self._active = False

    def __setattr__(self, attr: str, value: Any) -> None:
        if attr in type(self)._PROXIED and "_inner" in self.__dict__:
            setattr(self._inner, attr, value)
        else:
            object.__setattr__(self, attr, value)

    def begin_section(self, section_index: int, section_code: int, size: int) -> None:
        self._active = section_code in self._wanted_ids
        if self._active:
            self._inner.begin_section(section_index, section_code, size)

    def begin_custom_section(
        self, section_index: int, size: int, section_name: str
    ) -> None:
        self._active = section_name in self._wanted_custom
        if self._active:
            self._inner.begin_custom_section(section_index, size, section_name)

    def begin_module(self, version: int) -> None:
        # Module banners print regardless of the filter so the output keeps
        # its shape.
        self._inner.begin_module(version)

    def end_module(self) -> None:
        self._inner.end_module()

    def on_error(self, message: str) -> None:
        # Parse errors are module-level facts; they pass through regardless
        # of the section filter.
        self._inner.on_error(message)

    def __getattr__(self, attr: str) -> Any:
        # Reached only for names this wrapper does not define. A name the
        # wrapped visitor lacks raises AttributeError, so the parser's
        # hasattr checks see the same delegate surface as without the
        # filter; callbacks outside the selected sections become no-ops,
        # and plain attributes (the proxied reads) always pass through.
        inner = object.__getattribute__(self, "_inner")
        value = getattr(inner, attr)
        if object.__getattribute__(self, "_active") or not callable(value):
            return value
        return lambda *args, **kwargs: None
