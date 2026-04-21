from typing import Any, List

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

    def on_type(self, index: int, params: List[str], results: List[str]) -> None:
        ft = FuncType(params=params, results=results)
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
            )
            if kind == "table"
            else None,
            mem_limits=Limits(
                minimum=kwargs["limits_min"],
                maximum=kwargs.get("limits_max"),
                is_64=kwargs.get("limits_64", False),
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

    def on_table(self, index: int, ref_type: str, mn: int, mx: Any, is64: bool) -> None:
        entry = TableEntry(index=index, ref_type=ref_type, limits=Limits(mn, mx, is64))
        while len(self.objdump_state.tables) <= index:
            self.objdump_state.tables.append(None)  # type: ignore
        self.objdump_state.tables[index] = entry

    def on_memory(self, index: int, mn: int, mx: Any, is64: bool) -> None:
        entry = MemoryEntry(index=index, limits=Limits(mn, mx, is64))
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
    ) -> None:
        entry = DataEntry(
            index=index,
            mode=mode,
            memory_index=mem_idx,
            offset_expr=offset_expr,
            size=size,
            data=data,
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
        off = self.offset
        print(f"  {section_code:3d} {name:<16} {size:6d}  {off:08x}")
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
        p = ", ".join(params) if params else ""
        r = ", ".join(results) if results else ""
        print(f" - type[{index}]: ({p}) -> ({r})")

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

    def on_table(self, index: int, ref_type: str, mn: int, mx: Any, is64: bool) -> None:
        mx_str = f" max={mx}" if mx is not None else ""
        print(f" - table[{index}]: {ref_type} min={mn}{mx_str}")

    # ── memory section ────────────────────────────────────────────────────

    def on_memory(self, index: int, mn: int, mx: Any, is64: bool) -> None:
        mx_str = f" max={mx}" if mx is not None else ""
        addr = " i64" if is64 else ""
        print(f" - memory[{index}]: pages: initial={mn}{mx_str}{addr}")

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

    def on_opcode_block_sig(self, sig: int) -> None:
        self._log_opcode(f"sig={sig}")

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

    def on_opcode_memarg_lane(self, align: int, mem_offset: int, lane: int) -> None:
        self._log_opcode(f"{align} {mem_offset} lane={lane}")

    def on_opcode_v128(self, raw: bytes) -> None:
        self._log_opcode("0x" + raw.hex())

    def on_opcode_v128_shuffle(self, lanes: List[int]) -> None:
        self._log_opcode(" ".join(str(l) for l in lanes))

    def on_opcode_br_table(self, targets: List[int], default: int) -> None:
        tgts = " ".join(str(t) for t in targets)
        self._log_opcode(f"{tgts} {default}")

    def on_opcode_br_on_cast(self, flags: int, label: int, ht1: str, ht2: str) -> None:
        self._log_opcode(f"{label} {ht1} {ht2}")

    def on_opcode_try_table(self, sig: int, catches: list) -> None:
        self._log_opcode(f"sig={sig} catches={len(catches)}")

    def on_opcode_select_t(self, types: List[str]) -> None:
        self._log_opcode(f"({', '.join(types)})")
