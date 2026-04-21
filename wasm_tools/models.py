from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class ObjdumpMode:
    PREPASS = 0
    HEADERS = 1
    DETAILS = 2
    DISASSEMBLE = 3
    RAW_DATA = 4


class BinarySection:
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11
    DATA_COUNT = 12
    TAG = 13
    INVALID = 99


SECTION_NAMES = {
    BinarySection.CUSTOM: "Custom",
    BinarySection.TYPE: "Type",
    BinarySection.IMPORT: "Import",
    BinarySection.FUNCTION: "Function",
    BinarySection.TABLE: "Table",
    BinarySection.MEMORY: "Memory",
    BinarySection.GLOBAL: "Global",
    BinarySection.EXPORT: "Export",
    BinarySection.START: "Start",
    BinarySection.ELEMENT: "Element",
    BinarySection.CODE: "Code",
    BinarySection.DATA: "Data",
    BinarySection.DATA_COUNT: "DataCount",
    BinarySection.TAG: "Tag",
}

# Human-readable kind labels for imports/exports.
EXTERN_KIND_NAMES = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}


@dataclass
class FuncType:
    """Decoded function signature (type section entry)."""

    params: List[str] = field(default_factory=list)
    results: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        p = ", ".join(self.params) if self.params else ""
        r = ", ".join(self.results) if self.results else ""
        return f"({p}) -> ({r})"


@dataclass
class Limits:
    """Memory/table address-space limits."""

    minimum: int = 0
    maximum: Optional[int] = None
    is_64: bool = False

    def __str__(self) -> str:
        base = f"min={self.minimum}"
        if self.maximum is not None:
            base += f" max={self.maximum}"
        if self.is_64:
            base += " i64"
        return base


@dataclass
class ImportEntry:
    """Decoded import section entry."""

    index: int
    module: str
    name: str
    kind: str  # "func", "table", "memory", "global", "tag"
    # kind-specific details (at most one set is populated)
    type_index: Optional[int] = None  # func
    table_ref_type: Optional[str] = None  # table
    table_limits: Optional[Limits] = None  # table
    mem_limits: Optional[Limits] = None  # memory
    global_valtype: Optional[str] = None  # global
    global_mutable: bool = False  # global
    tag_type_index: Optional[int] = None  # tag


@dataclass
class ExportEntry:
    """Decoded export section entry."""

    index: int
    name: str
    kind: str  # "func", "table", "memory", "global", "tag"
    ref_index: int


@dataclass
class GlobalEntry:
    """Decoded global section entry."""

    index: int
    valtype: str
    mutable: bool
    init_expr: str  # human-readable constant expression


@dataclass
class TableEntry:
    """Decoded table section entry."""

    index: int
    ref_type: str
    limits: Limits


@dataclass
class MemoryEntry:
    """Decoded memory section entry."""

    index: int
    limits: Limits


@dataclass
class DataEntry:
    """Decoded data section entry."""

    index: int
    mode: str  # "active" or "passive"
    memory_index: int
    offset_expr: str  # human-readable init expression for offset
    size: int
    data: bytes = field(default_factory=bytes, repr=False)


@dataclass
class ElementEntry:
    """Decoded element section entry."""

    index: int
    mode: str  # "active", "passive", "declarative"
    ref_type: str
    table_index: int
    offset_expr: str
    count: int
    func_indices: List[int] = field(default_factory=list)


@dataclass
class TagEntry:
    """Decoded tag (exception) section entry."""

    index: int
    type_index: int


@dataclass
class ObjdumpOptions:
    headers: bool = False
    details: bool = False
    raw: bool = False
    disassemble: bool = False
    debug: bool = False
    relocs: bool = False
    section_offsets: bool = False
    mode: int = ObjdumpMode.DETAILS
    filename: str = ""
    section_name: str = ""


@dataclass
class ObjdumpSymbol:
    kind: int
    name: str
    index: int


class ObjdumpState:
    def __init__(self) -> None:
        """Initialize mutable state shared across parser and visitors."""
        self.code_relocations: List[Any] = []
        self.data_relocations: List[Any] = []
        self.type_names: Dict[int, str] = {}
        self.function_names: Dict[int, str] = {}
        self.global_names: Dict[int, str] = {}
        self.section_names: Dict[int, str] = {}
        self.tag_names: Dict[int, str] = {}
        self.segment_names: Dict[int, str] = {}
        self.table_names: Dict[int, str] = {}
        self.local_names: Dict[Tuple[int, int], str] = {}
        self.symtab: List[ObjdumpSymbol] = []
        self.function_param_counts: Dict[int, int] = {}
        self.function_types: Dict[int, int] = {}
        # Rich section data (populated by prepass)
        self.types: List[FuncType] = []
        self.imports: List[ImportEntry] = []
        self.exports: List[ExportEntry] = []
        self.globals: List[GlobalEntry] = []
        self.tables: List[TableEntry] = []
        self.memories: List[MemoryEntry] = []
        self.data_segments: List[DataEntry] = []
        self.elements: List[ElementEntry] = []
        self.tags: List[TagEntry] = []
        self.start_function: Optional[int] = None
        self.data_count: Optional[int] = None
        self.imported_function_count: int = 0
        self.imported_table_count: int = 0
        self.imported_memory_count: int = 0
        self.imported_global_count: int = 0
        self.imported_tag_count: int = 0
