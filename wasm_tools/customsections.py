"""Decoders for well-known custom sections (tool-conventions catalog).

Every decoder is a pure function over a payload ``bytes`` and returns a
typed dict, or ``None`` when the payload does not parse. Parse errors must
never propagate: a malformed payload degrades to ``None`` plus an error
string, matching the per-section resilience model the parser already uses
(a broken custom section must not cost the rest of the report).

Decoded formats, verified against the tool-conventions documents:

- ``dylink.0`` (DynamicLinking.md): subsections MEM_INFO=1, NEEDED=2,
  EXPORT_INFO=3, IMPORT_INFO=4, RUNTIME_PATH=5, TARGET_ARCH=6. The legacy
  ``dylink`` (pre-.0) section is a flat sequence of four LEB values
  (memory size, memory alignment, table size, table alignment) optionally
  followed by the needed-libraries vector; this reader takes the four
  values and tolerates everything after them.
- ``linking`` (Linking.md): a version LEB (currently 2) followed by
  subsections 5 SEGMENT_INFO, 6 INIT_FUNCS, 7 COMDAT_INFO, 8 SYMBOL_TABLE,
  9 TARGET_ARCH. Symbol kinds 0-5 are function/data/global/section/tag/
  table; flag bits 0x3 binding mask, 0x4 hidden, 0x10 undefined, 0x20
  exported, 0x40 explicit name, 0x80 no-strip, 0x100 TLS, 0x200 absolute.
- ``metadata.code.branch_hint`` (CodeMetadata.md, branch-hinting proposal):
  vec(function) where function ::= funcidx:u32 vec(instance) and instance
  ::= funcpos:u32 size:0x01 hint:0x00(unlikely)|0x01(likely).
- ``component-type``: recorded by name, version, and payload length; the
  embedded WIT binary type grammar is out of scope here.
- ``core`` (Coredump.md): recorded by name only.
"""

from __future__ import annotations

from typing import Any, Optional

DYLINK_MEM_INFO = 1
DYLINK_NEEDED = 2
DYLINK_EXPORT_INFO = 3
DYLINK_IMPORT_INFO = 4
DYLINK_RUNTIME_PATH = 5
DYLINK_TARGET_ARCH = 6

LINKING_VERSION = 2
LINKING_SEGMENT_INFO = 5
LINKING_INIT_FUNCS = 6
LINKING_COMDAT_INFO = 7
LINKING_SYMBOL_TABLE = 8
LINKING_TARGET_ARCH = 9

SYMTAB_FUNCTION = 0
SYMTAB_DATA = 1
SYMTAB_GLOBAL = 2
SYMTAB_SECTION = 3
SYMTAB_TAG = 4
SYMTAB_TABLE = 5

SYMBOL_KIND_NAMES = {
    SYMTAB_FUNCTION: "func",
    SYMTAB_DATA: "data",
    SYMTAB_GLOBAL: "global",
    SYMTAB_SECTION: "section",
    SYMTAB_TAG: "tag",
    SYMTAB_TABLE: "table",
}

SYM_BINDING_MASK = 0x3
SYM_BINDING_NAMES = {0: "global", 1: "weak", 2: "local", 3: "common"}
SYM_VISIBILITY_HIDDEN = 0x4
SYM_UNDEFINED = 0x10
SYM_EXPORTED = 0x20
SYM_EXPLICIT_NAME = 0x40
SYM_NO_STRIP = 0x80
SYM_TLS = 0x100
SYM_ABSOLUTE = 0x200

DEFAULT_MAX_LINKING_SYMBOLS = 500
DEFAULT_MAX_BRANCH_HINT_FUNCTIONS = 500


class _CustomParseError(Exception):
    """Raised internally when a payload cannot be decoded; never escapes."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)
        self.offset = 0

    def ensure(self, n: int) -> None:
        if self.offset + n > self.size:
            raise _CustomParseError("unexpected end of payload")

    def read_u8(self) -> int:
        self.ensure(1)
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u32(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if shift > 32 + 7:
                raise _CustomParseError("LEB128 exceeds maximum length")
            if not (byte & 0x80):
                return result

    def read_string(self) -> str:
        length = self.read_u32()
        self.ensure(length)
        raw = self.data[self.offset : self.offset + length]
        self.offset += length
        return raw.decode("utf-8", errors="replace")


def parse_dylink(payload: bytes) -> Optional[dict[str, Any]]:
    """Decode the ``dylink.0`` custom section (DynamicLinking.md)."""
    if not payload:
        return None
    try:
        r = _Reader(payload)
        info: dict[str, Any] = {"legacy": False}
        while r.offset < r.size:
            sub_type = r.read_u8()
            sub_size = r.read_u32()
            sub_end = r.offset + sub_size
            if sub_end > r.size:
                raise _CustomParseError("dylink subsection extends past payload")
            if sub_type == DYLINK_MEM_INFO:
                info["mem_info"] = {
                    "memory_size": r.read_u32(),
                    "memory_alignment": r.read_u32(),
                    "table_size": r.read_u32(),
                    "table_alignment": r.read_u32(),
                }
            elif sub_type == DYLINK_NEEDED:
                info["needed"] = [
                    r.read_string() for _ in range(r.read_u32())
                ]
            elif sub_type == DYLINK_EXPORT_INFO:
                info["export_info"] = [
                    {"name": r.read_string(), "flags": r.read_u32()}
                    for _ in range(r.read_u32())
                ]
            elif sub_type == DYLINK_IMPORT_INFO:
                info["import_info"] = [
                    {
                        "module": r.read_string(),
                        "field": r.read_string(),
                        "flags": r.read_u32(),
                    }
                    for _ in range(r.read_u32())
                ]
            elif sub_type == DYLINK_RUNTIME_PATH:
                info["runtime_path"] = [
                    r.read_string() for _ in range(r.read_u32())
                ]
            elif sub_type == DYLINK_TARGET_ARCH:
                info["target_arch"] = r.read_string()
            # Unknown subsection ids are skipped by length, matching the
            # section framing contract.
            r.offset = sub_end
        return info
    except _CustomParseError:
        return None


def parse_dylink_legacy(payload: bytes) -> Optional[dict[str, Any]]:
    """Decode the legacy flat ``dylink`` section (pre-.0 emscripten ABI).

    The old layout is four LEB values (memory size, memory alignment, table
    size, table alignment) optionally followed by the needed-libraries
    vector; the document that specifies ``dylink.0`` no longer quotes the
    legacy layout, so this reader takes the four values, reads the needed
    vector best-effort, and never fails the module on trailing shapes it
    does not recognize.
    """
    try:
        r = _Reader(payload)
        info: dict[str, Any] = {
            "legacy": True,
            "mem_info": {
                "memory_size": r.read_u32(),
                "memory_alignment": r.read_u32(),
                "table_size": r.read_u32(),
                "table_alignment": r.read_u32(),
            },
        }
        if r.offset < r.size:
            try:
                info["needed"] = [r.read_string() for _ in range(r.read_u32())]
            except _CustomParseError:
                pass
        return info
    except _CustomParseError:
        return None


def _symbol_flags_dict(flags: int) -> dict[str, Any]:
    return {
        "flags": flags,
        "binding": SYM_BINDING_NAMES.get(
            flags & SYM_BINDING_MASK, str(flags & SYM_BINDING_MASK)
        ),
        "hidden": bool(flags & SYM_VISIBILITY_HIDDEN),
        "undefined": bool(flags & SYM_UNDEFINED),
        "exported": bool(flags & SYM_EXPORTED),
        "explicit_name": bool(flags & SYM_EXPLICIT_NAME),
        "no_strip": bool(flags & SYM_NO_STRIP),
        "tls": bool(flags & SYM_TLS),
        "absolute": bool(flags & SYM_ABSOLUTE),
    }


def parse_linking(payload: bytes) -> Optional[dict[str, Any]]:
    """Decode the ``linking`` custom section (Linking.md)."""
    try:
        r = _Reader(payload)
        version = r.read_u32()
        info: dict[str, Any] = {
            "version": version,
            "symbols": [],
            "symbols_truncated": False,
            "segment_names": [],
            "init_func_count": 0,
            "comdat_count": 0,
        }
        while r.offset < r.size:
            sub_type = r.read_u8()
            sub_size = r.read_u32()
            sub_end = r.offset + sub_size
            if sub_end > r.size:
                raise _CustomParseError("linking subsection extends past payload")
            if sub_type == LINKING_SYMBOL_TABLE:
                count = r.read_u32()
                symbols: list[dict[str, Any]] = []
                for _ in range(count):
                    kind = r.read_u8()
                    flags = r.read_u32()
                    entry: dict[str, Any] = {
                        "kind": SYMBOL_KIND_NAMES.get(kind, f"kind{kind}"),
                        **_symbol_flags_dict(flags),
                    }
                    if kind == SYMTAB_DATA:
                        entry["name"] = r.read_string()
                        if flags & SYM_UNDEFINED or flags & SYM_ABSOLUTE:
                            pass
                        else:
                            # Defined, non-absolute data symbols carry an
                            # optional segment index, offset, and size.
                            if r.offset < sub_end:
                                entry["segment_index"] = r.read_u32()
                                if r.offset < sub_end:
                                    entry["offset"] = r.read_u32()
                                    if r.offset < sub_end:
                                        entry["size"] = r.read_u32()
                    elif kind == SYMTAB_SECTION:
                        entry["section"] = r.read_u32()
                    else:
                        # func/global/tag/table: index, then an optional
                        # name (present for defined symbols or when the
                        # explicit-name flag is set).
                        entry["index"] = r.read_u32()
                        if (
                            not (flags & SYM_UNDEFINED)
                            or (flags & SYM_EXPLICIT_NAME)
                        ):
                            entry["name"] = r.read_string()
                    symbols.append(entry)
                info["symbol_count"] = count
                info["symbols"] = symbols[:DEFAULT_MAX_LINKING_SYMBOLS]
                info["symbols_truncated"] = count > len(info["symbols"])
            elif sub_type == LINKING_SEGMENT_INFO:
                seg_names = []
                for _ in range(r.read_u32()):
                    name = r.read_string()
                    r.read_u32()  # alignment (log2)
                    r.read_u32()  # flags
                    seg_names.append(name)
                info["segment_names"] = seg_names
            elif sub_type == LINKING_INIT_FUNCS:
                entries = []
                for _ in range(r.read_u32()):
                    priority = r.read_u32()
                    symbol_index = r.read_u32()
                    entries.append({"priority": priority, "symbol": symbol_index})
                info["init_func_count"] = len(entries)
                info["init_funcs"] = entries[:DEFAULT_MAX_LINKING_SYMBOLS]
            elif sub_type == LINKING_COMDAT_INFO:
                comdats = []
                for _ in range(r.read_u32()):
                    comdat_name = r.read_string()
                    r.read_u32()  # flags (must be zero)
                    members = []
                    for _ in range(r.read_u32()):
                        member_kind = r.read_u8()
                        member_index = r.read_u32()
                        members.append(
                            {
                                "kind": SYMBOL_KIND_NAMES.get(
                                    member_kind, f"kind{member_kind}"
                                ),
                                "index": member_index,
                            }
                        )
                    comdats.append({"name": comdat_name, "symbols": members})
                info["comdat_count"] = len(comdats)
            elif sub_type == LINKING_TARGET_ARCH:
                info["target_arch"] = r.read_string()
            r.offset = sub_end
        return info
    except _CustomParseError:
        return None


def parse_branch_hints(payload: bytes) -> Optional[dict[str, Any]]:
    """Decode ``metadata.code.branch_hint`` (CodeMetadata.md).

    Returns per-function entries with their hint offsets and values, capped
    at DEFAULT_MAX_BRANCH_HINT_FUNCTIONS functions; the summary counts cover
    the full payload regardless of the cap.
    """
    try:
        r = _Reader(payload)
        function_count = r.read_u32()
        functions: list[dict[str, Any]] = []
        hint_count = 0
        for _ in range(function_count):
            func_index = r.read_u32()
            instances = []
            for _ in range(r.read_u32()):
                offset = r.read_u32()
                size = r.read_u8()
                if size != 0x01:
                    raise _CustomParseError(
                        f"branch hint entry size must be 0x01, got {size:#x}"
                    )
                value = r.read_u8()
                if value not in (0x00, 0x01):
                    raise _CustomParseError(f"unknown hint value {value:#x}")
                instances.append(
                    {"offset": offset, "hint": "unlikely" if value == 0x00 else "likely"}
                )
                hint_count += 1
            functions.append({"function": func_index, "hints": instances})
        return {
            "hinted_function_count": function_count,
            "hint_count": hint_count,
            "functions": functions[:DEFAULT_MAX_BRANCH_HINT_FUNCTIONS],
            "functions_truncated": function_count
            > min(function_count, DEFAULT_MAX_BRANCH_HINT_FUNCTIONS),
        }
    except _CustomParseError:
        return None


def parse_component_type(payload: bytes) -> Optional[dict[str, Any]]:
    """Summarize the ``component-type`` custom section without decoding WIT.

    The embedded binary encodes a full component type (the input to
    ``wasm-tools component new``); decoding that grammar is out of scope,
    so this records the section's size for the analyst. A leading LEB is
    read best-effort as the version when the payload is non-empty.
    """
    if not payload:
        return None
    r = _Reader(payload)
    try:
        version = r.read_u32()
    except _CustomParseError:
        version = None
    return {"payload_size": len(payload), "version": version}


def name_precedence_names(
    linking: Optional[dict[str, Any]],
) -> dict[int, str]:
    """Function-name map derived from linking symbols (subsection 8).

    Only symbols that carry an explicit name contribute; the name section
    takes precedence over this map everywhere the parser uses names.
    """
    names: dict[int, str] = {}
    if not linking:
        return names
    for symbol in linking.get("symbols", []):
        if symbol.get("kind") == "func" and symbol.get("name"):
            index = symbol.get("index")
            if isinstance(index, int):
                names.setdefault(index, str(symbol["name"]))
    return names
