"""WebAssembly Component Model binary parsing.

A component binary uses the same ``\\0asm`` magic as a core module but a
different 4-byte version field, reinterpreted as two u16 values:
``(version, layer)``.  Core modules are ``(1, 0)``; components are
``(0x0d+,  1)`` (e.g. the pre-standard preamble ``00 61 73 6D 0D 00 01 00``).

The component format is still pre-standard, so this reader is deliberately
conservative: every section is length-prefixed, and any section whose payload
fails to decode is abandoned at its recorded end offset without aborting the
walk.  Sections whose grammar is fully decoded today are imports (10),
exports (11), canon (8), and nested core modules (1); the rest are recorded
as metadata and skipped.

Reference: WebAssembly/component-model ``design/mvp/Binary.md``.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

WASM_MAGIC = b"\x00asm"
COMPONENT_LAYER = 1
MIN_COMPONENT_VERSION = 0x0D
_MAX_NESTING = 8

# Component section ids (Binary.md section table).
COMPONENT_SECTION_NAMES = {
    0: "CoreCustom",
    1: "CoreModule",
    2: "CoreInstance",
    3: "CoreType",
    4: "Component",
    5: "Instance",
    6: "Alias",
    7: "Type",
    8: "Canon",
    9: "Start",
    10: "Import",
    11: "Export",
    12: "Value",
}

# Component primitive valtype bytes (used by value bounds in import
# descriptors).  Kept here only to skip them correctly.  0x64 is
# error-context, added to the primitive set by WASI 0.3 (Binary.md
# primvaltype grammar).
_PRIMITIVE_VALTYPES = set(range(0x73, 0x80)) | {0x64}

# Canon option encodings (Binary.md canon grammar).
_CANON_OPT_NAMES = {
    0x00: "utf8",
    0x01: "utf16",
    0x02: "latin1+utf16",
    0x03: "memory",
    0x04: "realloc",
    0x05: "post-return",
    0x06: "async",
    0x07: "callback",
}
_CANON_OPT_WITH_INDEX = {0x03, 0x04, 0x05, 0x07}

# Name attribute kinds (Binary.md nameattributes grammar, WASI 0.3.1).
_NAME_ATTRIBUTE_KINDS = {0x00: "implements", 0x01: "version-suffix", 0x02: "external-id"}

# Async-era canon built-ins (Binary.md canon grammar, WASI 0.3 layout):
# name -> payload shape descriptor.
#   bare            no immediates
#   async           one async? byte (0x00 sync / 0x01 async)
#   typeidx         one component type index
#   typeidx+opts    one component type index then an opts vector
#   typeidx+async   one component type index then an async? byte
#   resultlist+opts task.return's resultlist then an opts vector
#   sh+coretype     sh? byte then a core type index
#   sh+coretype+coretable  sh? byte, core type index, core table index
_CANON_BUILTINS = {
    0x05: ("task.cancel", "bare"),
    0x06: ("subtask.cancel", "async"),
    0x09: ("task.return", "resultlist+opts"),
    0x0D: ("subtask.drop", "bare"),
    0x0E: ("stream.new", "typeidx"),
    0x0F: ("stream.read", "typeidx+opts"),
    0x10: ("stream.write", "typeidx+opts"),
    0x11: ("stream.cancel-read", "typeidx+async"),
    0x12: ("stream.cancel-write", "typeidx+async"),
    0x13: ("stream.drop-readable", "typeidx"),
    0x14: ("stream.drop-writable", "typeidx"),
    0x15: ("future.new", "typeidx"),
    0x16: ("future.read", "typeidx+opts"),
    0x17: ("future.write", "typeidx+opts"),
    0x18: ("future.cancel-read", "typeidx+async"),
    0x19: ("future.cancel-write", "typeidx+async"),
    0x1A: ("future.drop-readable", "typeidx"),
    0x1B: ("future.drop-writable", "typeidx"),
    0x1C: ("error-context.new", "opts"),
    0x1D: ("error-context.debug-message", "opts"),
    0x1E: ("error-context.drop", "bare"),
    0x2E: ("stream.forward", "typeidx"),
    0x2F: ("future.forward", "typeidx"),
    0x40: ("thread.spawn-ref", "sh+coretype"),
    0x41: ("thread.spawn-indirect", "sh+coretype+coretable"),
    0x42: ("thread.available-parallelism", "sh"),
}


class _ComponentParseError(Exception):
    """Raised when a component payload cannot be decoded at the current spot."""


class _CReader:
    """Minimal bounds-checked reader over component bytes."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)
        self.offset = 0

    def ensure(self, n: int) -> None:
        if self.offset + n > self.size:
            raise _ComponentParseError("unexpected end of component payload")

    def read_u8(self) -> int:
        self.ensure(1)
        val = self.data[self.offset]
        self.offset += 1
        return val

    def read_u32_leb(self, max_bits: int = 32) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.read_u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if shift > max_bits + 7:
                raise _ComponentParseError("LEB128 exceeds maximum length")
            if not (byte & 0x80):
                break
        return result

    def read_bytes(self, n: int) -> bytes:
        self.ensure(n)
        raw = self.data[self.offset : self.offset + n]
        self.offset += n
        return raw

    def read_name(self) -> str:
        length = self.read_u32_leb()
        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace")


def detect_component(data: bytes) -> Optional[Tuple[int, int]]:
    """Return (version, layer) when ``data`` has a component preamble, else None.

    The layer field is the discriminator the spec reserves for exactly this
    purpose (core modules are implicitly layer 0). Older toolchains emitted
    pre-0x0d component versions, so any layer-1 preamble is accepted and the
    specific version is reported for triage.
    """
    if len(data) < 8 or data[:4] != WASM_MAGIC:
        return None
    version = data[4] | (data[5] << 8)
    layer = data[6] | (data[7] << 8)
    if layer == COMPONENT_LAYER:
        return version, layer
    return None


def _read_externname(r: _CReader) -> tuple[str, List[dict[str, str]]]:
    # nameattributes ::= 0x00|0x01 len:u32 externname
    #                  | 0x02 len:u32 externname vec(attribute)
    # Attribute kinds (WASI 0.3.1): 0x00 implements <interfacename>,
    # 0x01 version-suffix <semver>, 0x02 external-id <name>.
    kind = r.read_u8()
    if kind not in (0x00, 0x01, 0x02):
        raise _ComponentParseError(f"unknown nameattributes kind {kind:#x}")
    name = r.read_name()
    attributes: List[dict[str, str]] = []
    if kind == 0x02:
        attr_count = r.read_u32_leb()
        for _ in range(attr_count):
            attr_kind = r.read_u8()
            if attr_kind in _NAME_ATTRIBUTE_KINDS:
                attributes.append(
                    {
                        "kind": _NAME_ATTRIBUTE_KINDS[attr_kind],
                        "value": r.read_name(),
                    }
                )
            else:
                raise _ComponentParseError(
                    f"unknown attribute kind {attr_kind:#x}"
                )
    return name, attributes


def _skip_valtype(r: _CReader) -> str:
    """Skip one valtype or defvaltype, returning a short description.

    ``valtype`` is a type index (non-negative SLEB) or a primvaltype byte
    (0x73-0x7F plus 0x64).  Defvaltype composite opcodes (0x63-0x72) are not
    valid in strict valtype position, but accepting them keeps framing robust
    against toolchains that emit composite types where a valtype is expected:
    every opcode's payload is length-deterministic, so skipping is safe.
    """
    b = r.read_u8()
    if b < 0x40:
        # Small non-negative SLEB: a complete single-byte type index.
        return f"type:{b}"
    if b >= 0x80:
        # Continuation bytes of a larger multi-byte type index.
        while b & 0x80:
            b = r.read_u8()
        return "type"
    if b in _PRIMITIVE_VALTYPES:
        return f"prim:{b:#x}"
    if b == 0x69 or b == 0x68:  # own / borrow: one typeidx
        r.read_u32_leb()
        return "resource"
    if b == 0x6A:  # result: optional valtype, optional valtype
        if r.read_u8() == 0x01:
            _skip_valtype(r)
        if r.read_u8() == 0x01:
            _skip_valtype(r)
        return "result"
    if b == 0x6B:  # option: one valtype
        _skip_valtype(r)
        return "option"
    if b == 0x6D or b == 0x6E:  # enum / flags: vec of labels (plain names)
        for _ in range(r.read_u32_leb()):
            r.read_name()
        return "enum" if b == 0x6D else "flags"
    if b == 0x6F:  # tuple: vec(valtype)
        for _ in range(r.read_u32_leb()):
            _skip_valtype(r)
        return "tuple"
    if b == 0x70:  # list: one valtype
        _skip_valtype(r)
        return "list"
    if b == 0x67:  # fixed-length list: valtype + u32 length
        _skip_valtype(r)
        r.read_u32_leb()
        return "fixed-list"
    if b == 0x66 or b == 0x65:  # stream / future: optional valtype
        if r.read_u8() == 0x01:
            _skip_valtype(r)
        return "stream" if b == 0x66 else "future"
    if b == 0x63:  # map: two valtypes
        _skip_valtype(r)
        _skip_valtype(r)
        return "map"
    if b == 0x72:  # record: vec(labelvaltype); labelvaltype = name + valtype
        for _ in range(r.read_u32_leb()):
            r.read_name()
            _skip_valtype(r)
        return "record"
    if b == 0x71:  # variant: vec(case); case = name + valtype? + 0x00
        for _ in range(r.read_u32_leb()):
            r.read_name()
            if r.read_u8() == 0x01:
                _skip_valtype(r)
            r.read_u8()  # trailing 0x00
        return "variant"
    raise _ComponentParseError(f"unknown valtype byte {b:#x}")


def _read_externdesc(r: _CReader) -> dict[str, Any]:
    """Skip one externtype descriptor, returning what was learned about it."""
    kind = r.read_u8()
    if kind == 0x00:  # core module: 0x00 0x11 <core:typeidx>
        sub = r.read_u8()
        if sub != 0x11:
            raise _ComponentParseError("core module desc must use 0x11")
        return {"kind": "core-module", "type_index": r.read_u32_leb()}
    if kind == 0x01:  # func
        return {"kind": "func", "type_index": r.read_u32_leb()}
    if kind == 0x02:  # value: valuebound
        bound = r.read_u8()
        if bound == 0x00:
            return {"kind": "value", "value_index": r.read_u32_leb()}
        if bound == 0x01:
            vt_desc = _skip_valtype(r)
            return {"kind": "value", "valtype": vt_desc}
        raise _ComponentParseError("unknown valuebound")
    if kind == 0x03:  # type: typebound
        bound = r.read_u8()
        if bound == 0x00:
            return {"kind": "type", "type_index": r.read_u32_leb()}
        if bound == 0x01:
            return {"kind": "type", "sub": "resource"}
        raise _ComponentParseError("unknown typebound")
    if kind == 0x04:  # component
        return {"kind": "component", "type_index": r.read_u32_leb()}
    if kind == 0x05:  # instance
        return {"kind": "instance", "type_index": r.read_u32_leb()}
    raise _ComponentParseError(f"unknown externdesc kind {kind:#x}")


_CORE_SORT_NAMES = {
    0x00: "core-func",
    0x01: "core-table",
    0x02: "core-memory",
    0x03: "core-global",
    0x04: "core-tag",
    0x10: "core-type",
    0x11: "core-module",
    0x12: "core-instance",
}
_SORT_NAMES = {
    0x01: "func",
    0x02: "value",
    0x03: "type",
    0x04: "component",
    0x05: "instance",
}


def _read_sortidx(r: _CReader) -> Tuple[str, int]:
    sort = r.read_u8()
    if sort == 0x00:
        core_sort = r.read_u8()
        name = _CORE_SORT_NAMES.get(core_sort, f"core-{core_sort:#x}")
    elif sort in _SORT_NAMES:
        name = _SORT_NAMES[sort]
    else:
        raise _ComponentParseError(f"unknown sort {sort:#x}")
    return name, r.read_u32_leb()


def _read_canon_options(r: _CReader) -> List[str]:
    opts: List[str] = []
    count = r.read_u32_leb()
    for _ in range(count):
        opt = r.read_u8()
        if opt not in _CANON_OPT_NAMES:
            raise _ComponentParseError(f"unknown canon option {opt:#x}")
        if opt in _CANON_OPT_WITH_INDEX:
            r.read_u32_leb()
        opts.append(_CANON_OPT_NAMES[opt])
    return opts


def _decode_component_section(
    section_id: int, r: _CReader, end: int
) -> Tuple[List[dict[str, Any]], List[str], List[str], dict[str, Any]]:
    """Best-effort decode of import/export/canon sections.

    Returns (imports, exports, canon_options, extras).  Raises on unexpected
    shapes; the caller abandons the remainder of the section in that case.
    """
    imports: List[dict[str, Any]] = []
    exports: List[dict[str, Any]] = []
    canon_opts: List[str] = []
    extras: dict[str, Any] = {"lift_count": 0, "lower_count": 0, "resource_count": 0}

    if section_id == 10:
        count = r.read_u32_leb()
        for _ in range(count):
            name, attributes = _read_externname(r)
            desc = _read_externdesc(r)
            entry = dict(desc)
            entry["name"] = name
            if attributes:
                entry["attributes"] = attributes
            imports.append(entry)
    elif section_id == 11:
        count = r.read_u32_leb()
        for _ in range(count):
            name, attributes = _read_externname(r)
            sort_name, idx = _read_sortidx(r)
            entry: dict[str, Any] = {"name": name, "kind": sort_name, "index": idx}
            if attributes:
                entry["attributes"] = attributes
            opt = r.read_u8()
            if opt == 0x01:
                entry["externdesc"] = _read_externdesc(r)
            elif opt != 0x00:
                raise _ComponentParseError("export externtype option must be 0x00/0x01")
            exports.append(entry)
    elif section_id == 8:
        count = r.read_u32_leb()
        for _ in range(count):
            canon_kind = r.read_u8()
            if canon_kind == 0x00:  # lift
                r.read_u8()  # 0x00 reserved
                r.read_u32_leb()  # core func idx
                opts = _read_canon_options(r)
                r.read_u32_leb()  # type idx
                canon_opts.extend(opts)
                extras["lift_count"] += 1
            elif canon_kind == 0x01:  # lower
                r.read_u8()  # 0x00 reserved
                r.read_u32_leb()  # func idx
                canon_opts.extend(_read_canon_options(r))
                extras["lower_count"] += 1
            elif canon_kind in (0x02, 0x03, 0x04):  # resource new/drop/rep
                r.read_u32_leb()
                extras["resource_count"] += 1
            elif canon_kind in _CANON_BUILTINS:
                # WASI 0.3 async-era built-ins with fixed payload shapes
                # (Binary.md canon grammar).  Recorded as counts; payloads
                # are skipped because their immediates carry no capability
                # signal beyond the built-in name itself.
                builtin_name, shape = _CANON_BUILTINS[canon_kind]
                if shape == "async":
                    r.read_u8()
                elif shape == "typeidx":
                    r.read_u32_leb()
                elif shape == "typeidx+opts":
                    r.read_u32_leb()
                    _read_canon_options(r)
                elif shape == "typeidx+async":
                    r.read_u32_leb()
                    r.read_u8()
                elif shape == "opts":
                    _read_canon_options(r)
                elif shape == "resultlist+opts":
                    # resultlist ::= 0x00 t:<valtype> | 0x01 0x00
                    if r.read_u8() == 0x00:
                        _skip_valtype(r)
                    else:
                        if r.read_u8() != 0x00:
                            raise _ComponentParseError(
                                "task.return resultlist must end with 0x00"
                            )
                    _read_canon_options(r)
                elif shape == "sh+coretype":
                    r.read_u8()  # sh? 0x00/0x01
                    r.read_u32_leb()
                elif shape == "sh+coretype+coretable":
                    r.read_u8()  # sh? 0x00/0x01
                    r.read_u32_leb()
                    r.read_u32_leb()
                elif shape == "sh":
                    r.read_u8()  # sh? 0x00/0x01
                extras.setdefault("builtin_counts", {})
                extras["builtin_counts"][builtin_name] = (
                    extras["builtin_counts"].get(builtin_name, 0) + 1
                )
            else:
                raise _ComponentParseError(
                    f"canon kind {canon_kind:#x} not decoded"
                )
    return imports, exports, canon_opts, extras


def _producers_and_features(payload: bytes) -> dict[str, Any]:
    """Decode producers/target_features custom payloads (tool-conventions)."""
    out: dict[str, Any] = {"producers": {}, "target_features": []}
    try:
        r = _CReader(payload)
        name = r.read_name()
        if name == "producers":
            fields = r.read_u32_leb()
            for _ in range(fields):
                field = r.read_name()
                entries = r.read_u32_leb()
                pairs = []
                for _ in range(entries):
                    n1 = r.read_name()
                    n2 = r.read_name()
                    pairs.append((n1, n2))
                out["producers"][field] = pairs
        elif name == "target_features":
            count = r.read_u32_leb()
            for _ in range(count):
                prefix = r.read_u8()
                out["target_features"].append((prefix == 0x2B, r.read_name()))
    except _ComponentParseError:
        pass
    return out


def parse_component_bytes(
    data: bytes,
    core_parse: Optional[Any] = None,
    depth: int = 0,
) -> dict[str, Any]:
    """Walk a component binary and return its triage-relevant structure.

    ``core_parse`` is a callable ``(payload_bytes) -> report_dict`` used to
    fully decode nested core modules (supplied by :mod:`wasm_tools.api` to
    avoid an import cycle).
    """
    result: dict[str, Any] = {
        "detected": True,
        "imports": [],
        "exports": [],
        "core_modules": [],
        "interfaces": [],
        "interface_packages": [],
        "canonical_options": {
            "lift_count": 0,
            "lower_count": 0,
            "resource_count": 0,
            "options": [],
            "async": False,
        },
        "sections": [],
        "errors": [],
    }
    detected = detect_component(data)
    if detected is None:
        result["detected"] = False
        result["errors"].append("not a component binary")
        return result
    version, layer = detected
    result["component_version"] = version
    result["layer_version"] = layer

    r = _CReader(data)
    r.offset = 8
    section_index = 0
    while r.offset < r.size:
        try:
            section_id = r.read_u8()
            section_size = r.read_u32_leb()
        except _ComponentParseError as exc:
            result["errors"].append(str(exc))
            break
        payload_start = r.offset
        end = payload_start + section_size
        if end > r.size:
            result["errors"].append("component section extends beyond file")
            break

        section_record = {
            "index": section_index,
            "id": section_id,
            "name": COMPONENT_SECTION_NAMES.get(section_id, f"Unknown_{section_id}"),
            "size": section_size,
            "offset": payload_start,
        }
        result["sections"].append(section_record)

        payload = data[payload_start:end]
        sub = _CReader(payload)
        try:
            if section_id == 1 and core_parse is not None and depth < _MAX_NESTING:
                report = core_parse(payload)
                report["core_module_index"] = len(result["core_modules"])
                result["core_modules"].append(report)
            elif section_id == 4 and depth < _MAX_NESTING:
                nested = parse_component_bytes(
                    payload, core_parse=core_parse, depth=depth + 1
                )
                nested.pop("sections", None)
                nested["core_module_index"] = None
                result.setdefault("nested_components", []).append(nested)
            elif section_id in (8, 10, 11):
                imports, exports, canon_opts, extras = _decode_component_section(
                    section_id, sub, len(payload)
                )
                result["imports"].extend(imports)
                result["exports"].extend(exports)
                result["canonical_options"]["options"].extend(canon_opts)
                result["canonical_options"]["lift_count"] += extras["lift_count"]
                result["canonical_options"]["lower_count"] += extras["lower_count"]
                result["canonical_options"]["resource_count"] += extras["resource_count"]
                for builtin_name, builtin_count in extras.get(
                    "builtin_counts", {}
                ).items():
                    builtins = result["canonical_options"].setdefault(
                        "builtins", {}
                    )
                    builtins[builtin_name] = (
                        builtins.get(builtin_name, 0) + builtin_count
                    )
            elif section_id == 0:
                custom = _producers_and_features(payload)
                if custom["producers"]:
                    result["producers"] = custom["producers"]
                if custom["target_features"]:
                    result["target_features"] = custom["target_features"]
        except _ComponentParseError as exc:
            # Abandon this section's remaining entries; keep walking.
            result["errors"].append(
                f"section {section_index} ({section_record['name']}): {exc}"
            )

        r.offset = end
        section_index += 1

    result["canonical_options"]["async"] = (
        "async" in result["canonical_options"]["options"]
    )

    interfaces = sorted(
        {
            str(entry["name"])
            for entry in result["imports"] + result["exports"]
            if "@" in str(entry.get("name", ""))
        }
    )
    # WASI 0.3.1 name attributes: an `implements` attribute carries the real
    # interface name for plain-named imports, so it belongs in the interface
    # list that WASI detection reads.
    for entry in result["imports"] + result["exports"]:
        for attr in entry.get("attributes", []):
            if attr.get("kind") == "implements":
                implemented = str(attr.get("value", ""))
                if implemented and implemented not in interfaces:
                    interfaces.append(implemented)
    interfaces.sort()
    result["interfaces"] = interfaces
    result["interface_packages"] = sorted(
        {iface.rsplit("@", 1)[0] for iface in interfaces}
    )

    # Parsed WIT package structure: consumers should not re-split interface
    # names with regexes when the grammar is this small.
    wit_packages: dict[tuple, dict[str, Any]] = {}
    for entry in result["imports"]:
        parsed = parse_wit_name(str(entry.get("name", "")))
        if parsed is not None:
            key = (parsed["namespace"], parsed["package"], parsed["version"])
            pkg = wit_packages.setdefault(
                key,
                {
                    "namespace": parsed["namespace"],
                    "package": parsed["package"],
                    "version": parsed["version"],
                    "interfaces": [],
                    "direction": [],
                    "suggested_purl": suggested_wit_purl(parsed),
                },
            )
            if parsed["interface"] not in pkg["interfaces"]:
                pkg["interfaces"].append(parsed["interface"])
            if "import" not in pkg["direction"]:
                pkg["direction"].append("import")
    for entry in result["exports"]:
        parsed = parse_wit_name(str(entry.get("name", "")))
        if parsed is not None:
            key = (parsed["namespace"], parsed["package"], parsed["version"])
            pkg = wit_packages.setdefault(
                key,
                {
                    "namespace": parsed["namespace"],
                    "package": parsed["package"],
                    "version": parsed["version"],
                    "interfaces": [],
                    "direction": [],
                    "suggested_purl": suggested_wit_purl(parsed),
                },
            )
            if parsed["interface"] not in pkg["interfaces"]:
                pkg["interfaces"].append(parsed["interface"])
            if "export" not in pkg["direction"]:
                pkg["direction"].append("export")
    result["wit_packages"] = sorted(
        wit_packages.values(),
        key=lambda pkg: (pkg["namespace"], pkg["package"], pkg["version"]),
    )
    # Parse each interface-shaped import/export name in place so consumers of
    # component.imports / component.exports get the structure without
    # regexing the names themselves.
    for entry in result["imports"] + result["exports"]:
        parsed = parse_wit_name(str(entry.get("name", "")))
        if parsed is not None:
            entry["wit"] = parsed
            entry["suggested_purl"] = suggested_wit_purl(parsed)
    result["import_count"] = len(result["imports"])
    result["export_count"] = len(result["exports"])
    result["core_module_count"] = len(result["core_modules"])
    return result


def wasi_variants_from_interfaces(interfaces: List[str]) -> List[str]:
    """Map component interface names to WASI preview variants.

    ``wasi:*@0.2.x`` imports indicate WASI Preview 2; ``@0.3.x`` indicates
    the async-native WASI 0.3 rebase.
    """
    variants: List[str] = []
    for iface in interfaces:
        if not iface.startswith("wasi:") or "@" not in iface:
            continue
        version = iface.rsplit("@", 1)[1]
        if version.startswith("0.2") and "preview2" not in variants:
            variants.append("preview2")
        elif version.startswith("0.3") and "preview3" not in variants:
            variants.append("preview3")
    return variants


_WIT_NAME_RE = None


def parse_wit_name(name: str) -> Optional[dict[str, str]]:
    """Parse a WIT interface name into namespace, package, interface, version.

    The grammar components publish is ``<ns>:<pkg>/<iface>`` with an optional
    ``@<version>`` (semver, including pre-release suffixes such as
    ``0.3.0-draft`` that draft WASI extensions carry). Anything that does not
    match the grammar, including plain names and core-module import names
    (``env``, ``wbg``), returns None rather than a partial guess.
    """
    global _WIT_NAME_RE
    if _WIT_NAME_RE is None:
        import re

        # Namespace and package are kebab-case identifiers; the interface is
        # kebab-case too; the version is a semver core or a full semver with
        # an optional pre-release segment (which may itself contain dashes).
        _WIT_NAME_RE = re.compile(
            r"^(?P<ns>[a-z][a-z0-9_-]*):(?P<pkg>[a-z][a-z0-9_-]*)/"
            r"(?P<iface>[a-z][a-z0-9_-]*)"
            r"(?:@(?P<ver>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?))?$"
        )
    match = _WIT_NAME_RE.match(name)
    if match is None:
        return None
    return {
        "namespace": match.group("ns"),
        "package": match.group("pkg"),
        "interface": match.group("iface"),
        "version": match.group("ver") or "",
    }


def suggested_wit_purl(parsed: dict[str, str]) -> str:
    """Advisory purl for a parsed WIT package.

    The ``wasm`` purl type is not registered in package-url/purl-spec yet, so
    this is a proposal-shaped suggestion consumers may adopt or map to
    ``pkg:generic``; JSON_REFERENCE documents exactly that status.
    """
    purl = f"pkg:wasm/{parsed['namespace']}/{parsed['package']}"
    if parsed["version"]:
        purl += f"@{parsed['version']}"
    return purl
