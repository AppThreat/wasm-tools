# Migrating from wasm-tools 1.x to 2.0.0

Version 2.0.0 is a major release. It adds Component Model parsing, string/IoC
extraction, a static call graph, toolchain fingerprinting, and post-3.0 opcode
coverage. Some JSON schema values changed and several parser callbacks gained
parameters, so consumers of the JSON report and authors of custom delegates
should review this document.

Summary of what is new:

- **Component Model binaries are parsed** (previously only flagged as
  `possible-component`): nested core modules are fully decoded and aggregated.
- **Strings & secrets**: printable strings with linear-memory provenance are
  extracted from data segments and screened for URLs, credential-like blobs,
  and mining indicators (`analysis.detections.strings`, finding
  `WASM-STR-007`).
- **Call graph**: labeled `direct` / `indirect-approx` / `typed-approx` edges,
  import-boundary xrefs, and export reachability.
- **Toolchain fingerprint**: `producers` and `target_features` custom sections
  are decoded into a top-level `toolchain` block.
- **Post-3.0 instructions and limits**: wide-arithmetic, half-precision
  (f16x8 + `f32.load_f16`/`f32.store_f16`), custom page sizes, and the shared
  limit flag.

---

## JSON report changes

### New top-level keys (all reports)

| Key                 | Type   | Meaning                                                  |
| ------------------- | ------ | -------------------------------------------------------- |
| `is_component`      | bool   | `true` when the binary is a Component Model artifact     |
| `strings`           | array  | Extracted strings from data segments (capped at 1000)    |
| `strings_truncated` | bool   | `true` when the string list was capped                   |
| `call_graph`        | object | `nodes`, `edges`, `import_xrefs`, `reachability`, counts |
| `toolchain`         | object | `languages`, `processed_by`, `sdks`, `target_features`   |

### New top-level key (component binaries only)

| Key         | Type   | Meaning                                                                                                                                                  |
| ----------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `component` | object | `component_version`, `layer_version`, `imports`, `exports`, `interfaces`, `interface_packages`, `canonical_options`, `core_modules`, `nested_components` |

For component binaries the section lists (`functions`, `imports`, `exports`,
`tables`, `memories`, `globals`, `data_segments`, `elements`, `tags`,
`strings`) are **aggregations across all nested core modules**; every entry
carries a `core_module` index attributing it to its originating module.
`module_version` is the raw 32-bit version field (e.g. `65549` for version
13 / layer 1).

### Changed shapes

- **`limits` objects** (memories, tables, imported memories/tables) gain two
  keys: `shared` (bool) and `page_size_log2` (int or `null`, custom-page-sizes
  proposal). Exact-dict comparisons will break; key access will not.
  ```json
  { "min": 1, "max": 3, "is_64": true, "shared": true, "page_size_log2": null }
  ```
- **`data_segments[]`** gains `offset_value` (numeric constant offset or
  `null`).
- **`analysis.summary`** gains `unknown_opcode_count` (int) and
  `unknown_opcodes` (sorted distinct mnemonics).
- **`analysis.profiles.control_flow`** gains `export_reachable_functions` and
  `unreachable_functions` counts.

### Renamed / new enum values

- `analysis.detections.wasi.variants`: `"preview2-like"` is renamed to
  **`"preview2"`**. A new **`"preview3"`** variant is emitted when `wasi:*`
  interfaces carry `@0.3.x` versions (WASI 0.3 / async components).
- `analysis.detections.format.kind`: new value **`"component"`** with
  confidence `high` plus `component_version`/`layer_version` fields.
  Behavior change: components used to produce section decode errors and
  `possible-component`; they now parse fully. `possible-component` remains
  only for non-core, non-component binaries this decoder cannot identify.

### New detection blocks and findings

- `analysis.detections.strings` (new): `detected`, `signals`, `counts`,
  `samples`, `string_count`.
- Finding **`WASM-STR-007`** ("Credential-like or IoC strings embedded in
  data segments", severity high, weight 20) fires on URL / mining /
  AWS-key / JWT / PEM signals.
- `WASM-JSCFG-006` evidence optionally includes `paths_from_export`,
  example function-index paths from an exported entrypoint to a dynamically
  dispatched function.
- `WASM-FMT-005` no longer fires for successfully parsed components.

### String entries

Each entry: `{segment_index, byte_offset, memory_offset, length, encoding,
value}`; `encoding` is `"utf-8"` or `"utf-16le"`; `memory_offset` is
`null` for passive segments (unknown placement). In component reports,
entries also carry `core_module`.

### Call graph edges

Edges are `{from, to, kind, offset}`. `kind` is:

- `direct`: exact `call`/`return_call` target.
- `indirect-approx`: over-approximation via element segments for
  `call_indirect`/`return_call_indirect`.
- `typed-approx`: over-approximation via signature types for
  `call_ref`/`return_call_ref`.

Treat `*-approx` edges as candidate call targets, not ground truth. The edge
list is capped at 5000 with `truncated: true`. Limitation: in multi-core-module
components, function indices are per-module index spaces and may collide
across modules; the graph is exact for single-core-module components.

---

## Library API changes (breaking)

In `wasm_tools/parser.py`:

- `BinaryReader.read_limits()` now returns a **5-tuple**
  `(minimum, maximum, is_64, shared, page_size_log2)` (was 3-tuple).
- `BinaryReader.read_init_expr()` now returns `(text, value_or_None)`
  (was just text).

Delegate callbacks (custom visitors must accept the new keyword arguments):

- `on_table(index, ref_type, min, max, is_64, *, shared=False,
page_size_log2=None)`
- `on_memory(index, min, max, is_64, *, shared=False, page_size_log2=None)`
- `on_data(..., *, offset_value=None)`
- `on_import(..., limits_shared=..., limits_page_size_log2=...)` (kwargs on
  table/memory imports)

New optional callbacks (guarded with `hasattr` as before):

- `on_producers_field(field_name, [(name, version), ...])`
- `on_target_feature(enabled: bool, name: str)`

In `wasm_tools/api.py`:

- `parse_wasm_bytes()` / `parse_wasm_file()` now **auto-detect component
  binaries** and return a component report (previously they ran the core
  parser, which produced section errors). Any layer-1 preamble is treated
  as a component, including pre-0x0d versions emitted by older toolchains.
- The parse functions accept optional `strings_min_len` (extraction
  threshold), `include_strings`, and `include_call_graph` parameters so
  consumers can skip the heavier derived blocks (defaults preserve the
  full report).

New modules:

- `wasm_tools/strings.py`: `extract_strings(segments, min_len, max_entries)`,
  `analyze_strings(entries)`.
- `wasm_tools/graph.py`: `build_call_graph(...)`, `sample_paths(...)`.
- `wasm_tools/component.py`: `detect_component(data)`,
  `parse_component_bytes(data, core_parse=...)`.

---

## CLI changes

New flags:

```
--strings                 extract printable strings from data segments
--strings-min-len N       minimum string length, applied at extraction (default 5)
--calls FUNC              outgoing call tree for a function (name or index)
--no-strings              skip string extraction in --json reports
--no-call-graph           skip call graph construction in --json reports
```

`--strings-min-len` is threaded into extraction, so values below the default
do surface short strings. Call-tree markers are deterministic:
`(recursion)` marks a node on the current path, `(seen)` a node already
expanded elsewhere, and `...` the depth cap.

Component binaries now render dedicated text output for `-x`, `--headers`,
and `-d` (per-core-module disassembly). `--json` output for components
includes the `component` block and aggregated sections.

---

## Opcode and limits decoding changes

- Wide arithmetic (`0xFC` sub-opcodes 19-22, no immediates):
  `i64.add128`, `i64.sub128`, `i64.mul_wide_s`, `i64.mul_wide_u`.
- Half precision: `f32.load_f16` / `f32.store_f16` (`0xFC` 48/49, memarg) and
  `f16x8.*` SIMD ops (`0xFD` 288-290 lane ops, 304-316 unary/binary). The
  fp16 proposal defines no new valtype byte; `f16` exists only as SIMD lanes.
- Limits flags: bit 1 (`shared`) is now surfaced, and bit 3 (custom page
  size) consumes the trailing `page_size_log2` u32. **Bug fix**: binaries
  using custom page sizes previously desynchronized the parser at the memory
  section boundary; they now decode correctly.
- `producers` / `target_features` custom sections are decoded (previously
  only their section _names_ were recorded).

---

## Upgrade checklist

1. If you compare `limits` dicts for equality, add `shared` and
   `page_size_log2`.
2. If you switch on `detections.wasi.variants`, replace `"preview2-like"`
   with `"preview2"` and consider handling `"preview3"`.
3. If you treat `detections.format.kind == "possible-component"` as "component
   detected", switch to `is_component` / `kind == "component"`.
4. If you wrote a custom delegate with `on_table`/`on_memory`/`on_data`, add
   the new keyword parameters.
5. If you unpack `read_limits()` or `read_init_expr()` results, update the
   tuple arity.
6. Consider opting into the new surfaces (`strings`, `call_graph`,
   `toolchain`) because they are additive and cheap to ignore.

---

## Changes in 2.1.0

These landed on top of 2.0.0 and are backward compatible under the schema
rule (`summary`, `detections`, `capabilities`, `profiles`, `findings` keep
their shape), which is why 2.1.0 is a minor release. Two of them still change
values you may be reading, which is why they are listed here rather than only
in the [findings reference](FINDINGS.md).

### Values that change for existing keys

- **`types[]` index space now matches the module for GC rec groups.** Every
  member of a `rec` group occupies its own type index, as the spec requires.
  A rec group used to be collapsed into a single entry, so in modules with
  rec groups (Kotlin/Wasm, dart2wasm) `types[]` was short and every later
  index was shifted, including `functions[].signature_index` and
  `call_indirect` type displays. Entries also gain **`kind`** (`func`,
  `struct`, or `array`); composite kinds carry empty `params`/`results`.
- **`WASM-DOS-003` evidence `functions` changed meaning.** The rule now
  requires the `memory.grow` itself to execute inside a loop body, so
  `functions` lists the grow-in-loop functions rather than every function
  with memory traffic inside a loop. The list is capped at 50 with
  `functions_truncated: true` when it applies, and evidence gains
  `loop_memory_grow_ops`. Consumers keying off `functions` will see different
  indices, and known-benign binaries that previously scored `high` from this
  rule (bz2, spidermonkey, ffmpeg, pulldown-cmark) now score `medium`.
- **Legacy exception-handling opcodes decode.** `try` (0x06), `catch` (0x07),
  `rethrow` (0x09), `delegate` (0x18), and `catch_all` (0x19) used to render
  as `unknown_00_xx` and desynchronize the rest of the function body, so
  `summary.unknown_opcodes` shrinks and instruction streams change for
  pre-renumbering binaries.

### Additive keys

- `analysis.capabilities` gains the **`isa.*` namespace** derived from decoded
  instructions and module types (`isa.simd`, `isa.relaxed-simd`,
  `isa.atomics`, `isa.gc`, `isa.function-references`, `isa.tail-call`,
  `isa.memory64`, `isa.wide-arithmetic`, `isa.exceptions`,
  `isa.legacy-exceptions`). These answer engine portability and carry no risk
  weight. Filter on the `isa.` prefix if you treat capabilities as host
  surface only.
- Finding **`WASM-ISA-008`** (relaxed SIMD, severity low, weight 0) is a
  compatibility advisory and does not move the risk score.
- `analysis.profiles.memory` gains `loop_memory_grow_ops`.
- `analysis.detections.format.signals` gains `debug_info_present` for
  unstripped DWARF builds.
- `strings[]` gains an optional **`source`** field. Entries from custom
  sections (currently `"custom:.debug_str"`) set it, have `null`
  `segment_index`/`memory_offset`, use a separate 250-entry budget, and are
  excluded from secret/IoC screening, which stays data-segment only.

### Library API

- New optional delegate callbacks: `on_type_kind(index, kind)`, called before
  `on_type` for every type-section entry, and
  `on_debug_section(name, payload)` for `.debug_*` custom sections. The
  payload is a zero-copy `memoryview`, so a delegate that retains it must
  copy it.
- New `BinaryReader.peek_u8()` reads the byte at the cursor without consuming
  it and raises `WasmParseError` past the end of input. Use it instead of
  indexing `self.data` directly: a raw `IndexError` is swallowed by the
  per-section handler and yields a silently empty section.
- Undecodable type sections now report through `on_error` (unknown composite
  tags, truncated payloads, and nested `rec` groups) and skip to the section
  end instead of decoding later entries from a desynchronized offset.
