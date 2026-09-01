# JSON report reference

This page is the contract for `wasm-tools --json`, `--json-out`, and the library functions `parse_wasm_file` / `parse_wasm_bytes`. Every field below is observable in the test fixtures, and the schema is kept backward compatible within a major version. The 1.x to 2.0.0 changes are listed in [MIGRATION.md](MIGRATION.md).

The report has four zones: top-level decode data, the per-binary entity lists, the component block (component binaries only), and the `analysis` triage layer. The analysis layer is computed after decoding and never changes it.

```mermaid
flowchart LR
    A["decode: sections, functions, instructions"] --> B["report: types, imports, exports, functions, memories, tables, data, elements, tags"]
    A --> C["strings[]"]
    A --> D["call_graph"]
    A --> E["toolchain"]
    B --> F["analysis: summary, detections, capabilities, profiles, findings"]
    C --> F
    D --> F
```

## Top-level fields

| Field            | Type        | Meaning                                                                                                                                        |
| ---------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `file`           | string      | Source path or the caller-supplied label.                                                                                                      |
| `module_version` | int or null | Version from the module header, 1 for core modules. `null` on early parse failure. Components report the raw 32-bit value (for example 65549). |
| `is_component`   | bool        | True when the binary has a Component Model preamble.                                                                                           |
| `section_count`  | int         | Number of recorded sections.                                                                                                                   |
| `sections`       | array       | One entry per section: `index` (encounter order), `id`, `name`, `size`, `offset`.                                                              |
| `function_count` | int         | Number of decoded function bodies.                                                                                                             |
| `functions`      | array       | Locally defined functions, see below.                                                                                                          |
| `errors`         | array       | Parse or read errors as strings. Check this first: non-empty means other fields may be partial.                                                |

Check `errors` before drawing conclusions. A truncated module yields partial data plus an entry such as `Section length extends beyond file boundary`, and the format detection drops to `invalid-core`:

```json
"errors": ["Section length extends beyond file boundary"]
```

## Entity lists

### `types`

Type-section entries: `{"index": 0, "kind": "func", "params": ["i32", "i32"], "results": ["i32"]}`. `kind` is `func`, `struct`, or `array`; composite kinds share the type index space with function signatures (every rec-group member occupies its own index) but carry no params or results. GC subtype and rec-type wrappers are decoded into plain param and result vectors.

### `imports`

| Field                | Present for | Meaning                                             |
| -------------------- | ----------- | --------------------------------------------------- |
| `index`              | all         | Module-global index in the import's index space.    |
| `module`, `name`     | all         | The two-part import name, for example `env`, `log`. |
| `kind`               | all         | `func`, `table`, `memory`, `global`, or `tag`.      |
| `type_index`         | func        | Index into `types`.                                 |
| `valtype`, `mutable` | global      | Declared type and mutability.                       |
| `ref_type`, `limits` | table       | Element type and limits object.                     |
| `limits`             | memory      | Limits object, see below.                           |
| `type_index`         | tag         | Exception tag signature.                            |

The `limits` object is shared by memories and tables: `{"min": 1, "max": null, "is_64": false, "shared": false, "page_size_log2": null}`. Memory `min` and `max` are in 64 KiB pages; `max: null` means unbounded; `is_64` marks Memory64 addressing.

### `exports`

`{"index": 0, "name": "add", "kind": "func", "ref_index": 0}`. `ref_index` points into the corresponding index space (functions for `func`, and so on). An exported `memory` gives the host read and write access to the whole address space, which is normal for Emscripten and wasm-bindgen builds but is still a trust boundary worth recording.

### `functions`

Only locally defined functions appear here; imports are in `imports`.

| Field                 | Meaning                                                     |
| --------------------- | ----------------------------------------------------------- |
| `index`               | Module-global index. Imports occupy the lower indices.      |
| `name`                | From the `name` custom section. Empty string when stripped. |
| `signature_index`     | Index into `types`.                                         |
| `offset`, `body_size` | Byte offset and byte length of the body in the file.        |
| `instructions`        | Decoded instruction list, see below.                        |
| `instruction_count`   | Convenience count.                                          |

Each instruction is `{"offset": 45, "opcode": "i32.load8_u", "immediates": [0, 2]}`. The `offset` is the file position of the opcode byte; `immediates` are decoded values in parse order, so for `call_indirect` they are `[type_index, table_index]`. The key `decode_incomplete` appears only when a body ended in the middle of an instruction record, which happens after unknown opcodes confuse the immediate scan.

### `globals`, `tables`, `memories`, `tags`

`globals` entries are `{"index": 1, "valtype": "f64", "mutable": true, "init": "f64=0"}`, where `init` is the pretty-printed constant initializer expression. `tables` entries carry `ref_type` and the same `limits` object as memories. `tags` entries are `{"index": 0, "type_index": 1}`.

### `data_segments` and `elements`

`data_segments` carries metadata only: `index`, `mode` (`active`, `passive`, or `active` with explicit memory index), `memory_index`, `offset` (pretty-printed init expression), `offset_value` (decoded integer when statically known), and `size`. Segment bytes are intentionally not embedded in the report; decoded string content lives in `strings[]`, and you can hexdump the file at the segment offset for the raw bytes.

`elements` entries are `{"index": 0, "mode": "active", "ref_type": "funcref", "table_index": 0, "offset": "i32=0", "count": 1, "func_indices": [1]}`. These initialize the dispatch tables used by `call_indirect`, which is why the call graph treats them as approximate call edges.

## `strings[]`

Printable strings extracted from data segments, both `utf-8` and `utf-16le`:

```json
{
  "segment_index": 1,
  "byte_offset": 0,
  "memory_offset": 64,
  "length": 20,
  "encoding": "utf-8",
  "value": "AKIAIOSFODNN7EXAMPLE"
}
```

`memory_offset` maps the string into linear memory and is null for passive segments. Unstripped DWARF builds also contribute `.debug_str` content: those entries carry a `source` field (`"custom:.debug_str"`) with null segment and memory provenance, use a separate 250-entry budget so they never crowd out data-segment strings, and do not feed the screening signals. Data-segment entries are capped at 1000 entries with `strings_truncated` set when either cap applies. Extraction is controlled by `strings_min_len` (default 5, CLI flag `--strings-min-len`) and can be disabled with `include_strings=False` in the library or `--no-strings` on the CLI. The `analysis.detections.strings` block screens data-segment values for secrets and indicators; see [findings and signals](FINDINGS.md).

## `call_graph`

A labeled static call graph over the module-global function index space:

```json
{
  "node_count": 4,
  "edge_count": 3,
  "nodes": [
    {
      "index": 0,
      "name": "env.log",
      "imported": true,
      "exported": false,
      "module": "env",
      "import_name": "log"
    },
    { "index": 2, "name": "run", "imported": false, "exported": true }
  ],
  "edges": [
    { "from": 2, "to": 0, "kind": "direct", "offset": 78 },
    { "from": 2, "to": 1, "kind": "indirect-approx", "offset": 84 }
  ],
  "import_xrefs": [
    {
      "func": 0,
      "name": "env.log",
      "module": "env",
      "import_name": "log",
      "call_count": 2,
      "callers": [{ "index": 2, "name": "", "offset": 78 }]
    }
  ],
  "reachability": {
    "roots": [2],
    "reachable_functions": [0, 1, 2],
    "reachable_count": 3,
    "unreachable_functions": [3],
    "unreachable_count": 1
  }
}
```

Edge kinds: `direct` is a resolved `call`; `indirect-approx` is derived from element segments (any function in a table entry could be dispatched); `typed-approx` groups by signature type where no table evidence exists. The approximate kinds are over-approximations by design. Reachability is computed from exports and the start function; `unreachable_functions` is dead code the host can never reach through declared entry points. Skip the block with `--no-call-graph` or `include_call_graph=False`. [Lesson 6](LESSON6.md) works an example.

## `toolchain`

Decoded from the `producers` and `target_features` custom sections:

```json
{
  "languages": ["Rust"],
  "processed_by": ["wasm-bindgen 0.2.x", "rustc 1.x"],
  "sdks": [],
  "target_features": ["mutable-globals", "sign-ext"]
}
```

Empty lists mean the sections were stripped, which is itself a triage observation: production builds commonly strip them.

## `component` (component binaries only)

Present when `is_component` is true. Shape and meaning are covered in the [Component Model page](COMPONENT_MODEL.md): `component_version`, `layer_version`, `imports`, `exports`, `interfaces`, `interface_packages`, `canonical_options`, and fully decoded `core_modules`. For component binaries the shared lists (`sections`, `imports`, `functions`, `strings`) are aggregations across all nested core modules and each entry carries a `core_module` index.

## `analysis`

The triage layer. Full field and rule documentation lives in two places: [findings and signals](FINDINGS.md) for the detection rules, capability tokens, and finding ids, and the [analyst guide](ANALYST_GUIDE.md) for how to use them under time pressure. The shape at a glance:

```json
{
  "summary": {
    "risk_score": 8,
    "risk_tier": "low",
    "finding_count": 0,
    "unknown_opcode_count": 0,
    "unknown_opcodes": []
  },
  "detections": { "wasi": {}, "js_interface": {}, "strings": {}, "format": {} },
  "capabilities": ["host.logging", "js.host", "isa.simd"],
  "profiles": { "memory": {}, "control_flow": {}, "compute": {} },
  "findings": []
}
```

Risk tiers map from the 0 to 100 score: 0 is `none`, 1 to 39 `low`, 40 to 69 `medium`, 70 and above `high`. The score is a weighted triage aid, not a verdict; a self-contained crypto-attack module with no imports scores 0. Capability tokens mix two namespaces: host-surface tokens (`fs.*`, `network`, `host.*`, `js.host`) from imports and instruction-set tokens (`isa.*`) from decoded opcodes; the latter carry no risk weight and answer engine portability instead.

## Stability notes

- Field additions are minor-version changes; removals and renames are major-version changes with a [MIGRATION.md](MIGRATION.md) entry.
- `immediates` ordering follows the binary, not the text format, so `memory.init` immediates are `[data_segment_index, memory_index]`.
- Unknown opcodes decode as `unknown_<prefix>_<opcode>` with no immediates; this is a resiliency behavior, not an error.
- The report is serializable with plain `json.dumps`; the CLI prints it minified with `ensure_ascii=False`.
