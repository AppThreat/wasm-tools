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

| Field             | Type        | Meaning                                                                                                                                        |
| ----------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `file`            | string      | Source path or the caller-supplied label.                                                                                                      |
| `module_version`  | int or null | Version from the module header, 1 for core modules. `null` on early parse failure. Components report the raw 32-bit value (for example 65549). |
| `is_component`    | bool        | True when the binary has a Component Model preamble.                                                                                           |
| `report_contract` | string      | Versioned consumer contract, currently `wasm-tools/2`. Machine consumers switch on this value; the documented top-level keys are additive within a major version. |
| `section_count`   | int         | Number of recorded sections.                                                                                                                   |
| `sections`        | array       | One entry per section: `index` (encounter order), `id`, `name`, `size`, `offset`.                                                              |
| `truncation`      | object      | Present only when instruction budgets applied, see below.                                                                                      |
| `dylink`          | object      | Present only when a `dylink.0` (or legacy `dylink`) custom section exists; see [CUSTOM_SECTIONS.md](CUSTOM_SECTIONS.md).                        |
| `linking`         | object      | Present only when a `linking` custom section exists: symbol table (capped at 500 entries with `symbols_truncated`), segment names, init funcs, target arch. `em_js_segments` counts segments named `__em_js`. |
| `branch_hints`    | object      | Present only when `metadata.code.branch_hint` exists: per-function hint entries with offsets and likely/unlikely values.                       |
| `component_type`  | object      | Present only when a `component-type` custom section exists: version and payload size.                                                          |
| `coredump`        | bool        | True when the coredump convention custom section (`core`) was seen.                                                                             |
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
| `name`                | From the `name` custom section; object-file modules get names from the linking symbol table when the name section is absent (the name section wins where both exist). Empty string when stripped. |
| `demangled_name`      | Present when demangling changes the name (Rust legacy and v0 crate paths); presentation only, never a graph identity. |
| `signature_index`     | Index into `types`.                                         |
| `offset`, `body_size` | Byte offset and byte length of the body in the file.        |
| `local_decls`         | Local declaration groups as `[count, valtype]` pairs, in code-section order. |
| `instructions`        | Decoded instruction list, see below.                        |
| `instruction_count`   | Convenience count; always the pre-trim truth.               |
| `features`            | Per-function structural features, see below.                |
| `cfg`                 | Opt-in (`include_cfg` / `--cfg`) basic-block control-flow graph, see below. |
| `source`              | Present when the DWARF line table maps this function: `{"file": "...", "line": N}`. |
| `instructions_truncated`, `instructions_kept` | Present on functions an instruction budget trimmed. |
| `instructions_omitted` | Present when `include_instructions=False` dropped the stream. |

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

Data-segment entries also carry `entropy`, the byte-level Shannon entropy of the segment payload (rounded to four decimals), which feeding packing analysis and the OBF-010 signal. `memory_offset` maps the string into linear memory and is null for passive segments. Unstripped DWARF builds also contribute `.debug_str` content: those entries carry a `source` field (`"custom:.debug_str"`) with null segment and memory provenance, use a separate 250-entry budget so they never crowd out data-segment strings, and do not feed the screening signals. Data-segment entries are capped at 1000 entries with `strings_truncated` set when either cap applies. Extraction is controlled by `strings_min_len` (default 5, CLI flag `--strings-min-len`) and can be disabled with `include_strings=False` in the library or `--no-strings` on the CLI. The `analysis.detections.strings` block screens data-segment values for secrets and indicators; see [findings and signals](FINDINGS.md).

## `features` and per-function structural data

Every locally defined function carries a `features` object computed during analysis. Boolean and numeric fields are always present so consumers can branch without `get()`:

| Field                          | Meaning |
| ------------------------------ | ------- |
| `instruction_count`            | Pre-trim body length (mirrors the function field). |
| `has_loop`, `max_loop_depth`   | Loop presence and deepest `loop` nesting. |
| `has_direct_call`, `has_indirect_call`, `has_call_ref`, `has_tail_call` | Call-shape flags. |
| `has_table_mutation`, `has_memory_grow`, `has_bulk_memory` | Mutation and growth flags. |
| `has_simd`, `has_atomics`, `has_exceptions`, `has_gc_ops` | Instruction-family flags. |
| `calls_imported_functions`, `imported_callees` | Whether the body calls imported functions and how many distinct ones. Consumers can compose `has_system_call`-style predicates from these plus the called imports' modules. |
| `max_br_table_targets_in_loop` | Widest `br_table` inside a loop (control-flow-flattening signal). |
| `const_branch_density`         | Share of `br_if` with an `i32.const` nearby (reported per function; documented as noise-prone and not fed into findings). |
| `br_table_count`               | Total `br_table` instructions. |
| `body_hash`                    | sha256 over the mnemonic sequence (immediates excluded): two functions with the same instruction shape hash identically regardless of constants. |

These fields mirror what native-binary consumers read from disassembled functions for stripped-binary structural matching (`instruction_count`, `has_loop`, `has_indirect_call` and friends); wasm previously fell back to name-only matching.

## `cfg` (opt-in)

With `include_cfg=True` or `--cfg`, each function gains a basic-block control-flow graph:

```json
{
  "block_count": 3,
  "edge_count": 3,
  "blocks": [
    {"id": 0, "start": 0, "end": 27, "instructions": 12, "labels": ["entry"], "successors": [1, 2]}
  ],
  "loop_headers": [2],
  "unreachable_blocks": [],
  "incomplete": false
}
```

Block ids are dense and ordered by start offset, successors are sorted, and every instruction belongs to exactly one block (asserted across the fixtures). Fan-out past 64 successors truncates the list with a `successors_truncated` marker on the block. Truncated decodes set `incomplete: true`; the CFG is skipped when instruction emission is off. The recovery is structural: dead code after unconditional exits is emitted and marked, never dropped.

## Instruction budgets and truncation

`parse_wasm_bytes` and friends accept `max_instructions_per_function` (hard per-function cap) and `instruction_budget` (max-min fair total budget, applied per core module for components). Trimming runs after analysis, so findings, profiles, and the call graph always describe the full bodies, and `instruction_count` keeps the pre-trim value. Reports with trimming carry:

```json
"truncation": {
  "instructions": {
    "budget": 40, "per_function_cap": null,
    "total_kept": 40, "total_original": 281,
    "truncated_functions": 12, "function_count": 60,
    "core_modules": []
  }
}
```

`core_modules` lists the per-module blocks on component reports. `apply_instruction_budget(report, budget, per_function)` applies the same trimming to an already-built report in place.

`include_instructions=False` (`--no-instructions`) drops emitted instruction streams entirely for metadata-only consumers: analysis, findings, and counts still describe the full decode, and each function is marked `instructions_omitted: true`. On a real clang build this removes over 95 percent of the report.

## Analysis additions

Alongside the blocks documented under findings and signals, the analysis layer carries:

- `features`: the module-wide opcode statistics, see below.
- `dependency_hints`: an evidence-first list of frameworks and interfaces the module demonstrably links against (`wasm-bindgen`, `emscripten` glue, `wasi-preview1`, `rustc`, `clang`, component WIT packages, `fastly-compute`), each with an evidence string and a `high`/`medium` confidence. Core-module imports carry no versions in the binary, so hints state a version only when a producers entry or a versioned interface name states one.
- `provenance`: what built the module and through what glue, see [PROVENANCE.md](PROVENANCE.md). Never changes findings or risk scores.
- `wit_summary` (components): `package_count`, `imported_packages`, `exported_packages` from the parsed WIT structure.

### `analysis.features`

Deterministic opcode statistics for downstream detectors: `opcode_histogram` (per-mnemonic counts, sorted by count then name), `histogram_total`, `distinct_opcodes`, `prefix_counts` (exact counts per prefix family `core`/`fc`/`fb`/`fd`/`fe`, derived from the opcode table), `ngram_top` (capped top bigrams and trigrams over per-function mnemonic sequences; never across function boundaries), and `derived` (size-normalized ratios: memory, call, SIMD, branch density, loop-function share, indirect-call share, f64 arithmetic share, average instructions per function, code and data section shares, function and exported-function counts). Identical input produces identical output; consumers must tolerate unknown mnemonic keys across minor releases. Opt out with `include_features=False` / `--no-features`.

### Vocabulary and evidence contract

Finding `severity` is one of `critical`, `high`, `medium`, `low`, `info`; `confidence` is one of `high`, `medium`, `low`, `none`. Each finding's `evidence` keys are constrained by a registry (`_FINDING_EVIDENCE_KEYS` in `api.py`, enforced by tests) so the shapes downstream converters rely on stay small, named, and stable.

## Custom-section catalog

Well-known custom sections are decoded into the top-level keys listed above; the full catalog with byte layouts lives in [CUSTOM_SECTIONS.md](CUSTOM_SECTIONS.md). Source-level provenance (producers, DWARF strings, toolchain detection) lives in [PROVENANCE.md](PROVENANCE.md).

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

Nodes may also carry `demangled_name` when demangling changes the label; identity stays index-based. On component reports the graph is module-scoped: every node carries `module_id`, every edge carries `from_module` and `to_module`, and node identity is the `(module_id, index)` pair (flattened indices collide across core modules and always did). `canon` edges connect core functions to synthetic `component:type<N>` nodes from the canon lift/lower records. `reachability` becomes a `per_module` map plus component-level counts, and `component_summary` carries module, canon-edge, and synthetic-node counts. Single-module reports never carry these keys.

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

Present when `is_component` is true. Shape and meaning are covered in the [Component Model page](COMPONENT_MODEL.md): `component_version`, `layer_version`, `imports`, `exports`, `interfaces`, `interface_packages`, `wit_packages`, `canonical_options` (including `builtins` counts for the WASI 0.3 async-era canon operations), `canon_records`, `exported_functions`, and fully decoded `core_modules`. For component binaries the shared lists (`sections`, `imports`, `functions`, `strings`) are aggregations across all nested core modules and each entry carries a `core_module` index.

Import and export entries whose names match the WIT interface grammar (`<ns>:<pkg>/<iface>@<version>`, including pre-release versions like `0.3.0-draft`) carry a parsed `wit` object (`namespace`, `package`, `interface`, `version`) and an advisory `suggested_purl` of the form `pkg:wasm/<ns>/<pkg>@<version>`. The `wasm` purl type is not registered in package-url/purl-spec yet, so treat the suggestion as a proposal-shaped label; consumers may map it to `pkg:generic` instead. WASI 0.3.1 name attributes (`implements`, `version-suffix`, `external-id`) surface as `attributes` lists, and an `implements` attribute feeds interface listing and WASI variant detection because a plain-named import can carry the real interface there.

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
