# Findings and signals

The `analysis` block distills the decoded report into detections, capability tokens, behavior profiles, and rule-based findings. This page documents every rule exactly as implemented, including thresholds and severities, so you can reason about why a finding fired and when one should have fired but did not.

The whole layer is heuristic. It exists to rank modules for human review, not to prove exploitability. Absence of findings is not evidence of safety.

## Detection blocks

### `detections.wasi`

Import-based WASI detection. `detected` is true when WASI namespaces are present; `import_modules` lists them; `import_count` counts the imports; `variants` may include:

| Variant    | Evidence                                                        |
| ---------- | --------------------------------------------------------------- |
| `preview1` | Imports from `wasi_snapshot_preview1`                           |
| `preview2` | Component interfaces in the `wasi:*@0.2.x` family               |
| `preview3` | `wasi:*` interfaces versioned 0.3.x or later (async components) |
| `legacy`   | Imports from the historical `wasi_unstable` namespace           |

Confidence is `high` for normative namespaces and `medium` for partial signals.

### `detections.js_interface`

Detects modules built for JavaScript embedders. Signals and their meanings:

| Signal                          | Meaning                                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| `js_namespace_import`           | At least one import from module `js`                                                    |
| `wasm_builtin_namespace_import` | At least one import from a `wasm:*` builtin namespace                                   |
| `wbindgen_pattern`              | `wbg` imports, or any import or export name starting `__wbindgen` or `__wbg_`           |
| `emscripten_pattern`            | Import or export names containing `emscripten` or starting `invoke_`                    |
| `env_glue_import`               | `env` imports with glue-shaped names (log, print, console, emscripten, invoke\_, abort) |

Confidence is `high` when `js_namespace_import` or `wasm_builtin_namespace_import` is present, `medium` when only name-pattern signals fired, and `none` when no signals fired. The block also carries three structural sub-objects used for boundary triage:

- `signature_surface`: inventory of import and export signatures with a `risks` list. Risk tokens: `externref_i64_mix` (tagged refs and 64-bit values cross the same boundaries, raising return-materialization complexity), `multi_result_boundary` (multiple results across the boundary), `ref_numeric_mix` (refs and numerics mixed in one signature). `risky_boundary_count` summarizes how many entries carry at least one risk.
- `risky_import_signatures`: the individual imports whose signatures triggered risks, each with `reasons`.
- `entry_trampolines`: exported or start-reachable functions that look like glue trampolines, with the `risk_ops` that earned the classification (for example `i32.wrap_i64`, `table.set`).

### `detections.strings`

Screening of `strings[]`. Signals, the regex shapes behind them, and masking behavior:

| Signal             | Matched shape                                                       |
| ------------------ | ------------------------------------------------------------------- |
| `url`              | `http(s)://`, `ws(s)://`, `ftp://` endpoints                        |
| `ipv4`             | Dotted-quad address outside a URL                                   |
| `domain`           | Bare hostname against a curated public-suffix list                  |
| `aws_access_key`   | `AKIA` followed by 16 characters, masked to the prefix              |
| `jwt_token`        | Three-segment `eyJ...` shape, truncated in samples                  |
| `pem_private_key`  | `-----BEGIN ... PRIVATE KEY-----` header                            |
| `base64_blob`      | 24 or more base64 characters, sample truncated                      |
| `hex_blob`         | 16 or more hex bytes, sample truncated                              |
| `high_entropy`     | Printable run with Shannon entropy of 4.5 or more, sample truncated |
| `mining_indicator` | `stratum+tcp`, cryptonight, monero, xmr, miner markers              |

The block reports `counts` per signal and masked `samples`. Full unmasked values are in `strings[]` with their linear-memory offsets, so reports and CI logs do not carry live secrets by default. Screening covers data-segment strings only; `.debug_str` payloads are extracted into `strings[]` with a `source` provenance field for the analyst but do not feed these signals.

### `detections.format`

Classifies the binary: `core` (standard module), `component` (parsed component), `possible-component` (component-like bytes this decoder could not parse), or `invalid-core` (magic matches but structure is broken). `signals` lists the evidence tokens, for example `parse_errors` or `debug_info_present` (unstripped DWARF sections are present, so build paths and symbol names ride along). A non-`core` kind for a file you expected to be a plain module is itself a triage event.

## Capability tokens

Capabilities come from two sources, deduplicated into `analysis.capabilities`: import surface (what the module asks of its host) and decoded instructions (which engine features the bytecode actually needs). The exact mapping:

| Token               | Trigger                                                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `fs.path`           | `wasi_snapshot_preview1` imports starting with `path_`; preview2 interface names containing filesystem, path, or descriptor |
| `fs.io`             | `fd_` prefixed preview1 imports; preview2 names containing read, write, or stream                                           |
| `network`           | `sock_` prefixed preview1 imports; preview2 names containing socket or network                                              |
| `crypto.random`     | `random_get`, or preview2 names containing random                                                                           |
| `process.terminate` | `proc_exit`, preview2 names containing exit or terminate, or `env`/`js`/`wbg` imports containing abort                      |
| `clock.high_res`    | `clock_time_get`, `poll_oneoff`, or preview2 clock names                                                                    |
| `host.memory`       | A memory import                                                                                                             |
| `host.table`        | A table import                                                                                                              |
| `host.global`       | A global import                                                                                                             |
| `host.tag`          | A tag import                                                                                                                |
| `host.logging`      | `env`/`wbg`/`js` imports whose names contain log or print                                                                   |
| `js.host`           | Any import from `wbg` or `js`                                                                                               |

Instruction-set tokens (portability: they answer whether a given engine can run the module at all, before any behavior question):

| Token                     | Trigger                                                                                                                                                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `isa.simd`                | Any `v128`/lane-prefixed vector opcode (`i8x16.`, `f32x4.`, `f16x8.`, and friends)                                                                                                                                                                                        |
| `isa.relaxed-simd`        | Any relaxed SIMD opcode (`*.relaxed_*`)                                                                                                                                                                                                                                   |
| `isa.atomics`             | Any `*.atomic.*` opcode or `atomic.fence`                                                                                                                                                                                                                                 |
| `isa.gc`                  | Any struct/array instruction, `ref.i31`, `ref.test`, `ref.cast`, `br_on_cast`, `ref.eq`, or extern/any conversion, or a `struct`/`array` type definition (type-heavy Kotlin/Wasm and dart2wasm modules need GC support to load even before they execute a GC instruction) |
| `isa.function-references` | `call_ref`, `return_call_ref`, `ref.as_non_null`, `br_on_null`, or `br_on_non_null`                                                                                                                                                                                       |
| `isa.tail-call`           | `return_call`, `return_call_indirect`, or `return_call_ref`                                                                                                                                                                                                               |
| `isa.memory64`            | A declared or imported memory with 64-bit index type                                                                                                                                                                                                                      |
| `isa.wide-arithmetic`     | `i64.add128`, `i64.sub128`, or `i64.mul_wide_*`                                                                                                                                                                                                                           |
| `isa.exceptions`          | `try_table`, `throw`, or `throw_ref` (final exception encoding; `throw` shares its opcode with the legacy encoding, so a legacy-EH module can carry both tokens)                                                                                                          |
| `isa.legacy-exceptions`   | `try`, `catch`, `rethrow`, `delegate`, or `catch_all` (pre-renumbering encoding still accepted by V8)                                                                                                                                                                     |

An empty list means no host interaction was detected from imports alone. It does not mean the module is harmless; it means the decode surface is silent.

## Behavior profiles

Three counters groups computed over decoded instructions:

| Group                   | Fields                                                                                                                                                | Reading                                                                                                                                                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `profiles.memory`       | `memory_access_ops`, `memory_grow_ops`, `loop_memory_grow_ops`, `bulk_memory_ops`, `data_segment_total_bytes`                                         | Memory pressure. Any `memory_grow_ops` deserves a note, and `loop_memory_grow_ops` is the subset that runs inside a loop body and feeds DOS-003; large `data_segment_total_bytes` means embedded data worth extracting. |
| `profiles.control_flow` | `indirect_call_ops`, `table_mutation_ops`, `callsite_conversion_ops`, `call_ref_unguarded_ops`, `export_reachable_functions`, `unreachable_functions` | Dispatch complexity. High indirect counts plus table writes are the CFG-002 pattern; `callsite_conversion_ops` counts conversion and cast ops near call sites and is a glue-pressure metric.                            |
| `profiles.compute`      | `max_loop_depth`, `loop_memory_ops`, `loop_branch_ops`                                                                                                | Compute amplification. Depth 3 or more feeds LOOP-004.                                                                                                                                                                  |

## Finding rules

Findings are the actionable output: stable ids, severity, confidence, evidence, and remediation text. Every rule, verbatim in behavior:

| ID               | Fires when                                                                                                     | Severity                                                                   | Evidence highlights                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `WASM-CAP-001`   | Capabilities include both `fs.path` and `network`                                                              | high                                                                       | The two capability tokens                                              |
| `WASM-CFG-002`   | At least one `call_indirect` and at least one table mutation op (`table.set`, `table.copy`, and friends)       | high                                                                       | Op counts, the dynamic dispatch functions, the mutating functions      |
| `WASM-DOS-003`   | A `memory.grow` executes inside a loop body (growth plus loop memory traffic alone no longer fires)            | high                                                                       | Growth count, grow-in-loop count, the offending function indices       |
| `WASM-LOOP-004`  | Max loop nesting depth is 3 or more                                                                            | medium                                                                     | The depth value                                                        |
| `WASM-FMT-005`   | Format kind is `possible-component` or `invalid-core`                                                          | medium                                                                     | Kind, signals, module version                                          |
| `WASM-JSCFG-006` | JS interface detected, plus indirect calls and table mutations that are reachable from JS-exposed entry points | high                                                                       | Op counts, exposed dynamic and mutating functions, `paths_from_export` |
| `WASM-STR-007`   | String screening hits `aws_access_key`, `jwt_token`, `pem_private_key`, `mining_indicator`, `url`, or `domain` | high for key, token, PEM, or mining signals; medium for only url or domain | Signal counts and masked samples                                       |
| `WASM-ISA-008`   | Any relaxed SIMD opcode is present                                                                             | low                                                                        | Relaxed opcode count and the opcode names                              |

Confidence is `high` for CAP-001 (the evidence is the import list itself) and ISA-008 (the opcodes are decoded directly), and `medium` for the heuristic rules. Use the ids in tickets and detection rules; they are stable.

DOS-003 matches lexically: the `memory.grow` must sit inside a loop body in the same function. A growth helper called from a loop does not fire it, so pair the finding with `profiles.memory.memory_grow_ops` and the [call graph](JSON_REFERENCE.md) when growth appears in a small callee.

## Risk scoring

The score is a bounded 0 to 100 sum. Capability weights:

| Token               | Weight | Token            | Weight |
| ------------------- | ------ | ---------------- | ------ |
| `network`           | 12     | `host.table`     | 3      |
| `fs.path`           | 10     | `host.memory`    | 3      |
| `fs.io`             | 8      | `clock.high_res` | 4      |
| `process.terminate` | 8      | `crypto.random`  | 2      |
| `js.host`           | 6      | `host.global`    | 2      |
|                     |        | `host.tag`       | 2      |
|                     |        | `host.logging`   | 2      |

Each active finding adds its own weight, and the total is clamped at 100. Finding weights:

| ID                 | Weight | ID               | Weight                     |
| ------------------ | ------ | ---------------- | -------------------------- |
| `WASM-CAP-001`     | 30     | `WASM-FMT-005`   | 10                         |
| `WASM-DOS-003`     | 30     | `WASM-JSCFG-006` | 20                         |
| `WASM-CFG-002`     | 25     | `WASM-STR-007`   | 20                         |
| `WASM-LOOP-004`    | 15     | `WASM-ISA-008`   | 0 (compatibility advisory) |
| unknown future ids | 5      |                  |                            |

Tier buckets: 0 is `none`, 1 to 39 `low`, 40 to 69 `medium`, 70 and above `high`. Treat the score as a queue priority. The real review decision still happens in the disassembly.

## Unknown opcode telemetry

`summary.unknown_opcode_count` and `summary.unknown_opcodes` list instructions that fell back to `unknown_<prefix>_<opcode>` names. This is not a parse error; it is a signal that the binary uses opcodes newer than the table. When you see it, check the [spec coverage matrix](COVERAGE.md) and the release notes, then re-run with a current version.
