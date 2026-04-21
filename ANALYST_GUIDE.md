# Analyst Guide — WebAssembly Security Triage with wasm-tools

This document is written for junior security analysts and developers who need to triage unknown `.wasm` files. It explains the binary format in plain terms, walks through every field in the JSON output, and gives concrete decision recipes for the most common security questions.

---

## Table of Contents

1. [What is a `.wasm` file?](#1-what-is-a-wasm-file)
2. [The eight-byte header — the first thing to verify](#2-the-eight-byte-header)
3. [Sections — the building blocks](#3-sections)
4. [Running the tool](#4-running-the-tool)
5. [JSON report walkthrough](#5-json-report-walkthrough)
   - [Top-level metadata](#51-top-level-metadata)
   - [sections](#52-sections)
   - [types](#53-types)
   - [imports](#54-imports)
   - [exports](#55-exports)
   - [functions](#56-functions)
   - [globals, tables, memories](#57-globals-tables-memories)
   - [data_segments and elements](#58-data_segments-and-elements)
   - [tags](#59-tags)
   - [errors](#510-errors)
6. [The analysis block](#6-the-analysis-block)
   - [summary](#61-summary)
   - [detections.wasi](#62-detectionswasi)
   - [detections.js_interface](#63-detectionsjs_interface)
   - [detections.format](#64-detectionsformat)
   - [capabilities](#65-capabilities)
   - [profiles](#66-profiles)
   - [findings](#67-findings)
7. [Triage recipes](#7-triage-recipes)
   - [Is this module WASI?](#71-is-this-module-wasi)
   - [Does this module call into JavaScript?](#72-does-this-module-call-into-javascript)
   - [What host resources can this module reach?](#73-what-host-resources-can-this-module-reach)
   - [Is this module obfuscated or adversarial?](#74-is-this-module-obfuscated-or-adversarial)
   - [What does this module expose to its host?](#75-what-does-this-module-expose-to-its-host)
   - [Could this loop forever or exhaust memory?](#76-could-this-loop-forever-or-exhaust-memory)
8. [Import and export kind reference](#8-import-and-export-kind-reference)
9. [Capability token reference](#9-capability-token-reference)
10. [Finding ID reference](#10-finding-id-reference)
11. [JS interface signal reference](#11-js-interface-signal-reference)
12. [Worked examples](#12-worked-examples)
    - [Example A — minimal arithmetic module](#example-a--minimal-arithmetic-module)
    - [Example B — wasm-bindgen JS interface module](#example-b--wasm-bindgen-js-interface-module)
13. [Glossary](#13-glossary)

---

## 1. What is a `.wasm` file?

A `.wasm` file is a **compiled binary program** designed to run inside a WebAssembly runtime. Think of it as a cross-platform bytecode, similar to a Java `.class` file or a .NET assembly. Unlike a native ELF or PE binary, a WebAssembly module:

- **cannot access memory outside its own linear memory sandbox** by default.
- **cannot make system calls directly**. Every interaction with the outside world (filesystem, network, DOM) must go through _imported functions_ that the host environment provides.
- **cannot execute native instructions**. A runtime validates and compiles it first.

This makes the import and export sections the most security-relevant parts of the file: they are the complete list of how the module touches the outside world.

---

## 2. The eight-byte header

Every valid `.wasm` file starts with exactly these eight bytes:

```
Offset  Bytes          Meaning
------  -------------  -----------------------------------------------
0x00    00 61 73 6D    Magic number — ASCII "\0asm"
0x04    01 00 00 00    Module version — always 1 for core WebAssembly
```

If the file does not start with `00 61 73 6D`, it is not a WebAssembly module. The tool will report this as a parse error in `report["errors"]`.

You can verify this manually:

```bash
xxd your_file.wasm | head -1
# Expected: 00000000: 0061 736d 0100 0000  ...
```

---

## 3. Sections

After the header, the file is a linear sequence of **sections**. Each section has:

- A **one-byte section ID** (0–13; ID 0 is "custom").
- A **LEB128-encoded byte count** telling the reader how long the section is.
- The **section payload**.

The sections and what they tell you at a glance:

| ID  | Name       | Security relevance                                                                                                |
| --- | ---------- | ----------------------------------------------------------------------------------------------------------------- |
| 0   | Custom     | Arbitrary data. Subsection `name` holds debug symbols. Other names may be toolchain metadata or embedded strings. |
| 1   | Type       | Function signatures. Shows what parameter/return types the module was compiled with.                              |
| 2   | **Import** | **Critical.** Every external dependency. Functions here are the module's attack surface toward its host.          |
| 3   | Function   | Maps local function indices to type indices.                                                                      |
| 4   | Table      | Indirect call tables. Large tables suggest complex dispatch (more difficult to audit).                            |
| 5   | Memory     | Linear memory declarations. Tells you the initial and maximum memory size (in 64 KiB pages).                      |
| 6   | Global     | Module-level variables. Mutable globals persist across calls.                                                     |
| 7   | **Export** | **Critical.** What the module exposes to the host. Functions here can be called by JavaScript or a WASI runtime.  |
| 8   | Start      | A function called automatically on instantiation, before anything else. Check what this does.                     |
| 9   | Element    | Initialises function reference tables. Relevant for indirect call analysis.                                       |
| 10  | Code       | The function bodies. This is where the actual instructions live.                                                  |
| 11  | Data       | Byte blobs written into linear memory at startup. May contain strings, keys, or configuration.                    |
| 12  | DataCount  | Declares the number of data segments (required for bulk memory operations).                                       |
| 13  | Tag        | Exception tag declarations (WebAssembly exception handling proposal).                                             |

---

## 4. Running the tool

**Get JSON output (best for scripting and triage):**

```bash
wasm-tools module.wasm --json
```

**Pipe to `jq` for quick field extraction:**

```bash
wasm-tools module.wasm --json | jq '.analysis.detections'
wasm-tools module.wasm --json | jq '.imports'
wasm-tools module.wasm --json | jq '.analysis.summary'
```

**See a disassembly of function bodies:**

```bash
wasm-tools module.wasm -d
```

**See full section detail in human-readable form:**

```bash
wasm-tools module.wasm -x
```

**See just the section header table:**

```bash
wasm-tools module.wasm --headers
```

**From Python:**

```python
from wasm_tools.api import parse_wasm_file

report = parse_wasm_file("module.wasm")

# Risk tier: "none", "low", "medium", "high"
print(report["analysis"]["summary"]["risk_tier"])

# All imports
for imp in report["imports"]:
    print(imp["module"], imp["name"], imp["kind"])
```

---

## 5. JSON report walkthrough

### 5.1 Top-level metadata

```json
{
  "file": "tests/fixtures/js_interface.wasm",
  "module_version": 1,
  "section_count": 5,
  ...
  "errors": []
}
```

| Field            | Type    | What it tells you                                                       |
| ---------------- | ------- | ----------------------------------------------------------------------- |
| `file`           | string  | Path of the analysed file.                                              |
| `module_version` | integer | Always `1` for current core WebAssembly. Any other value is unusual.    |
| `section_count`  | integer | Total number of sections found. Helps spot stripped or minimal modules. |
| `errors`         | list    | Parse errors. Non-empty means the file is malformed or truncated.       |

> **Tip:** Always check `errors` first. If it is non-empty, all other data may be incomplete.

---

### 5.2 `sections`

```json
"sections": [
  {"index": 0, "id": 1, "name": "Type",   "size": 18, "offset": 10},
  {"index": 1, "id": 2, "name": "Import", "size": 65, "offset": 30},
  ...
]
```

| Field    | What it tells you                                                                                             |
| -------- | ------------------------------------------------------------------------------------------------------------- |
| `id`     | Numeric section ID (see table in §3 above).                                                                   |
| `name`   | Human-readable section name.                                                                                  |
| `size`   | Byte count of the payload. Disproportionately large `Code` or `Data` sections can indicate embedded payloads. |
| `offset` | Byte offset from the start of the file. Useful for hex editor navigation.                                     |

> **Tip:** A missing `Import` section means the module has no external dependencies — it is entirely self-contained. A missing `Export` section means the host cannot call into it (probably a start-only or data-only module).

---

### 5.3 `types`

```json
"types": [
  {"index": 0, "params": ["i32"],        "results": []},
  {"index": 1, "params": ["i32", "i32"], "results": []},
  {"index": 2, "params": ["i32"],        "results": ["i32"]}
]
```

These are the **function signatures** the module declares. Imports and locally-defined functions both reference entries in this table by index.

Value types you will see:

| Type        | Meaning                                                          |
| ----------- | ---------------------------------------------------------------- |
| `i32`       | 32-bit integer — the most common type.                           |
| `i64`       | 64-bit integer — often used with `BigInt` in JS.                 |
| `f32`/`f64` | 32/64-bit float.                                                 |
| `v128`      | 128-bit SIMD vector — indicates SIMD usage.                      |
| `externref` | A reference to an opaque host object (JS value, DOM node, etc.). |
| `funcref`   | A reference to a function. Used in indirect calls.               |

> **Tip:** A type with `externref` in its params or results is a strong signal that this function is designed to exchange JavaScript values with the host.

---

### 5.4 `imports`

```json
"imports": [
  {"index": 0, "module": "js",             "name": "console_log",      "kind": "func", "type_index": 0},
  {"index": 1, "module": "wbg",            "name": "__wbindgen_throw",  "kind": "func", "type_index": 1},
  {"index": 2, "module": "wasm:js-string", "name": "length",           "kind": "func", "type_index": 2}
]
```

This is the **most important section for security triage.** Every row is something the module cannot run without — the host must provide it.

| Field        | What it tells you                                                                                                                                                    |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `module`     | The "namespace" the import comes from. `wasi_snapshot_preview1` = WASI. `js` or `env` = generic JS host. `wbg` = wasm-bindgen (Rust→JS). `wasm:*` = JS API builtins. |
| `name`       | The specific function/memory/global/table being requested.                                                                                                           |
| `kind`       | `func`, `memory`, `table`, `global`, or `tag`. See §8 for what each means.                                                                                           |
| `type_index` | For `func` imports — index into the `types` array above. Look up the signature.                                                                                      |

**Common `module` values and what they mean:**

| `module` value           | Origin / host environment                                       |
| ------------------------ | --------------------------------------------------------------- |
| `wasi_snapshot_preview1` | WASI preview 1 — Linux-like system calls (files, sockets, args) |
| `wasi_snapshot_preview2` | WASI preview 2 — component model ABI                            |
| `js`                     | Generic JavaScript host                                         |
| `env`                    | Common Emscripten / generic C ABI host                          |
| `wbg`                    | wasm-bindgen (Rust compiled to WebAssembly for the browser)     |
| `wasm:js-string`         | JS API builtin — efficient string operations                    |
| `wasm:text-encoder`      | JS API builtin — text encoding                                  |
| `wasm:text-decoder`      | JS API builtin — text decoding                                  |
| `metering`               | Gas metering injection (often from instrumentation tools)       |

---

### 5.5 `exports`

```json
"exports": [
  {"index": 0, "name": "run",              "kind": "func", "ref_index": 3},
  {"index": 1, "name": "__wbindgen_start", "kind": "func", "ref_index": 4}
]
```

Exports are what the host (a browser, Node.js, WASI runner, or embedder) can **call or read**.

| Field       | What it tells you                                                                   |
| ----------- | ----------------------------------------------------------------------------------- |
| `name`      | The external-facing name. This is what JavaScript or a WASI runner calls.           |
| `kind`      | `func`, `memory`, `table`, `global`, or `tag`.                                      |
| `ref_index` | Index into the corresponding internal array (functions, memories, tables, globals). |

**Notable export name patterns:**

| Export name pattern | Likely origin / meaning                                               |
| ------------------- | --------------------------------------------------------------------- |
| `memory`            | Exposes the linear memory buffer — the host can read/write it freely  |
| `__wbindgen_start`  | wasm-bindgen module initializer — called automatically by the glue JS |
| `__wbindgen_*`      | wasm-bindgen ABI glue functions                                       |
| `_start`            | WASI entry point (like `main()`)                                      |
| `_initialize`       | WASI reactor pattern (library, not application)                       |
| `malloc` / `free`   | Exposes allocator — JS can allocate/free wasm memory                  |
| `invoke_*`          | Emscripten dynamic dispatch trampolines                               |

> **Tip:** A module that exports `memory` gives the JavaScript host unrestricted read/write access to its entire address space. This is normal for wasm-bindgen and Emscripten modules but is a meaningful trust boundary to note.

---

### 5.6 `functions`

```json
"functions": [
  {
    "index": 3,
    "name": "",
    "signature_index": 3,
    "offset": 130,
    "body_size": 6,
    "instructions": [
      {"offset": 133, "opcode": "i32.const", "immediates": [1]},
      {"offset": 135, "opcode": "call",      "immediates": [0]},
      {"offset": 137, "opcode": "end",       "immediates": []}
    ],
    "instruction_count": 3
  }
]
```

Only **locally-defined** functions appear here — imported functions are in `imports`, not `functions`.

| Field               | What it tells you                                                            |
| ------------------- | ---------------------------------------------------------------------------- |
| `index`             | Global function index. Imports occupy the lower indices; locals start after. |
| `name`              | From the `name` custom section (debug info). Empty string if stripped.       |
| `signature_index`   | Index into `types`. Look up the function's parameter and return types.       |
| `offset`            | Byte offset of the function body in the file.                                |
| `body_size`         | Byte count of the function body. Very large bodies merit closer inspection.  |
| `instructions`      | Decoded instruction sequence with offsets and immediates.                    |
| `instruction_count` | Total instruction count. Very high counts indicate generated code.           |

**Reading instructions:** An instruction's `immediates` list contains the operand values:

```json
{"opcode": "call",      "immediates": [0]}   // calls function index 0
{"opcode": "i32.const", "immediates": [42]}  // pushes the integer 42
{"opcode": "call_indirect", "immediates": [2, 0]}  // indirect call via type 2, table 0
```

> **Tip:** A `call_indirect` instruction means the exact function called is determined at runtime by the value on the stack — it's like a C function pointer. Modules with many `call_indirect` instructions are harder to statically audit.

---

### 5.7 `globals`, `tables`, `memories`

```json
"globals":  [{"index": 0, "valtype": "i32", "mutable": true,  "init_expr": "i32.const 0"}],
"tables":   [{"index": 0, "ref_type": "funcref", "min": 10, "max": null, "is_64": false}],
"memories": [{"index": 0, "min": 1, "max": null, "is_64": false}]
```

**Globals** — module-level variables. Mutable globals that are exported give the host read-write access to module state.

**Tables** — hold function or object references for indirect calls. A table with a large `min` indicates heavy use of function pointers (common in C/C++ compiled code).

**Memories** — linear memory regions. Sizes are in **pages** where 1 page = 64 KiB.

| `min` pages | Approximate initial memory |
| ----------- | -------------------------- |
| 1           | 64 KiB                     |
| 16          | 1 MiB                      |
| 256         | 16 MiB                     |
| 2048        | 128 MiB                    |

`max: null` means **no upper bound** — the module may grow memory up to the runtime limit (4 GiB for 32-bit, 16 GiB for 64-bit). `is_64: true` indicates a Memory64 module.

---

### 5.8 `data_segments` and `elements`

**`data_segments`** — byte blobs copied into linear memory on startup. These often contain:

- String constants (error messages, paths, embedded configuration)
- Lookup tables
- Embedded resources (fonts, WASM-in-WASM, encoded payloads)

```json
"data_segments": [
  {"index": 0, "mode": "active", "mem_idx": 0, "offset_expr": "i32.const 1024",
   "size": 512, "data_bytes": "68656c6c6f..."}
]
```

`data_bytes` is hex-encoded. The `size` field gives the byte count.

**`elements`** — initialise table entries with function references. Used for indirect call setup.

---

### 5.9 `tags`

Exception tags declared in the module (WebAssembly exception-handling proposal). Rare in most modules. When present, the module uses structured exceptions — either for normal error handling or potentially to abuse exception flow for control obfuscation.

---

### 5.10 `errors`

```json
"errors": ["unexpected end of section at offset 0x1a2b"]
```

Any entry here means the file is malformed. The tool continues as far as it can, so other fields may be partially populated. Always check `errors` before drawing conclusions from the rest of the report.

---

## 6. The `analysis` block

The `analysis` block is computed from the decoded data. It does not change parsing — it is a summary layer added on top.

---

### 6.1 `summary`

```json
"summary": {
  "risk_score": 8,
  "risk_tier": "low",
  "finding_count": 0
}
```

| Field           | Range / values                  | Meaning                                        |
| --------------- | ------------------------------- | ---------------------------------------------- |
| `risk_score`    | 0 – 100 integer                 | Weighted sum of capability and finding scores. |
| `risk_tier`     | `none`, `low`, `medium`, `high` | Bucketed label for the score.                  |
| `finding_count` | integer                         | Number of active `findings` entries.           |

**Tier thresholds** (approximate — subject to change):

| Tier     | Score range | Typical module                                                        |
| -------- | ----------- | --------------------------------------------------------------------- |
| `none`   | 0           | No imports, no findings. Pure compute.                                |
| `low`    | 1–30        | JS host interaction or basic capabilities. Normal browser module.     |
| `medium` | 31–60       | WASI with filesystem/network, or complex indirect control flow.       |
| `high`   | 61–100      | Multiple dangerous capabilities + findings (loop + memory + process). |

> **Important:** The risk score is a **triage aid**, not a verdict. A score of 0 does not mean a module is safe — a module with no imports that implements cryptographic attack primitives would score 0. Always read the imports and capabilities.

---

### 6.2 `detections.wasi`

```json
"detections": {
  "wasi": {
    "detected": true,
    "confidence": "high",
    "import_modules": ["wasi_snapshot_preview1"],
    "import_count": 14,
    "variants": ["preview1"]
  }
}
```

| Field            | What it tells you                                                   |
| ---------------- | ------------------------------------------------------------------- |
| `detected`       | `true` if WASI imports were found.                                  |
| `confidence`     | `high` = normative WASI namespace; `medium` = partial signals only. |
| `import_modules` | Which WASI namespaces were present.                                 |
| `import_count`   | How many WASI imports (more = more syscall surface).                |
| `variants`       | Which WASI version(s): `preview1`, `preview2`, or both.             |

A WASI module is designed to run in a sandboxed CLI environment (like a container). It has access to virtual filesystem, network sockets, environment variables, process exit, and random numbers — but only those that the runner explicitly grants. The `capabilities` list (§6.5) shows the specific ones detected.

---

### 6.3 `detections.js_interface`

```json
"detections": {
  "js_interface": {
    "detected": true,
    "confidence": "high",
    "signals": [
      "js_namespace_import",
      "wasm_builtin_namespace_import",
      "wbindgen_pattern"
    ],
    "import_modules": ["js", "wasm:js-string", "wbg"],
    "import_count": 3,
    "export_count": 1,
    "builtin_sets": ["js-string"],
    "imports": [
      {"module": "js",             "name": "console_log",     "kind": "func"},
      {"module": "wbg",            "name": "__wbindgen_throw", "kind": "func"},
      {"module": "wasm:js-string", "name": "length",          "kind": "func"}
    ],
    "exports": [
      {"name": "__wbindgen_start", "kind": "func"}
    ]
  }
}
```

This detection fires when the module is designed to run inside a JavaScript environment (browser, Node.js, Deno, etc.).

| Field            | What it tells you                                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `detected`       | `true` if any JS interface signals were found.                                                                                         |
| `confidence`     | `high` = unambiguous signals; `medium` = heuristic pattern match only.                                                                 |
| `signals`        | The specific evidence tokens. See §11 for the complete reference.                                                                      |
| `import_modules` | Namespaces of the JS-facing imports.                                                                                                   |
| `import_count`   | Number of JS-facing imports.                                                                                                           |
| `export_count`   | Number of JS glue exports detected.                                                                                                    |
| `builtin_sets`   | JS API builtin sets in use (e.g., `js-string`, `text-encoder`). These are normative per the WebAssembly JS Interface specification §6. |
| `imports`        | Filtered list of only the JS-relevant imports.                                                                                         |
| `exports`        | Filtered list of only the JS glue exports.                                                                                             |

---

### 6.4 `detections.format`

```json
"detections": {
  "format": {
    "kind": "core",
    "confidence": "high",
    "signals": [],
    "module_version": 1
  }
}
```

| `kind` value         | Meaning                                                        |
| -------------------- | -------------------------------------------------------------- |
| `core`               | Standard core WebAssembly module (the vast majority of files). |
| `possible-component` | Byte patterns suggest a WebAssembly Component Model binary.    |
| `invalid-core`       | Magic bytes match but structure is severely malformed.         |

> **Tip:** `possible-component` files require a Component Model-aware tool to fully decode. This tool will parse what it can but may report parse errors on the component-specific sections.

---

### 6.5 `capabilities`

```json
"capabilities": ["host.logging", "js.host"]
```

Capabilities are high-level labels inferred from the import list. Each token maps to a class of host interaction:

| Token          | What the module can do                                |
| -------------- | ----------------------------------------------------- |
| `wasi.fs`      | Read, write, open, close files and directories        |
| `wasi.net`     | Open and use network sockets                          |
| `wasi.proc`    | Terminate the process (`proc_exit`)                   |
| `wasi.env`     | Read environment variables and command-line arguments |
| `wasi.random`  | Generate random bytes (`random_get`)                  |
| `wasi.time`    | Read wall clock or monotonic time                     |
| `wasi.io`      | Async I/O polling (WASI preview 2)                    |
| `host.logging` | Call a host-provided logging/console function         |
| `host.abort`   | Signal an abort or panic to the host                  |
| `js.host`      | General JavaScript host interaction                   |
| `js.dom`       | DOM manipulation                                      |
| `crypto`       | Cryptographic operations (imported from host)         |

An empty `capabilities` list means the module has **no detected host interaction** — it is purely self-contained compute.

---

### 6.6 `profiles`

Profiles summarise opcode-level metrics from the function bodies.

```json
"profiles": {
  "memory": {
    "memory_access_ops":    42,
    "memory_grow_ops":       1,
    "bulk_memory_ops":       0,
    "data_segment_total_bytes": 2048
  },
  "control_flow": {
    "indirect_call_ops":    17,
    "table_mutation_ops":    0
  },
  "compute": {
    "max_loop_depth":        3,
    "loop_memory_ops":       8,
    "loop_branch_ops":       5
  }
}
```

**`memory` profile:**

| Field                      | Security relevance                                                     |
| -------------------------- | ---------------------------------------------------------------------- |
| `memory_access_ops`        | High count = memory-intensive code. Normal for crypto, compression.    |
| `memory_grow_ops`          | Each `memory.grow` expands the sandbox. Any non-zero is worth noting.  |
| `bulk_memory_ops`          | `memory.copy`, `memory.fill`, `memory.init` — efficient bulk moves.    |
| `data_segment_total_bytes` | Total bytes of embedded data — may contain strings, keys, or payloads. |

**`control_flow` profile:**

| Field                | Security relevance                                                       |
| -------------------- | ------------------------------------------------------------------------ |
| `indirect_call_ops`  | Number of `call_indirect` instructions. High = hard to statically audit. |
| `table_mutation_ops` | `table.set` / `table.copy` — mutations to function pointer tables.       |

**`compute` profile:**

| Field             | Security relevance                                                            |
| ----------------- | ----------------------------------------------------------------------------- |
| `max_loop_depth`  | Deeply nested loops (`> 5`) may indicate obfuscation or algorithm complexity. |
| `loop_memory_ops` | Memory ops inside loops — pattern for buffer scanning or crypto rounds.       |
| `loop_branch_ops` | Branch-heavy loops — pattern for parsers, state machines.                     |

---

### 6.7 `findings`

Findings are rule-based detections with stable IDs.

```json
"findings": [
  {
    "id":         "WASM-DOS-003",
    "severity":   "medium",
    "confidence": "medium",
    "title":      "Potential resource exhaustion",
    "description": "Module imports memory.grow and has unbounded loop nesting ...",
    "evidence":   {"memory_grow_ops": 3, "max_loop_depth": 6},
    "remediation": "Review memory growth strategy; consider bounding loop depth."
  }
]
```

| Field         | What it tells you                                                  |
| ------------- | ------------------------------------------------------------------ |
| `id`          | Stable rule identifier. Use this in tickets and SIEM rules.        |
| `severity`    | `low`, `medium`, or `high`. Reflects worst-case impact.            |
| `confidence`  | `low`, `medium`, or `high`. Reflects how certain the detection is. |
| `title`       | Short human-readable label.                                        |
| `description` | Full explanation of why this finding was raised.                   |
| `evidence`    | Key metrics that triggered the rule.                               |
| `remediation` | Suggested action for the module author.                            |

See §10 for the complete finding ID reference.

---

## 7. Triage recipes

### 7.1 Is this module WASI?

```bash
wasm-tools module.wasm --json | jq '.analysis.detections.wasi'
```

**Yes, high confidence** → module imports from `wasi_snapshot_preview1` or `wasi_snapshot_preview2`. Check `.analysis.capabilities` to see which system call families are used. A WASI module run through a properly configured runtime (e.g., Wasmtime with explicit `--dir` grants) is well-sandboxed.

**No** → either a browser/JS module or a self-contained compute module.

---

### 7.2 Does this module call into JavaScript?

```bash
wasm-tools module.wasm --json | jq '.analysis.detections.js_interface'
```

**`detected: true, confidence: "high"`** → the module has clear JS interop. Look at `.imports` filtered by `module` values `js`, `wbg`, `env`, or `wasm:*`.

**`builtin_sets` is non-empty** → the module uses normative WebAssembly JS API builtins (e.g., `js-string`). These are well-defined per spec; review the function names to understand exactly which JS string operations are called.

**`wbindgen_pattern` in `signals`** → Rust compiled with wasm-bindgen. The `__wbindgen_*` functions are ABI glue — review the higher-level exports (`run`, application-named functions) for actual functionality.

---

### 7.3 What host resources can this module reach?

```bash
wasm-tools module.wasm --json | jq '.analysis.capabilities'
```

Then cross-reference with the imports:

```bash
wasm-tools module.wasm --json | jq '.imports[] | select(.module == "wasi_snapshot_preview1") | .name'
```

If you see `fd_write`, `fd_read`, `path_open` — the module can do file I/O.
If you see `sock_open`, `sock_recv`, `sock_send` — the module can do networking.
If you see `proc_exit` — the module can terminate the host process.

---

### 7.4 Is this module obfuscated or adversarial?

Warning signs to look for in sequence:

1. **`errors` is non-empty** — file is malformed. Could be truncation, corruption, or deliberate fuzz.
2. **`format.kind == "possible-component"`** — if you expected a core module, something unusual is going on.
3. **`functions` have no names** (`"name": ""` on all entries) — debug info is stripped. Normal for production builds but limits auditability.
4. **High `indirect_call_ops` with no function names** — indirect dispatch through stripped tables is very hard to trace statically.
5. **Very large `body_size`** on a small number of functions — monolithic generated code; common in heavy obfuscation or transpiled code.
6. **Data segments with high entropy** — may contain embedded encrypted payloads. Check `data_bytes` field.
7. **`findings` contains `WASM-CFG-002`** — unusual control flow complexity detected.

---

### 7.5 What does this module expose to its host?

```bash
wasm-tools module.wasm --json | jq '.exports'
```

Pay particular attention to:

- **`memory` exported** — host can read/write all module memory.
- **Functions with security-sensitive names** — `execute`, `eval`, `run_script`, etc.
- **`__wbindgen_start` or `_start` exported** — an automatic initialiser runs on instantiation without the host explicitly calling it.

---

### 7.6 Could this loop forever or exhaust memory?

```bash
wasm-tools module.wasm --json | jq '.analysis.profiles.compute'
wasm-tools module.wasm --json | jq '.analysis.profiles.memory'
wasm-tools module.wasm --json | jq '.analysis.findings[] | select(.id == "WASM-DOS-003")'
```

`WASM-DOS-003` fires when both `memory_grow_ops > 0` and `max_loop_depth` exceeds a threshold, suggesting a module that may grow memory inside a loop. This is the classic pattern for a memory exhaustion DoS.

---

## 8. Import and export kind reference

| `kind` value | What is being imported or exported                                                            |
| ------------ | --------------------------------------------------------------------------------------------- |
| `func`       | A function. For imports: the host must provide a callable. For exports: the host can call it. |
| `memory`     | A linear memory buffer. Only one memory per module in most cases.                             |
| `table`      | A reference table. Used for indirect function calls.                                          |
| `global`     | A module-level scalar value. Can be mutable or immutable.                                     |
| `tag`        | An exception tag (WebAssembly exception-handling proposal).                                   |

---

## 9. Capability token reference

| Token          | Triggered by import names                                                    |
| -------------- | ---------------------------------------------------------------------------- |
| `wasi.fs`      | `fd_read`, `fd_write`, `fd_seek`, `path_open`, `path_create_directory`, etc. |
| `wasi.net`     | `sock_open`, `sock_recv`, `sock_send`, `sock_accept`                         |
| `wasi.proc`    | `proc_exit`                                                                  |
| `wasi.env`     | `environ_get`, `args_get`, `environ_sizes_get`                               |
| `wasi.random`  | `random_get`                                                                 |
| `wasi.time`    | `clock_time_get`, `clock_res_get`                                            |
| `wasi.io`      | `poll_oneoff`, `wasi:io/streams`, `wasi:io/poll`                             |
| `host.logging` | Any import named `log`, `console_log`, `print`, `write` from `js`/`env`      |
| `host.abort`   | Any import named `abort`, `_abort`, `__abort` from `env`/`js`                |
| `js.host`      | Imports from `js`, `wbg`, `env` namespaces                                   |
| `js.dom`       | Imports with DOM-related names (`document`, `window`, `element`, etc.)       |
| `crypto`       | Imports named `crypto_*`, `subtle`, or similar from any namespace            |

---

## 10. Finding ID reference

| ID              | Severity | Title                         | Fires when                                                            |
| --------------- | -------- | ----------------------------- | --------------------------------------------------------------------- |
| `WASM-CAP-001`  | medium   | Sensitive host capabilities   | Module imports process termination, network sockets, or both FS + net |
| `WASM-CFG-002`  | low      | High indirect call complexity | `indirect_call_ops > 20` or `table_mutation_ops > 0`                  |
| `WASM-DOS-003`  | medium   | Potential resource exhaustion | `memory_grow_ops > 0` and `max_loop_depth > threshold`                |
| `WASM-LOOP-004` | low      | Deep loop nesting             | `max_loop_depth > 5`                                                  |
| `WASM-FMT-005`  | low      | Unusual module format         | `format.kind != "core"` or parse errors present                       |

---

## 11. JS interface signal reference

The `detections.js_interface.signals` list may contain any combination of these tokens:

| Signal token                    | What it means                                                                                                                |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `js_namespace_import`           | At least one import from module `js` — the generic JS host namespace.                                                        |
| `wasm_builtin_namespace_import` | At least one import from a `wasm:*` namespace — normative JS API builtins (WebAssembly JS Interface §6).                     |
| `wbindgen_pattern`              | At least one import from `wbg` or an export/import name matching `__wbindgen_*` or `__wbg_*`. Indicates Rust + wasm-bindgen. |
| `emscripten_pattern`            | Import or export names matching Emscripten ABI (`emscripten_*`, `invoke_*`, `dynCall_*`).                                    |
| `env_js_pattern`                | Imports from `env` with JS-adjacent names — common in older Emscripten modules.                                              |
| `glue_export_pattern`           | Exports with well-known JS glue names (`__wbindgen_start`, `__wasm_call_ctors`).                                             |

**Confidence mapping:**

| Confidence | Conditions                                                               |
| ---------- | ------------------------------------------------------------------------ |
| `high`     | `js_namespace_import` or `wasm_builtin_namespace_import` present.        |
| `medium`   | Only heuristic patterns like `wbindgen_pattern` or `emscripten_pattern`. |
| `low`      | Only export-name patterns detected, no import signals.                   |
| `none`     | No JS interface signals found at all.                                    |

---

## 12. Worked examples

### Example A — minimal arithmetic module

**File:** `tests/fixtures/simple_add.wasm`

**What to expect:** A module that exports a single `add` function and has no imports. Purely self-contained.

```bash
wasm-tools tests/fixtures/simple_add.wasm --json | jq '{
  imports: .imports,
  exports: .exports,
  risk:    .analysis.summary,
  caps:    .analysis.capabilities,
  js:      .analysis.detections.js_interface.detected
}'
```

**Result:**

```json
{
  "imports": [],
  "exports": [{ "index": 0, "name": "add", "kind": "func", "ref_index": 0 }],
  "risk": { "risk_score": 0, "risk_tier": "none", "finding_count": 0 },
  "caps": [],
  "js": false
}
```

**Interpretation:** No imports → no attack surface toward the host. The only thing the host can do is call `add`. Risk score 0, tier `none`. This is the lowest-risk module shape possible.

---

### Example B — wasm-bindgen JS interface module

**File:** `tests/fixtures/js_interface.wasm`

**What to expect:** A Rust module compiled with wasm-bindgen, using both a direct `js` namespace import and `wasm:js-string` builtins.

```bash
wasm-tools tests/fixtures/js_interface.wasm --json | jq '{
  imports:    .imports,
  exports:    .exports,
  risk:       .analysis.summary,
  js_signals: .analysis.detections.js_interface.signals,
  builtins:   .analysis.detections.js_interface.builtin_sets,
  caps:       .analysis.capabilities
}'
```

**Result:**

```json
{
  "imports": [
    { "index": 0, "module": "js", "name": "console_log", "kind": "func" },
    { "index": 1, "module": "wbg", "name": "__wbindgen_throw", "kind": "func" },
    { "index": 2, "module": "wasm:js-string", "name": "length", "kind": "func" }
  ],
  "exports": [
    { "index": 0, "name": "run", "kind": "func" },
    { "index": 1, "name": "__wbindgen_start", "kind": "func" }
  ],
  "risk": { "risk_score": 8, "risk_tier": "low", "finding_count": 0 },
  "js_signals": [
    "js_namespace_import",
    "wasm_builtin_namespace_import",
    "wbindgen_pattern"
  ],
  "builtins": ["js-string"],
  "caps": ["host.logging", "js.host"]
}
```

**Interpretation:**

1. **Imports analysis:**
   - `js/console_log` — this module can write to the browser console. Not dangerous but confirms browser environment.
   - `wbg/__wbindgen_throw` — wasm-bindgen ABI: throws a JavaScript exception from Rust panic machinery.
   - `wasm:js-string/length` — uses the normative `js-string` builtin (WebAssembly JS Interface §6.1.10) to get the length of a JS string without copying it into wasm memory. Efficient and well-specified.

2. **Exports analysis:**
   - `run` — the public function the application calls.
   - `__wbindgen_start` — will run automatically on module instantiation. In wasm-bindgen this usually does global initialization.

3. **Risk:** Score 8, tier `low`. The module interacts with the JS host but does not have filesystem, network, or process control. This is a normal browser-facing WebAssembly module.

---

## 13. Glossary

| Term                | Meaning                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------- |
| **embedder**        | The environment that runs a WebAssembly module — a browser, Node.js, Wasmtime, etc.         |
| **host function**   | A function provided by the embedder and imported by the module.                             |
| **linear memory**   | The module's flat byte array address space. Isolated from the host's memory by default.     |
| **LEB128**          | Little Endian Base 128 — the variable-length integer encoding used throughout `.wasm`.      |
| **WASI**            | WebAssembly System Interface — a standardised set of host imports for CLI/server use.       |
| **wasm-bindgen**    | A Rust tool that generates JS/WASM glue code for Rust → browser compilation.                |
| **Emscripten**      | A compiler toolchain that compiles C/C++ to WebAssembly with a POSIX-compatible runtime.    |
| **component model** | A newer WebAssembly standard for composable modules with richer interface types.            |
| **section**         | A named, length-prefixed chunk inside a `.wasm` file.                                       |
| **import section**  | Declares all external dependencies the module needs the host to supply.                     |
| **export section**  | Declares what the module makes available to the host.                                       |
| **custom section**  | An extension section with an arbitrary name — used for debug info, metadata, etc.           |
| **indirect call**   | A `call_indirect` instruction — like a function pointer; the target is resolved at runtime. |
| **type index**      | An index into the `types` array, referencing a function signature.                          |
| **function index**  | A global index across both imported and locally-defined functions. Imports come first.      |
| **start function**  | A function (if declared) called automatically when the module is instantiated.              |
| `externref`         | A WebAssembly value type that holds an opaque reference to a host object (e.g. JS value).   |
| `funcref`           | A WebAssembly value type that holds a reference to a function.                              |
