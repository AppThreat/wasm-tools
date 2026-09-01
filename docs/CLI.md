# CLI reference

The installed console script is `wasm-tools`, defined in `pyproject.toml` as `wasm_tools.cli:main`. You can also run it from a checkout with `python -m wasm_tools.cli`.

```
wasm-tools FILE [FLAGS]
```

`FILE` is the only positional argument. With no flags the tool prints section details, which is the same as passing `-x`.

## Flags

| Flag                  | Effect                                                                                                                                        |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `--headers`           | Print the section header table with ids, names, sizes, and offsets.                                                                           |
| `-x`, `--details`     | Print section contents: type signatures, imports, exports, globals, tables, memories, data segments, elements, tags, and code body summaries. |
| `-d`, `--disassemble` | Decode and print function body instructions with offsets.                                                                                     |
| `--strings`           | Extract printable strings from data segments with linear-memory provenance.                                                                   |
| `--strings-min-len N` | Minimum string length applied at extraction time (default 5). Affects `--strings` and `--json`.                                               |
| `--calls FUNC`        | Print the outgoing call tree for a function selected by name or index.                                                                        |
| `--no-strings`        | Skip string extraction in `--json` reports.                                                                                                   |
| `--no-call-graph`     | Skip call graph construction in `--json` reports. Incompatible with `--calls`.                                                                |
| `--json`              | Print a minified JSON report to stdout.                                                                                                       |
| `--json-out PATH`     | Write the same minified JSON report to `PATH`.                                                                                                |
| `--analysis-only`     | With `--json` and/or `--json-out`, emit only the `analysis` object.                                                                           |

Two combinations are rejected by the argument parser: `--analysis-only` without at least one of `--json` or `--json-out`, and `--calls` together with `--no-call-graph`.

When `--json` and `--json-out` are combined, the payload is printed to stdout and written to the file, so one parse serves both uses. Exit code is 1 with a stderr message if the file cannot be read or the output file cannot be written.

## Output modes in detail

### `--headers`

The fastest way to understand what a file contains. Each row shows the section id, its symbolic name, the payload size in bytes, and the offset of the section payload in the file. Custom sections append their quoted name after the offset, which makes DWARF (`.debug_info`, `.debug_str`) and toolchain (`producers`, `target_features`) sections identifiable at a glance. Section ids are listed in the [format primer](FORMAT_PRIMER.md).

### `-x`, `--details`

This mode prints the semantic content of every non-code section plus a one-line summary per function body. It is the default mode. Imports and exports are printed in module-global index space, so imported functions occupy the lowest indices and locally defined bodies start at `func[imported_count]`:

```text
Import[2]:
 - func[0] sig=0 <"env"."log">
 - global[0] f64 const <"env"."PI">

Function[1]:
 - func[1]: sig=1
```

Custom toolchain sections print their contents in this mode: `producers` rows as ` - <field>: "<name>" "<version>"`, `target_features` rows as ` - +feature` or ` - -feature`. Type rows print ` - type[N]: (params) -> (results)` for function signatures and ` - type[N]: struct` or `array` for GC composite types.

A missing import section means the module has no external dependencies. A missing export section means the host cannot call into it by name.

### `-d`, `--disassemble`

Function bodies printed instruction by instruction, one line per instruction:

```text
000020 func[0]:
 000023: | local.get 0
 000025: | local.get 1
 000027: | i32.add
 000028: | end
```

The left column is the byte offset of the opcode within the file. Immediates follow the mnemonic in parse order, so `call_indirect 0 0` means type index 0, table index 0. Instructions the decoder does not know print as `unknown_<prefix>_<opcode>` and continue decoding; treat them as a signal that the binary uses newer opcodes than the table.

### `--strings`

Prints one line per extracted string with its provenance:

```text
 segment[0] mem[0x00000000] +0x0 len=32 utf-8 "https://evil.example.com/payload"
```

Read the fields as follows: `segment[N]` is the data segment index, `mem[0x...]` is the absolute linear-memory offset the segment initializes (a dash for passive segments), `+0x...` is the offset within the segment, `len` is the decoded byte length, and the encoding is `utf-8` or `utf-16le`. Both encodings are extracted, so obfuscated UTF-16 strings in data segments still surface. Unstripped binaries also contribute `.debug_str` content, printed as ` custom:.debug_str +0x... len=N utf-8 "..."` with section-relative offsets. Extraction happens before output filtering, which is why `--strings-min-len 3` can surface short strings that the default threshold of 5 hides. The list is capped at 1000 entries in JSON output with a `strings_truncated` flag.

### `--calls FUNC`

Prints an outgoing call tree rooted at the function you name. `FUNC` may be a function name (from the `name` custom section) or a module-global index:

```text
Call tree for func[2] <run> [export]:

  -> func[0] <env.log> [import] (direct @0x4e)
  -> func[1] (indirect-approx @0x54)
```

Markers are deterministic: `(recursion)` marks a node on the current path, `(seen)` marks a node already expanded elsewhere, and `...` marks a subtree cut off at the depth cap of 4. Edge labels carry the call kind and the byte offset of the call instruction. `indirect-approx` edges come from element segments and are over-approximations: the table entry could be changed at runtime. See [lesson 6](LESSON6.md).

### `--json` and `--json-out`

Both produce the identical minified payload. The full schema is in the [JSON report reference](JSON_REFERENCE.md). Quick field pulls:

```bash
wasm-tools module.wasm --json | jq '.analysis.summary'
wasm-tools module.wasm --json | jq '.imports[] | select(.module | startswith("wasi"))'
wasm-tools module.wasm --json-out report.json
```

`--analysis-only` shrinks the payload to the triage layer, which is convenient for policy engines and log capture:

```bash
wasm-tools module.wasm --json --analysis-only | jq '.summary, [.findings[].id]'
```

## Index semantics

All entity indices printed by the CLI (and used in JSON output) are module-global index spaces. Concretely: if a module imports two functions, the first locally defined body is `func[2]`, and `func[0]` and `func[1]` refer to imports. The same rule applies to globals, tables, memories, and tags. Section detail headers use entry counts (`Function[3]` means three entries in the function section), and `DataCount` prints the decoded count value.

This matches how `wasm-objdump` presents indices, but the text layout is not byte-identical to WABT output. Validate against offsets and counts, not formatting.

## Component Model binaries

Files with a component preamble (version `0x0d` or later with layer 1) are detected automatically. `-x` and `--headers` print a component summary with interfaces, imports, exports, canonical options, and per-core-module counts. `-d` disassembles each nested core module in turn, and `--json` includes the aggregated `component` block plus per-entry `core_module` indices on shared lists. Details are in the [Component Model page](COMPONENT_MODEL.md).

## Suggested command sequence for triage

```bash
wasm-tools sample.wasm --headers                 # map
wasm-tools sample.wasm -x                        # surface: imports, exports, memory
wasm-tools sample.wasm --json --analysis-only    # risk tier, capabilities, findings
wasm-tools sample.wasm -d                        # instructions for flagged functions
wasm-tools sample.wasm --strings                 # embedded data
wasm-tools sample.wasm --calls run               # behavior from the entry point
```

The same sequence with commentary is [lesson 1](LESSON1.md).
