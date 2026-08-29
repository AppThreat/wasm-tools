# Lesson 2: Reading the JSON report end to end

The JSON report is the tool's real interface. Text modes are for humans; the report is what scripts, SIEMs, and pipelines consume, and learning to walk it with `jq` pays off in every later lesson. This lesson reads one report top to bottom against a fixture with enough structure to be interesting.

## The sample

`tests/fixtures/call_graph.wasm` has an import, an indirect call, an element segment, an export, and dead code, which exercises most of the report:

```bash
wasm-tools tests/fixtures/call_graph.wasm --json-out /tmp/cg.json
jq 'keys' /tmp/cg.json
```

```json
[
  "analysis",
  "call_graph",
  "data_segments",
  "elements",
  "errors",
  "exports",
  "file",
  "function_count",
  "functions",
  "globals",
  "imports",
  "is_component",
  "memories",
  "module_version",
  "sections",
  "start_function",
  "strings",
  "strings_truncated",
  "tables",
  "tags",
  "toolchain",
  "types"
]
```

The report has four zones: decode facts (sections, types, functions), interface facts (imports, exports), derived blocks (strings, call_graph, toolchain), and the analysis layer. `errors` sits above all of it as a validity gate.

## Always check errors first

```bash
jq '.errors' /tmp/cg.json
```

```json
[]
```

Empty means the decode completed without incidents. A non-empty list means the file is malformed and every other field is best-effort. To see the failure mode for yourself:

```bash
head -c 40 tests/fixtures/call_graph.wasm > /tmp/trunc.json.wasm
wasm-tools /tmp/trunc.json.wasm --json | jq '.errors, .analysis.detections.format'
```

```json
[
  "Section length extends beyond file boundary"
]
{
  "kind": "invalid-core",
  "confidence": "medium",
  "signals": ["parse_errors"],
  "module_version": 1
}
```

The tool did not throw; it reported, classified, and kept going. That is the error model from the [architecture page](ARCHITECTURE.md) showing up in your pipeline.

## Sections and types

```bash
jq '.sections[] | [.id, .name, .size, .offset]' /tmp/cg.json
```

```json
[
  [1, "Type", 13, 10],
  [2, "Import", 11, 25],
  [3, "Function", 4, 38],
  [4, "Table", 4, 44],
  [7, "Export", 7, 50],
  [9, "Element", 7, 59],
  [10, "Code", 29, 68]
]
```

`offset` values are file positions, useful for hexdump navigation. `size` anomalies are triage signals: a Code section dwarfing everything else suggests generated code, a large Data section suggests embedded resources.

Types are the ABI vocabulary:

```bash
jq '.types' /tmp/cg.json
```

```json
[
  { "index": 0, "params": ["i32"], "results": ["i32"] },
  { "index": 1, "params": ["i32"], "results": [] },
  { "index": 2, "params": [], "results": [] }
]
```

Every function and function import will reference one of these by index.

## Imports and exports: the contact surface

```bash
jq '.imports, .exports' /tmp/cg.json
```

```json
[
  [
    {
      "index": 0,
      "module": "env",
      "name": "log",
      "kind": "func",
      "type_index": 1
    }
  ],
  [{ "index": 0, "name": "run", "kind": "func", "ref_index": 2 }]
]
```

Two facts in two lines. The module asks the host for one function, `env.log`, and offers one function, `run`, which is function index 2 in the global space. Why 2 and not 0? Index spaces put imports first: the import occupies index 0, the two local functions occupy 1 and 2. `ref_index: 2` tells you `run` is the second local function. This convention holds across functions, globals, tables, memories, and tags, in text output and JSON alike.

## Functions and instructions

```bash
jq '.functions[] | {index, name, signature_index, offset, body_size, instruction_count}' /tmp/cg.json
```

```json
[
  {
    "index": 1,
    "name": "",
    "signature_index": 0,
    "offset": 68,
    "body_size": 4,
    "instruction_count": 2
  },
  {
    "index": 2,
    "name": "",
    "signature_index": 2,
    "offset": 73,
    "body_size": 14,
    "instruction_count": 7
  },
  {
    "index": 3,
    "name": "",
    "signature_index": 2,
    "offset": 88,
    "body_size": 7,
    "instruction_count": 3
  }
]
```

All three names are empty: `functions[].name` comes from the `name` custom section, which this fixture lacks. Yet `run` is not lost; the call graph labels nodes from export names too, which is why `--calls run` resolves in [lesson 6](LESSON6.md). Signature indices differ per function, so look each one up rather than assuming.

Instructions are a flat list per function with file offsets and immediates in parse order:

```bash
jq '.functions[] | select(.index == 2) | .instructions[]' /tmp/cg.json
```

```json
[
  { "offset": 76, "opcode": "i32.const", "immediates": [7] },
  { "offset": 78, "opcode": "call", "immediates": [0] },
  { "offset": 80, "opcode": "i32.const", "immediates": [1] },
  { "offset": 82, "opcode": "i32.const", "immediates": [0] },
  { "offset": 84, "opcode": "call_indirect", "immediates": [0, 0] },
  { "offset": 87, "opcode": "drop", "immediates": [] },
  { "offset": 88, "opcode": "end", "immediates": [] }
]
```

`call_indirect` immediates are `[type_index, table_index]`, so this one expects signature type 0 and dispatches through table 0. The actual target is whatever the table holds at the runtime index, which is exactly why the call graph labels that edge an approximation.

## Derived blocks

The strings, call graph, and toolchain blocks are computed after decoding:

```bash
jq '{strings: (.strings | length), strings_truncated, call_graph: (.call_graph | keys), toolchain}' /tmp/cg.json
```

```json
{
  "strings": 0,
  "strings_truncated": false,
  "call_graph": [
    "edge_count",
    "edges",
    "import_xrefs",
    "node_count",
    "nodes",
    "reachability"
  ],
  "toolchain": {
    "languages": [],
    "processed_by": [],
    "sdks": [],
    "target_features": []
  }
}
```

Empty toolchain on this fixture means the producers custom section is absent. On real binaries that block tells you the compiler and language at a glance, and its absence after you expected it is itself an observation. [Lesson 6](LESSON6.md) dissects the call graph, and [lesson 5](LESSON5.md) fills the strings block with secrets.

## Analysis last

```bash
jq '.analysis | {summary, capabilities, detections: (.detections | keys), profiles, finding_ids: [.findings[].id]}' /tmp/cg.json
```

The analysis layer is a view over everything above. When it and the raw decode disagree, trust the raw decode: the analysis is heuristic by design. The rules it applied are documented with their thresholds in [findings and signals](FINDINGS.md), and the [analyst guide](ANALYST_GUIDE.md) turns them into decisions.

## A reusable extraction skeleton

The queries above compose into a one-shot triage summary you can drop into scripts:

```bash
jq '{
  file, errors, kind: .analysis.detections.format.kind,
  risk: .analysis.summary,
  imports: [.imports[] | {(.module + "." + .name): .kind}],
  exports: [.exports[].name],
  caps: .analysis.capabilities,
  findings: [.analysis.findings[].id]
}' /tmp/cg.json
```

Keep the skeleton in your toolkit; every later lesson's verdict step is a variation of it.
