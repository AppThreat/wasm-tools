# Lesson 8: Component Model binaries

Core modules are self-contained programs. Components are packages: typed interfaces, canonical glue, and one or more embedded core modules. This lesson builds a small component from scratch, runs the tool over it, and reads the report's component block. No special flags are needed anywhere; detection is automatic.

## Building a test component

There is no component fixture in the repository, so we synthesize one: a component that imports the `wasi:cli/run@0.2.0` interface, embeds `tests/fixtures/simple_add.wasm` as its core module, canonically lifts the core `add` function, and exports it as `run`. Save this as `/tmp/make_component.py`:

```python
from wasm_tools.api import parse_wasm_bytes

def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def name(s):
    raw = s.encode()
    return leb(len(raw)) + raw

def section(sid, payload):
    return bytes([sid]) + leb(len(payload)) + payload

core = open("tests/fixtures/simple_add.wasm", "rb").read()
imports = section(10, leb(1) + b"\x00" + name("wasi:cli/run@0.2.0") + b"\x01" + leb(0))
core_module = section(1, core)
canon = section(8, leb(1) + b"\x00\x00" + leb(0) + leb(1) + b"\x06" + leb(0))
exports = section(11, leb(1) + b"\x00" + name("run") + b"\x01" + leb(0) + b"\x00")
component = b"\x00asm\x0d\x00\x01\x00" + imports + core_module + canon + exports

report = parse_wasm_bytes(component, filename="sample.component.wasm")
print(report["component"]["interfaces"])
print(report["analysis"]["detections"]["wasi"]["variants"])
```

```bash
python3 /tmp/make_component.py
```

```text
['wasi:cli/run@0.2.0']
['preview2']
```

The byte layout you just built, section by section:

```text
offset  bytes                              meaning
------  ---------------------------------  --------------------------------
0x00    00 61 73 6D 0D 00 01 00            magic + component v13, layer 1
0x08    0A <len> ...                       import section: wasi:cli/run@0.2.0
--      01 <len> 00 61 73 6D ...           core module section: simple_add
--      08 <len> ...                       canon section: 1 lift
--      0B <len> ...                       export section: "run"
```

The magic bytes tell the two worlds apart at a glance: a core module's fourth byte is `01`, a component's is `0D` or later with layer `01`. The [format primer](FORMAT_PRIMER.md) shows the core header; this is its sibling.

## Run the standard commands

Add one line to the script so the bytes land on disk, then rerun it:

```python
open("/tmp/sample.component.wasm", "wb").write(component)
```

```bash
python3 /tmp/make_component.py
wasm-tools /tmp/sample.component.wasm -x
```

```text

Component Details:

 component version: 13 layer: 1
 core modules: 1
 interfaces:
  - wasi:cli/run@0.2.0
 imports:
  - func type=0 <"wasi:cli/run@0.2.0">
 exports:
  - func[0] -> "run"
 canon: lift=1 lower=0 options: async

 core module[0]: version=1 functions=1 imports=0 exports=1
```

`-d` disassembles the embedded core module under a `Code Disassembly (core module[0])` heading, exactly as [lesson 1](LESSON1.md) taught, and `--headers` lists component sections.

## Reading the component block

The JSON report carries a `component` object alongside the usual fields:

```bash
wasm-tools /tmp/sample.component.wasm --json | jq '.component | {component_version, layer_version, interfaces, imports, exports, canonical_options, core_module_count}'
```

```json
{
  "component_version": 13,
  "layer_version": 1,
  "interfaces": ["wasi:cli/run@0.2.0"],
  "imports": [
    { "kind": "func", "type_index": 0, "name": "wasi:cli/run@0.2.0" }
  ],
  "exports": [{ "kind": "func", "index": 0, "name": "run" }],
  "canonical_options": {
    "lift_count": 1,
    "lower_count": 0,
    "options": ["async"]
  },
  "core_module_count": 1
}
```

Each embedded core module gets a full report of its own under `core_modules`, with the standard shape from [lesson 2](LESSON2.md) plus a `core_module_index` tag:

```bash
wasm-tools /tmp/sample.component.wasm --json | jq '.component.core_modules[0] | {core_module_index, function_count, exports, reachability: .call_graph.reachability}'
```

The shared top-level lists (`imports`, `functions`, `strings`) are aggregations across the nested modules; every aggregated entry carries a `core_module` field so indices that repeat between modules stay unambiguous.

## Triage differences

WASI detection reads interface names, so `wasi:cli/run@0.2.0` produces the `preview2` variant, as the script printed. Capability inference applies the same name mapping to interfaces: a `wasi:filesystem/preopens@0.2.0` import would add `fs.path`. The call graph is computed per core module and does not cross canon boundaries, so treat each module's graph as an island.

The triage order that works:

```text
1. interfaces + canonical_options   the component's offer to the host
2. per core module imports          each module's individual asks
3. aggregated strings               the data that rides along
4. per core module findings         the standard recipes, per island
```

Components can also nest components, and composition is the point of the model: a component can grant a nested module fewer capabilities than it itself receives. Compare the asks layer by layer when the composition matters; the per-module reports make that comparison mechanical.

## Known limits

Component parsing covers the interface surface: preamble, import, export, canon, instance, and type sections, plus full decode of every nested core module. It does not reconstruct cross-module call edges and does not decode every exotic type grammar. The [Component Model page](COMPONENT_MODEL.md) holds the full field reference, and the [coverage matrix](COVERAGE.md) states the boundaries.
