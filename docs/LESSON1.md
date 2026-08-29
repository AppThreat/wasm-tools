# Lesson 1: First contact with an unknown module

You have a `.wasm` file from a browser extension, an Electron app, or a suspicious upload, and you know nothing about it. This lesson walks the first fifteen minutes of analysis using repo fixtures as the unknown file. Everything here runs from a checkout of this repository.

```bash
git clone https://github.com/appthreat/wasm-tools
cd wasm-tools
pip install .
```

We will play that `tests/fixtures/control_flow.wasm` is the unknown file.

## Step 1: Confirm what it is

Before any tooling, look at the first bytes:

```bash
xxd tests/fixtures/control_flow.wasm | head -1
```

```text
00000000: 0061 736d 0100 0000 0106 0160 017f 017f  .asm.......`....
```

The magic `00 61 73 6D` is ASCII `\0asm` and the version bytes `01 00 00 00` mark a core module. If the fourth byte were `0D` or higher with `01` in the third position, you would be looking at a [component](COMPONENT_MODEL.md) instead. The [format primer](FORMAT_PRIMER.md) explains the rest of the header.

## Step 2: Map the sections

```bash
wasm-tools tests/fixtures/control_flow.wasm --headers
```

```text
tests/fixtures/control_flow.wasm:	file format wasm 0x1

Sections:

   id name               size  offset
  --- ---------------- ------  --------
    1 Type                  6  0000000a
    3 Function              2  00000012
   10 Code                 26  00000016
```

Read this as a table of contents. One type, one function, one code body, nothing else. Three absences are the first security facts: no `Import` section means the module asks its host for nothing, no `Export` section means the host cannot call into it by name, and no `Custom` section means no debug names and no toolchain metadata.

## Step 3: Read the surface

```bash
wasm-tools tests/fixtures/control_flow.wasm -x
```

```text
Section Details:


Type[1]:
 - type[0]: (i32) -> (i32)

Function[1]:
 - func[0]: sig=0

Code[1]:
 - func[0]: size=24 sig=0
```

The surface is minimal: a single function taking an `i32` and returning one, with no imports, no exports, no memory, and no start function. As shipped, this module computes nothing for anybody; something would have to instantiate it and reach the function through the host API directly. Files like this in the wild are usually libraries waiting for glue, or fragments of a bigger module.

## Step 4: Score it

```bash
wasm-tools tests/fixtures/control_flow.wasm --json --analysis-only | jq '{summary, capabilities, findings: [.findings[].id]}'
```

```json
{
  "summary": { "risk_score": 0, "risk_tier": "none", "finding_count": 0 },
  "capabilities": [],
  "findings": []
}
```

Score 0, no findings, and here the reading is honest: with no imports and no reachability, there is no behavior the host can trigger. But do not let a zero teach you the wrong lesson. The score measures host-facing surface, not what the code does. If this same countdown loop sat inside a module that exported it and grew memory per iteration, the score would still be modest while the behavior got interesting. The one number you should not skip: reachability.

## Step 5: Read the code

One function means one disassembly read:

```bash
wasm-tools tests/fixtures/control_flow.wasm -d
```

```text
Code Disassembly:

000016 func[0]:
 000019: | block sig=-64
 00001b: | loop sig=-64
 00001d: | local.get 0
 00001f: | i32.eqz
 000020: | br_if 1
 000022: | local.get 0
 000024: | i32.const 1
 000026: | i32.sub
 000027: | local.set 0
 000029: | br 0
 00002b: | end
 00002c: | end
 00002d: | local.get 0
 00002f: | end
```

You do not need fluency to follow this. `local.get 0` pushes parameter 0, `i32.eqz` tests it for zero, and `br_if 1` branches out of the `block` (depth 1 counts outward: the `loop` is 0, the `block` is 1) when the counter hits zero. Otherwise the counter decrements and `br 0` jumps back to the loop head. It is a countdown loop that returns zero.

Two details worth internalizing:

- `sig=-64` is the raw decoded block signature; `-64` (`0x40` as signed LEB) means "void". The tool prints decoded integers, not interpretations.
- Offsets in the left column are file positions. `000019` is where the `block` opcode sits in the file, which is what you paste into a hexdump when something looks wrong.

Now close the loop with reachability:

```bash
wasm-tools tests/fixtures/control_flow.wasm --json | jq '.call_graph.reachability'
```

```json
{
  "roots": [],
  "reachable_functions": [],
  "reachable_count": 0,
  "unreachable_functions": [0],
  "unreachable_count": 1
}
```

The only function in the module is unreachable: no exports, no start function, so no root exists. Reachability is computed from exports and the start function; a module whose entire code section is unreachable is either dead weight, a library awaiting glue, or a payload waiting for a custom host entry. That distinction is a judgment call, and now you have the fact that drives it.

## Step 6: Check the data

The headers showed no `Data` section (id 11), so there is nothing to extract, but build the habit now:

```bash
wasm-tools tests/fixtures/control_flow.wasm --strings
```

```text

0 strings shown
```

On a module with data segments this prints every string with its segment, linear-memory address, and encoding. [Lesson 5](LESSON5.md) shows it on a file that has secrets to find.

## The general pattern

You just executed the standard first-contact loop:

```mermaid
flowchart LR
    A["header"] --> B["--headers: map"]
    B --> C["-x: surface"]
    C --> D["--json: score + findings"]
    D --> E["-d: flagged code"]
    E --> F["--strings: data"]
    F --> G["verdict or escalate"]
```

The next lessons deepen each step: the JSON report ([lesson 2](LESSON2.md)), host capability triage ([lesson 3](LESSON3.md)), JS-facing modules ([lesson 4](LESSON4.md)), and call graphs ([lesson 6](LESSON6.md)).
