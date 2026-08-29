# WebAssembly format primer

This page explains what the bytes in a `.wasm` file mean. It is written for security engineers who want to read hexdumps with understanding, and it is the background for everything the tool reports. The authoritative source is the WebAssembly specification; this primer covers the parts the decoder implements and the parts that matter for triage.

## A module is a sandboxed bytecode program

A `.wasm` file is a compiled binary program designed to run inside a WebAssembly runtime, the way a `.class` file runs inside a JVM. Three properties define the security model:

- The module cannot touch memory outside its own linear memory.
- The module cannot make system calls. Every interaction with the world (filesystem, network, DOM, clock) goes through imported functions the host provides.
- The module cannot execute native instructions. The runtime validates and compiles it first.

The consequence for analysis: the import and export sections are the module's complete contact surface with the outside world. That is why every triage flow in these docs starts there.

## The eight-byte header

Every core module starts with the same eight bytes:

```text
0x00: 00 61 73 6D    magic, ASCII "\0asm"
0x04: 01 00 00 00    version, little-endian u32; 1 for core modules
```

If the file does not start with `00 61 73 6D` it is not WebAssembly. If the version bytes are `0D 00 01 00` or later with a nonzero third byte, the file is a [Component Model binary](COMPONENT_MODEL.md), not a core module. Verify the header by hand with `xxd file.wasm | head -1`.

## Sections

After the header the file is a sequence of sections. Each section is a one-byte id, a LEB128-encoded payload length, and the payload:

```text
+--------+---------------+----------------------+
| id: u8 | size: leb128u | payload (size bytes) |
+--------+---------------+----------------------+
```

The size field is the security workhorse of the format: a reader can skip any section it does not understand, and a decoder can confine every section parse to its declared bounds. wasm-tools uses exactly that property to survive corrupted files: a section that fails to decode internally is abandoned at its end offset and later sections still parse.

| ID  | Name      | What it holds                                              | Triage relevance                                                                                                              |
| --- | --------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 0   | Custom    | Named arbitrary payloads                                   | `name` carries debug symbols; `producers` and `target_features` carry toolchain fingerprints; unknown names may hide anything |
| 1   | Type      | Function signatures                                        | Shows the ABI shapes compiled in                                                                                              |
| 2   | Import    | Externally provided funcs, tables, memories, globals, tags | The module's requests toward its host                                                                                         |
| 3   | Function  | Type index for each locally defined function               | Count of defined functions                                                                                                    |
| 4   | Table     | Reference-typed tables                                     | Indirect call dispatch surface                                                                                                |
| 5   | Memory    | Linear memory limits                                       | Sandbox size and growth policy                                                                                                |
| 6   | Global    | Module-level scalars with constant initializers            | Mutable exported globals are shared state                                                                                     |
| 7   | Export    | Names the host can call or read                            | The module's offering to the outside                                                                                          |
| 8   | Start     | One function run at instantiation                          | Code that runs without being called                                                                                           |
| 9   | Element   | Table initialization with function references              | Feeds indirect calls                                                                                                          |
| 10  | Code      | Function bodies                                            | The actual instructions                                                                                                       |
| 11  | Data      | Bytes written into linear memory at startup                | Strings, keys, embedded blobs                                                                                                 |
| 12  | DataCount | Number of data segments                                    | Required when bulk memory ops are used                                                                                        |
| 13  | Tag       | Exception tags                                             | Exception-handling proposal                                                                                                   |

Non-custom sections must appear in id order and at most once. Custom sections can appear anywhere, which is why the `name` section usually trails the code section and why a single-pass disassembler would print unnamed functions (this is the reason for the [two-pass design](ARCHITECTURE.md)).

## LEB128: the integer encoding

Almost every integer in the format is LEB128 (Little Endian Base 128). Each byte carries seven value bits; the high bit says whether another byte follows:

```text
value 624485 encoded as e5 8e 26:

  byte 0: 1 1100101   ^ continuation bit set, low 7 bits = 1100101
  byte 1: 1 0001110   ^ continuation bit set, low 7 bits = 0001110
  byte 2: 0 0100110   continuation clear, low 7 bits = 0100110

  value = 1100101 | 0001110<<7 | 0100110<<14
```

Signed variants interpret the final chunk as two's complement. Signed LEB is used where negative values are meaningful, most visibly in block signatures: a `block` immediate of `-64` (`0x40` as s7) means "void", while non-negative values reference type indices. This is why the disassembly prints `block sig=-64` rather than `block void`; the tool shows the decoded integer and leaves the interpretation to you.

The decoder enforces a maximum bit width per LEB read, so a crafted run of continuation bytes cannot overflow or consume unbounded input. That is one of the parser's [hardening decisions](ARCHITECTURE.md).

## Types, limits, and index spaces

Value types are single bytes: `0x7F` i32, `0x7E` i64, `0x7D` f32, `0x7C` f64, `0x7B` v128, `0x70` funcref, `0x6F` externref, plus GC reference forms (`0x63`/`0x64` prefixes followed by a heaptype byte). When you see `externref` in a signature you are looking at a boundary that exchanges opaque host values, which is a [JS-facing signal](ANALYST_GUIDE.md).

Memory and table sizes use a limits structure:

```text
[flags: u8] [min: leb] [max: leb, if flag bit 0] [page_size_log2: leb, if flag bit 3]
```

Flag bit 1 marks shared memory (threads), bit 2 marks a 64-bit address space (Memory64). Memory sizes are in 64 KiB pages: `min=16` means 1 MiB. A missing maximum means the memory can grow to the runtime limit, 4 GiB for 32-bit modules and beyond for Memory64.

Functions, globals, tables, memories, and tags each live in an index space where imported entities come first. This is the rule that trips up newcomers: in a module with two imported functions, the first locally defined body is `func[2]`. All tool output uses these global indices consistently.

## The instruction encoding

Instructions are one opcode byte plus zero or more immediates. Opcodes `0x00` through `0xBF` dispatch directly. Four prefix bytes open extension spaces where the real opcode follows as a LEB128 u32:

```text
common instruction:      [ opcode: u8 ] [ immediates... ]
prefixed instruction:    [ prefix: u8  ] [ sub-opcode: leb128u ] [ immediates... ]

0xFC  numeric extensions: saturating truncation, bulk memory, table ops, wide arithmetic
0xFD  SIMD/vector:        v128 loads and arithmetic, lane ops, relaxed SIMD
0xFB  GC:                 struct.new, array.get, ref.test, br_on_cast
0xFE  threads/atomics:    atomic loads and stores, atomic.fence
```

Immediate shapes vary by instruction: a single LEB index for `call`, a block signature for `block`, an alignment and offset pair (memarg) for loads and stores, sixteen raw bytes for `v128.const`, a target vector for `br_table`, and so on. The full mapping from opcode to immediate shape lives in one table, `OPCODES` in `wasm_tools/opcodes.py`, and the decoder switches on it. The [architecture page](ARCHITECTURE.md) shows how to extend it.

Function bodies are not length-prefixed at the instruction level. The code section entry declares a body size, and inside that the decoder tracks structural depth: `block`, `loop`, `if`, and `try_table` increment it, `end` decrements it, and depth zero means the body is complete. This design has an analysis consequence: a decoder that mis-tracks immediates after an unknown opcode can lose sync with the instruction stream. wasm-tools keeps going by design and reports `decode_incomplete` when a body ends mid-instruction; treat unknown opcodes as a review signal rather than a failure.

## Where each part lands in a file

A typical small module looks like this in byte order:

```text
offset  content
------  ------------------------------------------------------
0x00    magic + version
0x08    Type section        signatures
0x0F    Function section    type indices for local functions
0x14    Memory section      limits
0x18    Export section      names to call from the host
0x1E    Code section        bodies: locals + instructions
0x2A    Data section        bytes written into linear memory
0x31    Custom "name"       debug names for functions and locals
```

Section order is fixed except for custom sections, so a hexdump maps cleanly to this picture. The `--headers` command prints exactly this table for any file you point it at.

## Reading on

The [JSON report reference](JSON_REFERENCE.md) maps each of these structures to its report field, and the [analyst guide](ANALYST_GUIDE.md) turns them into triage decisions. For the formal grammar, the repository bundles the SpecTec snapshot under `specification/wasm-latest/`, with `5.3-binary.instructions.spectec` and `5.4-binary.modules.spectec` being the two files that matter for decoding.
