# Architecture and specification notes

This document describes the WebAssembly binary format, how the specification defines it, and how this library decodes it. It is written for readers with a security background who want to understand parsing decisions, trust boundaries, and what the library does and does not guarantee.

---

## The WebAssembly binary format in brief

A `.wasm` file is a compact binary encoding of a module. It is not an executable in the traditional sense. A WebAssembly runtime reads the module, validates it against a type system, and then compiles or interprets it. This library sits before that validation step: it reads the raw bytes, identifies structure, and reports what it finds without making judgments about correctness.

### Module layout

Every well-formed WebAssembly file starts with an eight-byte header:

```
00 61 73 6D  01 00 00 00
 \_ magic _/  \_ version (1) _/
```

After the header, the file is a sequence of sections. Each section starts with a one-byte section id and a LEB128-encoded byte count. The byte count lets a reader skip a section it does not understand. Section ids 0 through 13 are currently assigned; higher values are unrecognised and skipped.

```
[section_id: u8] [byte_count: leb128u32] [payload: byte_count bytes]
```

The section id values and their roles:

| ID  | Name      | Role in a module                                                         |
| --- | --------- | ------------------------------------------------------------------------ |
| 0   | Custom    | Arbitrary named data; the `name` subsection carries debug symbol names   |
| 1   | Type      | Function type signatures: param and result value type vectors            |
| 2   | Import    | Externally-provided funcs, tables, memories, globals, and exception tags |
| 3   | Function  | Maps each locally-defined function to a type section index               |
| 4   | Table     | Reference-typed tables used for indirect calls and element segments      |
| 5   | Memory    | Linear memory limits; most modules declare exactly one                   |
| 6   | Global    | Module-level mutable or immutable values with a constant initialiser     |
| 7   | Export    | Names and references that a host environment can call or read            |
| 8   | Start     | Optional single function called on module instantiation                  |
| 9   | Element   | Segments that initialise table entries with function references          |
| 10  | Code      | Function bodies: local declarations followed by instruction sequences    |
| 11  | Data      | Segments that initialise regions of linear memory                        |
| 12  | DataCount | Declares the number of data segments; required when bulk memory is used  |
| 13  | Tag       | Exception tag declarations for the exception-handling proposal           |

Sections must appear in this order (with Custom sections allowed anywhere) and each non-Custom section may appear at most once.

### Value types

The binary encoding uses compact one-byte tags for the common numeric and reference types:

| Byte | Type      | Notes                                               |
| ---- | --------- | --------------------------------------------------- |
| 0x7F | i32       | 32-bit integer                                      |
| 0x7E | i64       | 64-bit integer                                      |
| 0x7D | f32       | 32-bit IEEE 754 float                               |
| 0x7C | f64       | 64-bit IEEE 754 float                               |
| 0x7B | v128      | 128-bit SIMD vector                                 |
| 0x70 | funcref   | Reference to any function                           |
| 0x6F | externref | Reference to a host-provided object                 |
| 0x6E | anyref    | Top of the GC reference type hierarchy              |
| 0x63 | ref null  | Nullable reference, followed by a heaptype byte     |
| 0x64 | ref       | Non-nullable reference, followed by a heaptype byte |

The GC proposal adds heap type bytes (`0x69`-`0x74`) that can follow a `0x63` or `0x64` prefix, or stand alone as shorthand nullable references.

### Limits

Memory and table sizes are described by a limits structure:

```
[flags: u8] [minimum: leb128u32] [maximum: leb128u32 if flag bit 0 is set]
```

The flags byte encodes whether a maximum is present (bit 0) and whether the address space is 64-bit (bit 2, Memory64 proposal). The parser normalises this into `(minimum, maximum_or_None, is_64)`.

### LEB128 encoding

Almost all integers in the WebAssembly binary format use Little Endian Base 128 encoding. Each byte contributes seven bits of value; the high bit signals whether more bytes follow. The parser reads both unsigned (`u32`, `u64`) and signed (`s32`, `s33`, `s64`) variants. Signed variants matter for block type immediates and heap type indices, where negative values encode built-in types.

---

## The instruction encoding

### Core encoding

Instructions are encoded as a single opcode byte optionally followed by immediates. The mapping from opcode byte to instruction and immediate shape is defined in `wasm_tools/opcodes.py`.

For opcodes `0x00` through `0xBF` there is a direct one-byte dispatch. For the extensions, four prefix bytes signal that the actual opcode follows as a LEB128-encoded sub-opcode:

| Prefix | Family             | Examples                                      |
| ------ | ------------------ | --------------------------------------------- |
| 0xFC   | Numeric extensions | sat-trunc conversions, bulk memory, table ops |
| 0xFD   | SIMD/vector        | v128 loads, arithmetic, lane operations       |
| 0xFB   | GC                 | struct.new, array.get, ref.test, br_on_cast   |
| 0xFE   | Threads/atomics    | i32.atomic.load, memory.atomic.notify         |

Sub-opcodes for `0xFD` reach into the hundreds (relaxed SIMD goes up to 275), so LEB128 is used rather than a fixed byte.

### Immediate types

After the opcode, the parser reads zero or more immediate operands. The shape depends on the instruction:

| `ImmType`         | What the parser reads                                                     |
| ----------------- | ------------------------------------------------------------------------- |
| `NONE`            | Nothing; instruction is self-contained                                    |
| `INDEX`           | One u32 LEB (function index, label, table index, etc.)                    |
| `BLOCK_SIG`       | One s32 LEB; negative values are value types, non-negative are type refs  |
| `MEMARG`          | Two u32 LEBs: alignment hint and byte offset                              |
| `I32` / `I64`     | One signed LEB of the matching width                                      |
| `F32` / `F64`     | Four or eight raw bytes in IEEE 754 little-endian order                   |
| `BR_TABLE`        | Count u32, then that many u32 labels, then one default u32                |
| `CALL_INDIRECT`   | Two u32s: type index then table index                                     |
| `MEMORY_INIT`     | Two u32s: data segment index then memory index (binary order)             |
| `MEMORY_COPY`     | Two u32s: destination and source memory indices                           |
| `SELECT_T`        | u32 count then that many value type bytes                                 |
| `HEAP_TYPE`       | One heaptype: either a known one-byte shorthand or a signed LEB s33 index |
| `TABLE_INIT`      | Two u32s: element segment index then table index                          |
| `TABLE_COPY`      | Two u32s: destination table index then source table index                 |
| `V128_CONST`      | Sixteen raw bytes (little-endian vector value)                            |
| `V128_SHUFFLE`    | Sixteen raw bytes (one lane index per output lane)                        |
| `LANE_IDX`        | One raw byte (lane index)                                                 |
| `MEMARG_LANE`     | Two u32 LEBs (align, offset) then one byte (lane index)                   |
| `BR_ON_CAST`      | One flags byte, one u32 label, two heaptypes                              |
| `TRY_TABLE_BLOCK` | s32 block sig, u32 count, then count catch clauses                        |
| `ATOMIC_FENCE`    | One reserved byte (always 0x00)                                           |

The `ImmType` table and the `OPCODES` dict are the single place where this mapping lives. The parser `BinaryReader.read_instructions()` switches on `ImmType` to decide how many bytes to consume. When the library is extended with new opcodes, only these two places need to change.

### Block depth tracking

The instruction decoder tracks nested structure depth. `block`, `loop`, `if`, and `try_table` increment a depth counter. `end` decrements it. When depth reaches zero the function body is complete and the loop exits. This is needed because function bodies are not length-prefixed at the expression level; only the outer code section entry gives the total body size as a safety bound.

---

## Parser architecture

### BinaryReader

`BinaryReader` in `wasm_tools/parser.py` is the only stateful component that touches raw bytes. It owns a position cursor (`self.offset`) and advances it as it reads. When a structural error is detected (truncated file, bad magic, LEB128 overflow, section overrun) it raises `WasmParseError`. The public entry point `read_module()` catches that exception and forwards the message to `delegate.on_error()`, preventing it from propagating to the caller.

Each section has a dedicated decode method (`_decode_type`, `_decode_import`, etc.). When a section finishes, the cursor is set to the recorded end offset. This means a partially decoded section does not corrupt the parse of later sections; the bytes are simply abandoned.

Helper methods `read_heaptype()`, `read_reftype()`, `read_valtype()`, `read_limits()`, `read_globaltype()`, and `read_init_expr()` encapsulate the recursive type reading that appears in multiple section contexts.

### Delegate callbacks

The parser does not decide what to do with decoded data. It calls methods on a delegate object. Before each call it checks whether the method exists:

```python
if hasattr(self.delegate, "on_function"):
    self.delegate.on_function(i, sig_idx)
```

This means a minimal delegate implementing only `begin_module`, `begin_section`, and `begin_custom_section` is sufficient to drive a full parse. A visitor that cares about instructions only needs to implement `begin_function_body`, `on_opcode`, and the immediate callbacks it uses. Nothing breaks if a callback is absent.

Index semantics are important for consumers that compare against `wasm-objdump`.

- `begin_section(index, code, size)` uses `index` as the encounter order in the binary stream.
- Entity callbacks (`on_function`, `on_global`, `on_table`, `on_memory`, `on_tag`, and `begin_function_body`) use module-global index spaces. Locally-defined entries are offset by imported entries of the same kind.

The available callbacks are:

```
begin_module(version)
begin_section(index, code, size)
begin_custom_section(index, size, name)
on_type(index, params, results)
on_import(index, module, name, kind, **kwargs)
on_function(index, sig_index)
on_table(index, ref_type, min, max, is_64)
on_memory(index, min, max, is_64)
on_global(index, valtype, mutable, init_expr)
on_export(index, name, kind, ref_index)
on_start(func_index)
on_element(index, mode, ref_type, table_idx, offset_expr, count, func_indices)
on_data(index, mode, mem_idx, offset_expr, size, data_bytes)
on_data_count(count)
on_tag(index, type_index)
begin_function_body(index, size)
on_local_decl(func_index, decl_index, count, valtype)
end_function_body(index)
on_opcode(opcode)          -- called before the immediate callbacks below
on_opcode_bare()
on_end_expr()
on_opcode_index(idx)
on_opcode_block_sig(sig)
on_opcode_uint32(val)
on_opcode_uint64(val)
on_opcode_f32(val)
on_opcode_f64(val)
on_opcode_uint32_uint32(v1, v2)
on_call_indirect_expr(sig, table)
on_opcode_heap_type(ht)
on_opcode_lane_idx(lane)
on_opcode_memarg_lane(align, offset, lane)
on_opcode_v128(raw_bytes)
on_opcode_v128_shuffle(lanes)
on_opcode_br_table(targets, default)
on_opcode_br_on_cast(flags, label, ht1, ht2)
on_opcode_try_table(sig, catches)
on_opcode_select_t(types)
on_error(message)
```

### Two-pass execution

Parsing happens in two sequential passes over the same byte buffer. Both passes use independent `BinaryReader` instances sharing a single `ObjdumpState` object.

```
               raw bytes
                  |
          --------+--------
          |               |
    Pass 1 (prepass)   Pass 2 (mode-specific)
    BinaryReaderObjdumpPrepass    BinaryReaderObjdump[Disassemble|Details|...]
          |               |
          +---> ObjdumpState <---+
               function_names
               function_types
               local_names
               types[]
               imports[]
               exports[]
               globals[]
               tables[]
               memories[]
               data_segments[]
               elements[]
               tags[]
               start_function
```

The prepass needs to run first because the `name` custom section appears after the code section in binary order. A single-pass disassembler would produce function bodies without names; the two-pass design ensures names are available before any output is generated.

### Visitors provided

`wasm_tools/visitor.py` contains four concrete visitors built on top of `BinaryReaderObjdumpBase`:

**`BinaryReaderObjdumpPrepass`** is used in pass one only. It collects everything into `ObjdumpState` and emits no output.

**`BinaryReaderObjdumpDisassemble`** prints function bodies instruction by instruction, with byte offsets. This is the `-d` CLI mode and the most useful path for manual analysis of unknown binaries.

**`BinaryReaderObjdumpDetails`** prints section-by-section content in a structured text format: type signatures, import/export tables, global initialisers, memory and table limits, data segment metadata, element segments, and code body summaries. This is the `-x` CLI mode.

**`BinaryReaderObjdumpHeaders`** prints a compact section header table with ids, names, sizes, and byte offsets. This is the `--headers` CLI mode and the fastest path to understanding what is in a file.

### JSON collector

`wasm_tools/api.py` provides `_BinaryReaderJsonCollector`, a non-printing visitor that accumulates decoded data into Python dictionaries. At the end of the second pass, `build_report()` assembles a single dict from the in-progress function table and the fully-populated `ObjdumpState`. The result is directly serialisable with `json.dumps`.

The collector also computes an `analysis` block for security triage. This layer is heuristic and does not change parsing behavior.

- **Capability inference** maps imports into higher-level host capabilities such as filesystem, network, process termination, random, and JS host interaction.
- **Detection rules** add explicit `analysis.detections` signals for WASI usage, JavaScript interface usage (`js`/`wbg`/`wasm:*` import surfaces and glue patterns), and coarse module format classification (`core`, `possible-component`, `invalid-core`).
- **Behavior profiles** summarize memory, control-flow, and compute complexity signals from decoded opcode streams.
- **Findings** are stable-id rule checks (`WASM-CAP-001`, `WASM-CFG-002`, `WASM-DOS-003`, `WASM-LOOP-004`, `WASM-FMT-005`) with severity, confidence, evidence, and remediation text.
- **Risk scoring** combines capability and finding weights into a bounded 0-100 score and a tier (`none`, `low`, `medium`, `high`).

The public API functions (`parse_wasm_bytes`, `parse_wasm_file`, `parse_wasm_bytes_json`, `parse_wasm_file_json`) wrap the two-pass pipeline and handle OS errors at the file read level.

---

## Data flow diagram

The following shows how a call to `parse_wasm_file("module.wasm")` flows through the system:

```
parse_wasm_file("module.wasm")
  |
  +-- open and read bytes
  |
  +-- BinaryReader(data, BinaryReaderObjdumpPrepass)
  |     .read_module()
  |       _do_read_module()
  |         read_u32()  -- magic
  |         read_u32()  -- version --> begin_module(version)
  |         loop over sections:
  |           read_u8()          -- section id
  |           read_leb128()      -- section size
  |           _decode_section()
  |             _decode_type()   --> on_type(i, params, results)
  |             _decode_import() --> on_import(i, mod, name, kind, ...)
  |             _decode_function()--> on_function(i, sig_idx)
  |             ...
  |             _decode_custom() --> on_function_name(idx, name)
  |                                  on_local_name(fidx, lidx, name)
  |
  |       [ObjdumpState is now fully populated]
  |
  +-- BinaryReader(data, _BinaryReaderJsonCollector)
  |     .read_module()
  |       [same walk; prepass data now available for name lookups]
  |       _decode_code()
  |         begin_function_body(i, size)
  |         read_instructions(end)
  |           on_opcode(MockOpcode("i32.add"))
  |           on_opcode_bare()
  |           ...
  |         end_function_body(i)
  |
  +-- collector.build_report()
        {
          "file": "module.wasm",
          "module_version": 1,
          "types": [...],
          "imports": [...],
          "exports": [...],
          "functions": [
            {
              "index": 0,
              "name": "add",
              "instructions": [
                {"offset": 42, "opcode": "local.get", "immediates": [0]},
                {"offset": 44, "opcode": "local.get", "immediates": [1]},
                {"offset": 46, "opcode": "i32.add",   "immediates": []},
                {"offset": 47, "opcode": "end",       "immediates": []}
              ]
            }
          ],
          "errors": []
        }
```

---

## Security-relevant design decisions

### No exceptions to callers

`BinaryReader.read_module()` wraps the entire parse in a try/except for `WasmParseError`. Malformed input produces an error message in `report["errors"]`, not a Python traceback in the caller. This matters for batch analysis pipelines that process untrusted binaries from the network or from archive extraction. A single bad file does not abort the pipeline.

Sections with internal decode errors are abandoned at their end offset rather than skipped entirely. This preserves the ability to decode later sections that are well-formed even when an earlier section is corrupted.

### No code execution

The library performs no JIT compilation, no runtime evaluation, and no calls back into host code as a result of parsing. The only external effects are stdout/stderr writes from CLI visitors and whatever the caller does with the returned dictionary. This makes it safe to point at completely untrusted `.wasm` binaries.

### LEB128 overflow protection

`read_leb128()` enforces `max_bits` and raises `WasmParseError` if more bytes are consumed than a given type can hold. This prevents crafted inputs from causing integer overflow or consuming unbounded input while appearing to read a single number.

### Section bounds enforcement

After recording the section's end offset, every decode method is constrained to stay within it. If `_decode_type` reads past the section boundary, `read_u8()` or `read_leb128()` will raise `WasmParseError` (via `_ensure(n)`), which is caught and converted to an error entry. The outer loop then repositions to the recorded end offset before moving on.

### Resilient opcode dispatch

Unknown opcodes fall back to a synthetic name (`unknown_00_ab`) and `ImmType.NONE`. The instruction loop continues rather than aborting. This is the right behaviour for static analysis: an unknown instruction that has no immediates the parser knows about may consume the wrong number of bytes, but stopping the entire analysis on the first unfamiliar opcode would make the tool useless against binaries compiled from newer toolchains. Callers should treat `unknown_*` opcode names in JSON output as a signal to review the opcode table against a newer spec snapshot.

---

## Spec coverage boundaries

The local spec snapshot under `specification/wasm-latest/` is written in SpecTec notation and covers binary encoding, text format, typing rules, and execution semantics. This library implements the binary encoding chapters (`5.*`) for decoding, and partially covers the text-format instruction names (`6.3-text.instructions.spectec`) for mnemonic names.

What is deliberately not implemented:

- **Validation** (spec chapters 2.3 and 2.4): type checking of function bodies and module structure. This belongs in a runtime or a dedicated validator.
- **Execution** (spec chapter 4): reduction rules, store semantics, host function calls. Not applicable to a static decoder.
- **Text format parsing** (spec chapter 6): the library consumes binary only. `.wat` conversion is delegated to WABT.

The spec snapshot is not shipped in the PyPI package. It is only present in the repository to serve as a grounding reference during implementation.

---

## Extending the library

### Adding a new opcode

1. Add an entry to `OPCODES` in `wasm_tools/opcodes.py` with the `(prefix, byte)` key and a `(mnemonic, ImmType)` value.
2. If the immediate shape is new, add a constant to `ImmType` and a dispatch branch in `BinaryReader.read_instructions()` in `wasm_tools/parser.py`.
3. Add a callback method to the visitors in `wasm_tools/visitor.py` that need to render the new immediate (usually `BinaryReaderObjdumpDisassemble` and `_BinaryReaderJsonCollector`).
4. Write a test in `tests/test_extended_ops.py` asserting the opcode is in the table and that the dispatch path produces correct output from a synthetic byte sequence.

### Writing a custom visitor

Subclass `BinaryReaderNop` from `wasm_tools/visitor.py` and implement only the callbacks relevant to your use case. Pass an instance to `BinaryReader` as the delegate. The prepass must still run first if you need function names or type information during your visitor pass.

```python
from wasm_tools.visitor import BinaryReaderNop
from wasm_tools.parser import BinaryReader
from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.visitor import BinaryReaderObjdumpPrepass

class CallCounter(BinaryReaderNop):
    def __init__(self):
        self.offset = 0
        self.current_opcode = None
        self.call_count = 0

    def on_opcode_index(self, idx):
        if self.current_opcode and self.current_opcode.name == "call":
            self.call_count += 1

data = open("module.wasm", "rb").read()
options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
state = ObjdumpState()
BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

counter = CallCounter()
BinaryReader(data, counter).read_module()
print(counter.call_count)
```

### Adding a new section decoder

Add a method `_decode_<name>(self, end_offset: int)` to `BinaryReader` and wire it into `_decode_section()`. Guard each delegate call with `hasattr`. This ensures existing visitors that do not implement the new callback continue to work without modification.
