# WAT text emission

`--print-wat` renders a decoded report as faithful flat WAT text: one
instruction per line, explicit `block`/`end` structure, numeric indices.
This is not decompilation (wabt removed wasm-decompile in 1.0.42, and
C-like output stays with the Ghidra and Binary Ninja plugins and the
research decompilers); the uses are diffing two versions of a module,
writing text-level rules, and the round-trip conformance harness.

```bash
wasm-tools module.wasm --print-wat
wasm-tools module.wasm --wat-out module.wat
```

## Scope and honesty

Every instruction is rendered from its immediate type in the opcode table,
so it either appears with all of its immediates or not at all. An
instruction the emitter cannot render (an unknown opcode, a record with
missing or malformed immediates, a heap type the parser could not name)
becomes a `;; unrenderable instruction ...` comment line. Anything that
cannot be reproduced faithfully marks the emission incomplete, and the last
line of the output then reads `;; emission incomplete: <reasons>`. The
emitter never invents syntax it cannot verify and never drops an immediate
silently.

Global initializers, element segments and data segments are decoded from
the source bytes when the caller supplies them (`source=` in the library;
the CLI always passes the file). That decode handles extended constant
expressions, expression-based element segments, multi-byte memory indices
and exact float bit patterns, which the report's summary text does not
carry. Without the source bytes, data segments emit size comments, float
initializers are rounded, and the emission is marked incomplete.

Floats render as exact hex floats, and NaNs keep their sign and payload
(`f32.const nan:0x200000`, `f64.const -nan:0x8000000000000`). Constants in
instructions are read back from the source bytes when available, because
the parser widens floats to Python doubles and that conversion quiets
signalling NaNs.

Import, export and function names are escaped per the WAT string grammar:
printable ASCII stays as is, `"` and `\` are escaped, tab, newline and
carriage return use their short escapes, and every other byte (including
each byte of a non-ASCII UTF-8 sequence) becomes a `\hh` escape. A hostile
name therefore cannot close the string and inject text. Function names
become `$name` ids when they consist only of WAT id characters and quoted
`$"..."` ids otherwise; a repeated name is emitted once, on its first
function.

Component binaries emit their nested core modules under per-module comment
headers; component-level WIT text is out of scope.

## Bounded output

The output stays linear in the size of the binary, which matters because
the input is untrusted. The one construct that is not linear by nature is
a local declaration: the binary stores a count and a type, so six bytes can
declare 2^32 - 1 locals, and the text format has no repeat count. The
emitter expands local groups only while two limits hold. A function may
expand at most 50,000 locals, the limit V8 and the wasm-tools validator
enforce, so a larger group cannot belong to a module any engine loads. The
whole module may expand at most 50,000 locals plus 64 per byte of function
bodies. The first group that would cross either limit, and every later
group of that function, is replaced by a comment giving the count (later
groups cannot be emitted on their own without shifting local indices), and
the emission is marked incomplete.

## Round-trip conformance

The harness in `tests/test_wat_roundtrip.py` emits WAT for every core
fixture and every vendored corpus binary under `tests/fixtures/corpus/`,
reassembles it with WABT's wat2wasm and with the Rust `wasm-tools parse`
(each skipped when absent), and compares the decoded modules: instruction
streams with immediates and try_table catch clauses, types, imports with
limits and mutability, globals with their exact initializers, tables,
memories, exports, element segments with their items, data segments with
their payload bytes, tags, the start function and function names. Floats
compare by bit pattern, so NaN payloads count. Encoding choices the two
assemblers make differently are normalised before comparing: adjacent
local groups of the same type, an explicit `(table 0)` on element
segments, and block types written as a type index that the inline form can
express.

The skips are listed in the test with their reasons. `gc_ops.wasm` and
`gc_rec_group.wasm` are emitted with placeholder struct types and marked
incomplete, because the report carries no struct or array field types.
`f16x8_binary.wasm` emits complete text, but neither wat2wasm 1.0.42 nor
wasm-tools 1.263 has the f16x8 instruction keywords, so neither can
reassemble it. Component fixtures are skipped because component WAT is out
of scope. Golden files under `tests/fixtures/golden/` pin three fixtures so
wording changes become reviewable diffs.

## Known limitations

- The emitter is a renderer, not a validator: it does not reject invalid
  modules and relies on the assemblers for checking.
- GC struct and array types render as `(struct)` placeholders that keep
  later type indices in place, and the emission is marked incomplete.
- Custom sections other than function names (producers, DWARF, target
  features) are not emitted.
- wat2wasm 1.0.42 drops a `try_table` block type written as a type use
  (`try_table (type N)`) and encodes an empty block type instead, so for
  modules with such blocks only the wasm-tools round trip is exact. None of
  the fixtures contain one; modules generated with `wasm-tools smith` do.
