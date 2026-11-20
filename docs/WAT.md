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

- Data and element payloads come from the source bytes when the caller
  supplies them (`source=` in the library, and the CLI always passes the
  file). Without them, segments emit size comments and the emission is
  marked incomplete.
- Unknown opcodes render as `;; unknown opcode ...` comment lines and mark
  the emission incomplete. The emitter never invents syntax it cannot
  verify.
- Component binaries emit their nested core modules under per-module
  comment headers; component-level WIT text is out of scope.

## Round-trip conformance

The harness in `tests/test_wat_roundtrip.py` recompiles every fixture's
emitted WAT with wat2wasm (per-fixture feature flags mirroring
`tests/fixtures/build.py`, probed for support) and asserts the recompiled
instruction streams match the originals opcode and immediate for opcode and
immediate. This is the strongest parser regression net in the repo: any
decoder or emitter drift that changes program meaning shows up there.
Golden files under `tests/fixtures/golden/` pin three fixtures so wording
changes become reviewable diffs.

## Known limitations

- The emitter is a renderer, not a validator: it does not reject invalid
  modules and relies on wat2wasm for checking.
- GC composite types render minimally (`(sub (struct))` shapes and
  `(ref N)` references); deep rec-group structure is flattened.
- wat2wasm quirks the harness works around: lane-access memargs want
  `offset=` before `align=`, and `try_table` catch clauses are
  parenthesized.
