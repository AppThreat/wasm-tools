# Custom section catalog

The parser fully decodes the `name`, `producers`, and `target_features`
custom sections plus DWARF debug sections, and now the rest of the
tool-conventions catalog. Every decoder degrades gracefully: a malformed
payload becomes an in-band error string and the rest of the module keeps
walking, because a broken custom section must not cost the report.

## Decoded sections

### `dylink.0` and legacy `dylink` (Emscripten)

Report key `dylink`, decoded per DynamicLinking.md. Subsections:
`mem_info` (memory and table sizes and alignments), `needed` (the literal
needed-library list, which feeds dependency hints at high confidence),
`export_info`, `import_info`, `runtime_path`, and `target_arch`. The legacy
flat `dylink` (pre-`.0`) layout records the four memory/table values with
`legacy: true` and reads the needed vector best-effort.

### `linking` (LLVM/lld object files)

Report key `linking`, decoded per Linking.md: version, the symbol table
(kinds func/data/global/section/tag/table with flag decoding: binding,
hidden, undefined, exported, explicit-name, no-strip, TLS, absolute),
segment names, init funcs, comdat groups, and target arch. Symbol names
fill the gaps for object-file wasm built without a name section, with the
name section keeping precedence everywhere (report, call graph). The symbol
list is capped at 500 entries with `symbols_truncated`, matching the
strings and call graph caps. Segment names named `__em_js` count as
`linking.em_js_segments`: modern Emscripten ships EM_JS metadata as a data
segment of that name.

### `metadata.code.branch_hint` (branch hinting proposal)

Report key `branch_hints`, decoded per CodeMetadata.md: `vec(function)`
where each function is a funcidx plus a vector of `(offset, size=1, hint)`
entries with `likely`/`unlikely` values. Presence also raises the
`branch_hints_present` format signal and the `isa.branch-hints` capability.

### `component-type` and `core`

`component_type` records the section's version and payload size; the
embedded binary WIT type grammar is out of scope. The coredump convention
section (`core`) records `coredump: true`.

## Name precedence

Function and global names resolve in this order: the `name` custom section,
then linking symbol names, then export names. The precedence applies to
report entries, call graph nodes, and the analysis layer alike.

## What is deliberately not decoded

Relocation subsections and comdat groups record counts only; the embedded `component-type` WIT binary is summarized, not
decoded. Payloads the report retains (DWARF sections) are capped: the
retention budget is 8 MB per module, and retention past the cap stops with
a note rather than ballooning the process.
