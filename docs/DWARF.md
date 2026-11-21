# DWARF source mapping

Unstripped wasm builds embed DWARF as custom sections named like the ELF
sections (`.debug_info`, `.debug_line`, `.debug_str`, and friends), with one
format deviation that matters here: code addresses are offsets into the
code section (tool-conventions Dwarf.md), so mapping a function to source is
a lookup of the function's code-relative address in the line program rows.

## What is implemented (phase 1)

- The `.debug_line` line-program state machine for DWARF versions 2 through
  5: initial lengths including 64-bit DWARF, version-specific headers,
  include directories and file tables (inline strings and the v5
  `line_strp`/`strp`/udata forms), special opcodes, the standard opcodes,
  and the extended opcodes (`end_sequence`, `set_address`, `define_file`).
- Function-level source mapping: functions gain `source` =
  `{"file": "...", "line": N}` when the line table covers their
  code-relative address. Rows are grouped per `end_sequence`-delimited
  sequence and a function maps to the last row at or before its address
  within a sequence, never across a sequence boundary.
- A compilation-units summary (`toolchain.compilation_units`): unit offsets
  and versions from `.debug_info` headers, without DIE decoding.
- The `.debug_str` payload was already extracted for string provenance;
  `.debug_line`, `.debug_line_str`, and `.debug_info` are now retained for
  mapping, up to an 8 MB per-module budget.

Anything the parser cannot decode yields no mapping rather than a wrong
one. A mapping that cannot be proven is worse than none.

## What is deliberately out of scope

Instruction-level mapping, inlined-call reconstruction, split-DWARF sidecar
files (`-gseparate-dwarf`), and `sourceMappingURL` scanning are follow-up
work. The corpus fixture `bz2.wasm` ships full DWARF sections but its
`.debug_line` carries headers and file tables with no line programs (the
fixture was post-processed), so the state machine is validated against a
hand-built DWARF 4 table with rows derived by hand from the spec grammar
(`tests/test_dwarf.py`), plus an end-to-end module whose function maps to
the expected file and line.

## Triage recipe

On an unstripped module, `functions[].source` turns a name-less function
list into source-correlated listings. Pair it with `provenance` (the DWARF
producer string often names the exact compiler) and the call graph to walk
from an export to the source file and line where the behavior of interest
lives.
