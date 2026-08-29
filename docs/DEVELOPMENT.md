# Development guide

This page covers the working setup, the test layout, and the recipes for the four most common extensions: opcodes, section decoders, visitors, and analysis rules. The architecture behind these recipes is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Setup and workflow

The project uses Poetry and requires Python 3.10 or newer:

```bash
poetry install
poetry run pytest -q
```

Fixtures are compiled from `.wat` sources in `tests/fixtures/` with WABT's `wat2wasm`:

```bash
poetry run python tests/fixtures/build.py
```

`wat2wasm` must be on `PATH`. The compiled `.wasm` files are committed, so tests run without WABT; you only need it when adding or editing a fixture.

## Where things live

The codebase is small by design. `parser.py` decodes and dispatches, `opcodes.py` is the opcode-to-immediate table, `visitor.py` renders output, `models.py` holds shared state, and `api.py` contains the JSON collector plus all analysis post-processing. When you add behavior, the placement rule is: decoding belongs in the parser, interpretation belongs in post-processing modules (`strings.py`, `graph.py`, or analysis helpers in `api.py`). Security detections never go into parser decode branches.

## Adding an opcode

1. Add the `(prefix, opcode)` key and `(mnemonic, ImmType)` value to `OPCODES` in `wasm_tools/opcodes.py`. Sub-opcodes for prefixed families are LEB128 values, keyed as integers.
2. If the immediate shape is new, add an `ImmType` constant and a dispatch branch in `BinaryReader.read_instructions()` in `parser.py` that reads the immediates and calls the corresponding delegate callbacks.
3. Render the new immediates in `BinaryReaderObjdumpDisassemble` and `_BinaryReaderJsonCollector` (and `BinaryReaderObjdumpDetails` if relevant).
4. Test two things in `tests/test_extended_ops.py`: the table entry exists, and the dispatch path produces correct output from a synthetic byte sequence.

## Adding a section decoder

Add a `_decode_<name>(self, end_offset)` method to `BinaryReader`, wire it into `_decode_section()`, and define a state container in `models.py`. Guard every delegate call with `hasattr` so existing delegates keep working. Follow the existing pattern of constraining reads to the section end offset and repositioning the cursor on failure.

## Writing a custom visitor

Subclass `BinaryReaderNop` from `wasm_tools/visitor.py` and implement only the callbacks you need. Run the prepass first if you need names or types during your pass, sharing one `ObjdumpState`:

```python
from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
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

The `current_opcode` pattern comes from the base visitor: `on_opcode` fires before the immediate callbacks, so immediate handlers can look up which instruction they belong to. [Lesson 9](LESSON9.md) builds on this pattern.

## Adding analysis rules or detections

Detections live in `wasm_tools/api.py` (and `strings.py` or `graph.py` for their domains). Keep the schema backward compatible within the major version: `summary`, `detections`, `capabilities`, `profiles`, `findings` are stable keys. New detection keys are additive and need tests. New finding ids must have a stable id, severity, confidence, evidence, and remediation, and must be documented in [FINDINGS.md](FINDINGS.md) with their exact trigger conditions. Breaking schema changes require a major version bump and a [MIGRATION.md](MIGRATION.md) entry.

## Conventions worth preserving

These invariants are load-bearing and easy to break by accident:

- `read_module()` catches `WasmParseError` and reports via `on_error`. It does not re-raise. Batch pipelines depend on this.
- New parser events must be `hasattr`-guarded. The delegate contract is optional by design.
- Output wording is asserted by tests: phrases like `Code Disassembly:` and `func[0]:` are load-bearing substrings in `tests/test_e2e.py`.
- Offsets printed in disassembly depend on `get_print_offset()` and `section_offsets`; do not change offset semantics without updating tests.
- Entity callbacks use module-global index spaces. `read_limits()` returns a 5-tuple; `read_init_expr()` returns `(text, value)`; `on_data` receives `offset_value`; `on_table`/`on_memory` accept `shared` and `page_size_log2`.
- The library has zero runtime dependencies. Keep it that way; post-processing heuristics should need nothing but the standard library.

## Documentation

User-facing documentation lives in `docs/` and is published to GitHub Pages with docsify (no build step). Pages serves the `main` branch with Jekyll disabled via the root `.nojekyll`; the root `index.html` redirects into `docs/`, where the docsify shell loads the markdown as-is. If you add a page, register it in `docs/_sidebar.md`. Lessons follow the naming convention `LESSON<N>.md`, use repo fixtures so every command is reproducible, and avoid em-dashes and emoji by project convention. The in-repo map in `AGENTS.md` mirrors this structure; update it when pages move.

The examples are guarded against drift: `tests/test_docs.py` extracts every fenced bash block in `docs/` that references `tests/fixtures/` and runs it from the repository root. If a code change breaks a documented command, that test fails with the page and block number. Blocks needing tools the environment lacks (`wat2wasm`, `jq`, `xxd`, `poetry`) or scripts the page tells the reader to write are skipped with the reason recorded, so keep runnable examples pointed at committed fixtures.
