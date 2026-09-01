# AGENTS.md

## Purpose and scope

- This repo is a small WebAssembly objdump-style parser/disassembler in pure Python.
- Core package: `wasm_tools/`; behavior is mostly in parser + visitor callbacks, not in large class hierarchies.
- CLI entrypoint is the script name `wasm-tools` from `pyproject.toml` (`wasm_tools.cli:main`).

## Documentation map

User-facing documentation lives in `docs/` and is published to GitHub Pages with docsify. Pages serves the `main` branch with Jekyll disabled via the root `.nojekyll`; the root `index.html` redirects into `docs/`, where the docsify shell (`docs/index.html`) loads the markdown as-is (no build step). New pages must be registered in `docs/_sidebar.md`.

- `README.md`: quick start and pointer to the docs site.
- `docs/README.md`: site home page.
- `docs/GETTING_STARTED.md`: installation and first commands.
- `docs/CLI.md`: full CLI flag and output reference.
- `docs/FORMAT_PRIMER.md`: WebAssembly binary format walkthrough.
- `docs/COMPONENT_MODEL.md`: component binary support and report shape.
- `docs/JSON_REFERENCE.md`: the machine-readable report contract.
- `docs/FINDINGS.md`: analysis rules, thresholds, capability tokens, finding ids.
- `docs/ANALYST_GUIDE.md`: triage recipes for unknown `.wasm` files. **Start here if you are triaging an unknown file.**
- `docs/COVERAGE.md`: spec coverage matrix.
- `docs/LESSON1.md` ... `docs/LESSON10.md`: tutorials; every command is reproducible against `tests/fixtures/`.
- `docs/ARCHITECTURE.md`: binary format, parser internals, and design decisions. Read this before touching `parser.py` or `visitor.py`.
- `docs/DEVELOPMENT.md`: dev workflow and extension recipes.
- `docs/MIGRATION.md`: 1.x to 2.0.0 schema and callback changes, plus the 2.1.0 additive changes and the values they move.
- `docs/DEPENDENCY_RESEARCH.md`: WASM dependency detection and PURL research notes.
- `AGENTS.md`: this file. Conventions for automated agents and contributors.
- `SKILL.md`: high-level capability description for AI agents.

Docs conventions: technical and human tone, no em-dashes, no emoji, restrained bullet use, mermaid and ASCII diagrams welcome. Lesson files follow the `LESSON<N>.md` naming convention.

## Architecture (read these first)

- `wasm_tools/parser.py` (`BinaryReader`) owns binary decoding and section/instruction traversal.
- `wasm_tools/visitor.py` provides delegate implementations; parser calls delegate hooks with `hasattr(...)` checks.
- `wasm_tools/models.py` contains shared enums/state (`ObjdumpMode`, `ObjdumpOptions`, `ObjdumpState`).
- `wasm_tools/opcodes.py` maps `(prefix, opcode)` to `(mnemonic, immediate type)`; parser dispatch depends on this table.
- `wasm_tools/component.py` parses Component Model binaries (preamble detection, import/export/canon sections, nested core modules via an injected `core_parse` callable).
- `wasm_tools/strings.py` extracts printable strings from data segments and screens them for secret/IoC signals (pure post-processing).
- `wasm_tools/graph.py` builds the labeled static call graph, import xrefs, and export reachability (pure post-processing; `indirect-approx`/`typed-approx` edges are over-approximations by design).

## Data flow and why it is structured this way

- The tool runs in **two passes** (`wasm_tools/cli.py`):
  1. PREPASS visitor gathers names/types into `ObjdumpState`.
  2. Mode-specific visitor (currently disassembly) prints output using prepass state.
- `wasm_tools/api.py` `parse_wasm_bytes` auto-detects Component Model binaries (`wasm_tools/component.py` `detect_component`) and builds a component report with section data aggregated across nested core modules.
- Name custom section handling happens in parser (`section_id == CUSTOM`, `name == "name"`) and feeds `on_function_name`; `producers` and `target_features` custom sections feed `on_producers_field` / `on_target_feature`.
- Disassembly formatting is centralized in `BinaryReaderObjdumpDisassemble._log_opcode`; tests assert exact substrings from stdout.
- High-level security detections (for example WASI, JavaScript interface, strings, call graph, and format signals) belong in `wasm_tools/api.py` analysis helpers and the post-processing modules, not in parser decode branches.

## Critical workflows

- Run tests (verified in this repo):
  ```bash
  cd /Users/prabhu/work/AppThreat/wasm-tools
  poetry install
  poetry run pytest -q
  ```
- Rebuild fixture `.wasm` files from `.wat` (requires WABT `wat2wasm`; the final-spec GC fixtures additionally require the Rust `wasm-tools`, `brew install wasm-tools`):
  ```bash
  cd /Users/prabhu/work/AppThreat/wasm-tools
  poetry run python tests/fixtures/build.py
  ```
- Run CLI directly:
  ```bash
  cd /Users/prabhu/work/AppThreat/wasm-tools
  poetry run python -m wasm_tools.cli tests/fixtures/simple_add.wasm -d
  ```

## Project-specific conventions to preserve

- Error model: `BinaryReader.read_module()` catches `WasmParseError` and reports via delegate `on_error`; exceptions are not re-raised by default.
- Callback style is intentionally sparse/optional; new parser events should be guarded with `hasattr` to avoid breaking delegates.
- Maintain output wording/shape used by tests (examples in `tests/test_e2e.py`: `"Code Disassembly:"`, `"func[0]:"`, opcode text like `"call_indirect 0 0"`).
- When adding opcodes/immediates, update both `ImmType`/`OPCODES` and parser dispatch branches in `read_instructions()`.
- Offsets printed in disassembly depend on `get_print_offset()` and `section_offsets`; avoid changing default offset semantics unless tests are updated.
- Keep `analysis` schema backward compatible within a major version (`summary`, `detections`, `capabilities`, `profiles`, `findings`) and add new detection keys with tests. Current detection keys include `wasi`, `js_interface`, `strings`, and `format`. Breaking schema changes require a major version bump plus a `MIGRATION.md` entry (see 2.0.0).
- Parser delegate signatures: `on_table`/`on_memory` accept `shared` and `page_size_log2` keyword args; `on_data` accepts `offset_value`; `on_import` passes `limits_shared`/`limits_page_size_log2` for table/memory imports; `read_limits()` returns a 5-tuple; `read_init_expr()` returns `(text, value)`; `on_type_kind(index, kind)` precedes `on_type` for every type-section entry; `on_debug_section(name, payload)` receives a zero-copy `memoryview`, so delegates that retain a payload must copy it.
- Peek before consuming with `BinaryReader.peek_u8()`, never `self.data[self.offset]`: the bounds check turns truncation into `WasmParseError`, which section decoders report through `on_error`. A raw `IndexError` is swallowed by the per-section `except Exception` handler and produces a silently empty section.

## Integration points and dependencies

- No runtime third-party Python deps are required for the library itself (`dependencies = []` in `pyproject.toml`).
- Dev/test deps are `pytest` + `pytest-cov`; pytest options are configured in `pyproject.toml`.
- External binary dependencies only for fixture generation (`tests/fixtures/build.py`): WABT `wat2wasm` for most fixtures, plus the Rust `wasm-tools` for the final-spec GC fixtures (`gc_rec_group.wat`, `gc_ops.wat`); WABT's text front-end cannot parse rec groups, GC instruction keywords, or abstract heap types such as `anyref`, even with `--enable-gc`.
