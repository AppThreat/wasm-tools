# AGENTS.md

## Purpose and scope

- This repo is a small WebAssembly objdump-style parser/disassembler in pure Python.
- Core package: `wasm_tools/`; behavior is mostly in parser + visitor callbacks, not in large class hierarchies.
- CLI entrypoint is the script name `wasm-tools` from `pyproject.toml` (`wasm_tools.cli:main`).

## Documentation map

- `README.md` — quick-start and CLI reference.
- `ARCHITECTURE.md` — binary format, parser internals, and design decisions. Read this before touching `parser.py` or `visitor.py`.
- `ANALYST_GUIDE.md` — practical field guide for security analysts: JSON field reference, triage recipes, worked examples. **Start here if you are triaging an unknown `.wasm` file.**
- `AGENTS.md` — this file. Conventions for automated agents and contributors.
- `SKILL.md` — high-level capability description.

## Architecture (read these first)

- `wasm_tools/parser.py` (`BinaryReader`) owns binary decoding and section/instruction traversal.
- `wasm_tools/visitor.py` provides delegate implementations; parser calls delegate hooks with `hasattr(...)` checks.
- `wasm_tools/models.py` contains shared enums/state (`ObjdumpMode`, `ObjdumpOptions`, `ObjdumpState`).
- `wasm_tools/opcodes.py` maps `(prefix, opcode)` to `(mnemonic, immediate type)`; parser dispatch depends on this table.

## Data flow and why it is structured this way

- The tool runs in **two passes** (`wasm_tools/cli.py`):
  1. PREPASS visitor gathers names/types into `ObjdumpState`.
  2. Mode-specific visitor (currently disassembly) prints output using prepass state.
- Name custom section handling happens in parser (`section_id == CUSTOM`, `name == "name"`) and feeds `on_function_name`.
- Disassembly formatting is centralized in `BinaryReaderObjdumpDisassemble._log_opcode`; tests assert exact substrings from stdout.
- High-level security detections (for example WASI, JavaScript interface, and format signals) belong in `wasm_tools/api.py` analysis helpers, not in parser decode branches.

## Critical workflows

- Run tests (verified in this repo):
  ```bash
  cd /Users/prabhu/work/AppThreat/wasm-tools
  poetry install
  poetry run pytest -q
  ```
- Rebuild fixture `.wasm` files from `.wat` (requires WABT `wat2wasm`):
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
- Keep `analysis` schema backward compatible (`summary`, `detections`, `capabilities`, `profiles`, `findings`) and add new detection keys with tests. Current detection keys include `wasi`, `js_interface`, and `format`.

## Integration points and dependencies

- No runtime third-party Python deps are required for the library itself (`dependencies = []` in `pyproject.toml`).
- Dev/test deps are `pytest` + `pytest-cov`; pytest options are configured in `pyproject.toml`.
- External binary dependency only for fixture generation: WABT `wat2wasm` (`tests/fixtures/build.py`).
