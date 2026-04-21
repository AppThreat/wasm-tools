# SKILL.md

## Purpose

This guide helps AI coding agents decide when to use the `wasm-tools` CLI, which mode to choose, and how to interpret output in a security analysis workflow.

## When to use CLI vs library API

Use the CLI when:

- a human needs fast terminal output for triage,
- you need section layout visibility (`--headers`) or readable disassembly (`-d`),
- you are comparing behavior with `wasm-objdump`.

Use the Python API (`wasm_tools.api`) when:

- output will be consumed by another program,
- you need structured records for pipelines,
- you are integrating with scanners or batch tooling.

## CLI modes and decision rules

### `--headers`

Use for a quick module map:

- section ids, names, sizes, and offsets,
- no instruction-level detail,
- best first command for unknown large binaries.

### `-x` / `--details`

Use for semantic section content:

- type signatures,
- imports/exports,
- globals, tables, memories,
- element/data/tag sections,
- code body size summaries.

This is the default mode when no mode flag is provided.

### `-d` / `--disassemble`

Use for instruction-level inspection:

- function body opcode streams,
- immediates shown in parse order,
- useful for control-flow and behavior review.

### `--json`

Use for machine-readable output to stdout:

- minified JSON payload,
- suitable for shell pipelines and redirection.

Tiny verified example from `tests/fixtures/simple_add.wasm`:

```bash
wasm-tools tests/fixtures/simple_add.wasm --json
```

```json
{
  "module_version": 1,
  "function_count": 1,
  "first_export": "add",
  "errors": []
}
```

### `--json-out PATH`

Use to persist machine-readable output:

- writes minified JSON to file,
- non-zero exit on write failure with stderr message.

When both `--json` and `--json-out PATH` are provided, the CLI prints JSON to stdout and writes the same payload to file.

### `--analysis-only`

Use with `--json` and/or `--json-out` when you want only the high-level triage layer:

- emits the `analysis` object instead of the full decode report,
- best for policy engines, SOC triage, and compact evidence capture,
- invalid on its own and must be paired with `--json` or `--json-out`.

When triaging host/runtime assumptions, inspect:

- `analysis.detections.wasi` to confirm whether imports indicate WASI (`preview1`, `preview2-like`, or `legacy`),
- `analysis.detections.js_interface` to identify JavaScript embedder-facing imports/exports and `wasm:*` builtin namespace usage,
- `analysis.detections.format` to quickly identify non-core or parse-incompatible binaries.

## Security-focused usage patterns

1. Start with `--headers` to understand attack surface quickly.
2. Use `-x` to inspect imports/exports and memory/table capabilities.
3. Use `-d` for suspicious functions or proposal-heavy modules.
4. Use `--json` or `--json-out` for reproducible evidence capture.
5. Use `--analysis-only` when the full decode is too verbose for the immediate review task.
6. For runtime compatibility checks, verify `analysis.detections.wasi`, `analysis.detections.js_interface`, and `analysis.detections.format` before deeper policy decisions.

## Output semantics that matter

- Function/global/table/memory/tag indices are module-global.
- Imported entities shift indices for locally-defined entries.
- Errors from malformed binaries are reported in structured error fields rather than raising by default in library flows.
- WASI detection is import-based; this tool parses WASI modules but does not execute WASI syscalls.

## Practical command set

```bash
wasm-tools sample.wasm --headers
wasm-tools sample.wasm -x
wasm-tools sample.wasm -d
wasm-tools sample.wasm --json
wasm-tools sample.wasm --json --analysis-only
wasm-tools sample.wasm --json-out sample.json
wasm-tools sample.wasm --json-out analysis.json --analysis-only
wasm-tools sample.wasm --json --json-out sample.json
```

## Agent guardrails

- Do not assume output text matches `wasm-objdump` formatting exactly.
- Validate correctness using section offsets, counts, and decoded operands.
- Prefer fixtures under `tests/fixtures/` for reproducible checks.
- Run relevant tests after CLI changes before claiming behavior.
