# Getting started

## Installation

wasm-tools requires Python 3.10 or newer and has no runtime dependencies. Install it with pip:

```bash
pip install wasm-tools
```

This installs the library (`wasm_tools`) and the console script (`wasm-tools`). If you work on the repository itself, use Poetry:

```bash
git clone https://github.com/appthreat/wasm-tools
cd wasm-tools
poetry install
poetry run pytest -q
```

## Your first commands

The repository ships a set of small test fixtures under `tests/fixtures/`. They are real binaries compiled with WABT, and every page on this site uses them, so you can reproduce every command shown here from a checkout.

Map the sections of a module:

```bash
wasm-tools tests/fixtures/simple_add.wasm --headers
```

```text
tests/fixtures/simple_add.wasm:	file format wasm 0x1

Sections:

   id name               size  offset
  --- ---------------- ------  --------
    1 Type                  7  0000000a
    3 Function              2  00000013
    7 Export                7  00000017
   10 Code                  9  00000020
```

Disassemble the function bodies:

```bash
wasm-tools tests/fixtures/simple_add.wasm -d
```

```text
Code Disassembly:

000020 func[0]:
 000023: | local.get 0
 000025: | local.get 1
 000027: | i32.add
 000028: | end
```

Get the full JSON report, which is the same payload the library returns:

```bash
wasm-tools tests/fixtures/simple_add.wasm --json | jq
```

Every command is safe to run on untrusted files. The parser never executes the code it decodes, and malformed input turns into entries in the `errors` array instead of a crash. Try it: truncate a file and run again.

```bash
head -c 40 tests/fixtures/simple_add.wasm > /tmp/truncated.wasm
wasm-tools /tmp/truncated.wasm --json | jq '.errors, .analysis.detections.format'
```

## Choosing a workflow

The CLI and the library produce the same decode. Pick your entry point by what happens next.

- Use the CLI for interactive triage: `--headers` for a map, `-x` for section contents, `-d` for instructions, `--json` for anything you want to pipe through `jq`.
- Use the library (`wasm_tools.api.parse_wasm_file` or `parse_wasm_bytes`) when another program consumes the result. The JSON report is the stable contract.
- Use a custom visitor (subclass from `wasm_tools.visitor`) when you need a decode mode the CLI does not offer, such as counting specific instructions or streaming events into your own store.

## Where to go next

Work through [lesson 1](LESSON1.md) for a guided first contact with an unknown module, or jump straight to the [analyst guide](ANALYST_GUIDE.md) if you have a file waiting. The [CLI reference](CLI.md) documents every flag, and the [JSON report reference](JSON_REFERENCE.md) documents every field.
