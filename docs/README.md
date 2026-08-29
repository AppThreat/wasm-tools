# wasm-tools documentation

`wasm-tools` is a pure-Python WebAssembly parser and disassembler built for security work. It reads core modules and Component Model binaries, decodes every section and instruction, extracts strings, builds a static call graph, and produces a structured JSON report with capability and risk analysis. It never executes the code it parses, and the library has zero third-party dependencies.

This site is the complete documentation: a format primer, a CLI reference, a JSON contract, an analyst guide, ten hands-on lessons, and the parser internals.

## The five-minute tour

Install the package and point the CLI at any `.wasm` file:

```bash
pip install wasm-tools
wasm-tools module.wasm -d
```

You get an objdump-style disassembly with file offsets. Add `--json` to get the full machine-readable report, which includes an `analysis` block with risk scoring, host capability inference, WASI and JavaScript interface detection, and rule-based findings:

```bash
wasm-tools module.wasm --json --analysis-only
```

From Python, the same report is one function call away:

```python
from wasm_tools.api import parse_wasm_file

report = parse_wasm_file("module.wasm")
print(report["analysis"]["summary"]["risk_tier"])
```

## How the documentation is organized

| Section                                    | Read it when                                                   |
| ------------------------------------------ | -------------------------------------------------------------- |
| [Getting started](GETTING_STARTED.md)      | You want install steps and your first commands.                |
| [CLI reference](CLI.md)                    | You need the exact flags, output formats, and index semantics. |
| [Format primer](FORMAT_PRIMER.md)          | You want to understand what the bytes in a `.wasm` file mean.  |
| [Component Model](COMPONENT_MODEL.md)      | The binary is a component (version `0x0d` or later).           |
| [JSON report reference](JSON_REFERENCE.md) | You are writing code against the report.                       |
| [Findings and signals](FINDINGS.md)        | A finding fired and you want its exact rule and severity.      |
| [Analyst guide](ANALYST_GUIDE.md)          | You are triaging an unknown file under time pressure.          |
| [Lessons 1 to 10](LESSON1.md)              | You learn best by running commands against real fixtures.      |
| [Architecture](ARCHITECTURE.md)            | You want to know how the parser works inside.                  |
| [Development guide](DEVELOPMENT.md)        | You want to add opcodes, sections, or visitors.                |

## Design stance

Three decisions shape everything else in this project. First, parsing and judging are separated: the decoder reports structure, and the analysis layer heuristically interprets it, so the two can evolve independently. Second, errors are data: malformed input produces entries in `report["errors"]` rather than exceptions, which keeps batch pipelines alive when someone feeds them a fuzzed binary. Third, the opcode table is data: support for a new instruction is usually one entry in `OPCODES` plus one dispatch branch, not a redesign.

These decisions are documented in detail in the [architecture page](ARCHITECTURE.md), and the trade-offs they create (over-approximated indirect call edges, unknown-opcode fallbacks, heuristic risk scores) are stated plainly wherever they apply.
