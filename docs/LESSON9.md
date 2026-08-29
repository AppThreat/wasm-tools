# Lesson 9: Scripting with the Python API

The CLI is a convenience over a library, and the library is where automation lives. This lesson builds a working batch scanner with the public API, then writes a custom visitor for a job no built-in mode does: counting calls across a directory tree. Everything runs on the standard library plus `wasm_tools` itself.

## The API surface

Four functions cover most needs:

```python
from wasm_tools.api import (
    parse_wasm_file,        # path -> report dict
    parse_wasm_bytes,       # bytes -> report dict
    parse_wasm_file_json,   # path -> JSON string
    parse_wasm_bytes_json,  # bytes -> JSON string
)
```

`parse_wasm_bytes` and `parse_wasm_file` accept tuning arguments that the CLI also exposes: `strings_min_len` (default 5), `include_strings`, and `include_call_graph`. Skipping blocks you do not need speeds up large batch runs:

```python
from wasm_tools.api import parse_wasm_bytes

data = open("tests/fixtures/call_graph.wasm", "rb").read()
report = parse_wasm_bytes(data, filename="call_graph.wasm", include_strings=False)
print(report["analysis"]["summary"])
```

The report is a plain dict, so it composes with everything: `json.dumps` it, feed it to pandas, push it to a queue. Two passes run under the hood (see the [architecture page](ARCHITECTURE.md)), and parse errors arrive in `report["errors"]`, not as exceptions.

## A batch scanner

One real-world job: score every `.wasm` in a directory tree and print a ranked list. Save as `scan_dir.py`:

```python
import json
import sys
from pathlib import Path

from wasm_tools.api import parse_wasm_bytes


def scan(root: Path):
    for path in sorted(root.rglob("*.wasm")):
        try:
            data = path.read_bytes()
        except OSError as e:
            print(f"SKIP {path}: {e}", file=sys.stderr)
            continue
        report = parse_wasm_bytes(data, filename=str(path))
        summary = report["analysis"]["summary"]
        finding_ids = [f["id"] for f in report["analysis"]["findings"]]
        caps = ",".join(report["analysis"]["capabilities"])
        yield {
            "file": str(path),
            "score": summary["risk_score"],
            "tier": summary["risk_tier"],
            "errors": len(report["errors"]),
            "unknown_opcodes": summary["unknown_opcode_count"],
            "capabilities": caps,
            "findings": finding_ids,
        }


if __name__ == "__main__":
    rows = sorted(scan(Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures")),
                  key=lambda r: r["score"], reverse=True)
    for row in rows:
        print(json.dumps(row))
```

Run it over the fixture tree:

```bash
python3 scan_dir.py tests/fixtures
```

Sample of the ranked output on this repository's fixtures:

```text
{"file": "tests/fixtures/wasi_capabilities.wasm", "score": 70, "tier": "high", "errors": 0, "unknown_opcodes": 0, "capabilities": "crypto.random,fs.io,fs.path,network,process.terminate", "findings": ["WASM-CAP-001"]}
{"file": "tests/fixtures/js_deopt_surface.wasm", "score": 53, "tier": "medium", ...}
{"file": "tests/fixtures/strings_secrets.wasm", "score": 20, "tier": "low", ...}
{"file": "tests/fixtures/simple_add.wasm", "score": 0, "tier": "none", ...}
```

Note what the scanner inherits for free: truncated or corrupted files come back with `errors` populated instead of exceptions, so the loop never dies mid-directory. That is the error model doing production work. [Lesson 10](LESSON10.md) turns this scanner into a CI gate.

## Custom visitors

When the JSON report does not fit, drop to the delegate layer. The parser emits events; a visitor decides what to keep. Here is a visitor that counts direct calls per function, something the report does not aggregate:

```python
from pathlib import Path

from wasm_tools.models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from wasm_tools.parser import BinaryReader
from wasm_tools.visitor import BinaryReaderNop, BinaryReaderObjdumpPrepass


class CallTally(BinaryReaderNop):
    def __init__(self):
        self.current_function = None
        self.current_opcode = None
        self.tally = {}

    def begin_function_body(self, index, size):
        self.current_function = index

    def on_opcode(self, opcode):
        self.current_opcode = opcode

    def on_opcode_index(self, idx):
        if self.current_opcode and self.current_opcode.name == "call":
            self.tally.setdefault(self.current_function, []).append(idx)


def tally_calls(path):
    data = Path(path).read_bytes()
    options = ObjdumpOptions(mode=ObjdumpMode.PREPASS)
    options.filename = path
    state = ObjdumpState()
    BinaryReader(data, BinaryReaderObjdumpPrepass(data, options, state)).read_module()

    visitor = CallTally()
    BinaryReader(data, visitor).read_module()
    return visitor.tally


print(tally_calls("tests/fixtures/call_graph.wasm"))
```

```text
tests/fixtures/call_graph.wasm:	file format wasm 0x1
{2: [0], 3: [0]}
```

(The first line is the prepass's version banner; it goes to stdout like any other visitor output.)

Function 2 (`run`) and function 3 (`dead`) each call the import at index 0, matching the edges [lesson 6](LESSON6.md) derived. The pattern that makes it work: `on_opcode` fires before immediate callbacks, so the visitor records the current opcode and lets `on_opcode_index` interpret the immediate. Run the prepass first whenever your visitor needs names or types; here it is free insurance.

## Building blocks to steal

Three small patterns cover most integrations:

```text
1. Event counting   subclass BinaryReaderNop, keep counters in the visitor,
                    run one prepass plus one pass. Use for opcode statistics,
                    custom profiles, or metric collection.
2. Report shaping   parse_wasm_bytes + dict comprehensions. Use for
                    dashboards, dedup, and delta reports between builds.
3. Streaming        feed parse_wasm_bytes outputs into a queue or database
                    per file; the error model keeps bad files isolated.
```

The delegate contract and the full callback list are in the [architecture page](ARCHITECTURE.md). If you need a decode mode the CLI lacks, a visitor is usually twenty lines; if it is broadly useful, the [development guide](DEVELOPMENT.md) describes how to contribute it.
