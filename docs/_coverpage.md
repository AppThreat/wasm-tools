# wasm-tools

> A pure-Python WebAssembly parser, disassembler, and security triage toolkit.

[Get started](GETTING_STARTED.md) · [CLI reference](CLI.md) · [Analyst guide](ANALYST_GUIDE.md) · [Lessons](LESSON1.md)

Decode any `.wasm` binary without a runtime, a native library, or a single third-party dependency. Read sections, disassemble function bodies, extract strings, build a call graph, and score host capabilities from the command line or from a few lines of Python.

## Why wasm-tools

Security teams keep receiving `.wasm` files: browser extensions, CDN-served modules, Electron apps, plugin sandboxes, and shipping containers full of components. Most tooling in this space either executes the binary (which you should not do with untrusted input) or wraps a heavyweight runtime. wasm-tools takes a third path: it reads the bytes, reports exactly what is there, and never executes a single instruction.

The whole thing is a handful of Python files you can read in an afternoon. That matters when the tool itself becomes part of your evidence chain.

## Where to go next

If you are triaging an unknown file right now, start with the [analyst guide](ANALYST_GUIDE.md) or [lesson 1](LESSON1.md). If you are integrating WebAssembly inspection into a pipeline, the [JSON report reference](JSON_REFERENCE.md) is the contract you will code against. If you want to understand how the decoder works, the [architecture page](ARCHITECTURE.md) walks the two-pass pipeline end to end.
