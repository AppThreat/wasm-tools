# Toolchain provenance and demangling

The `analysis.provenance` block answers one question for the analyst: what
built this module and what glue framework did it come through, at what
confidence, on what evidence. It never changes findings or risk scores.

## Detection table

Producers-backed claims are high confidence (LLVM-based toolchains emit the
`producers` custom section through WebAssemblyAsmPrinter and lld merges
entries). Import-, export-, custom-section-, and string-shaped claims stay
medium because import shapes are conventions, not authorities. No version is
ever claimed without a producers or DWARF string stating one.

| Target            | Signals used |
| ----------------- | ------------ |
| `rustc`           | producers `language[Rust]` or `processed_by[rustc]`; version from the producers string |
| `clang`           | producers `processed_by[clang]` or `language[C/C++]`; DWARF `.debug_str` carrying a `clang version` string |
| `emscripten`      | `dylink.0` or legacy `dylink` custom section, `emscripten`/`invoke_` glue imports. Emscripten strips producers by default, so their absence is expected here and noted, not suspicious |
| `go`              | No producers, no name section, the wasi wasip1 import subset, Go runtime strings in data segments |
| `tinygo`          | Go signals plus TinyGo runtime strings |
| `assemblyscript`  | `env.abort` import plus the `__new`/`__pin`/`__unpin`/`__collect` GC runtime exports |
| `.NET`            | dylink plus `dotnet` strings in data segments |
| `zig`             | DWARF producer string carrying `zig <version>` |
| `kotlin/wasm`     | `kotlin.wasm.internal` name-section mangling |
| `swiftwasm`       | Swift `_$s`-mangled names in the name section |
| `javy`            | producers `processed_by[Javy]` |
| glue: `wasm-bindgen` | producers entry, `__wbindgen_*` exports, `wbg`/`js` import modules |
| glue: `binaryen`  | producers `processed_by[Binaryen]` |

`runtime_target` resolves among `wasi-preview2+`, `wasi-preview1`,
`browser-js` (requires the dedicated JS namespaces or an identified glue
framework; bare `env` imports are too common to count), and `unknown`.
`platform` resolves `fastly-compute` (from `fastly:compute` imports),
`browser`, or `none`. `stripped_producers` is true when emscripten-class
signals exist without a producers section.

## Demangling

`wasm_tools.demangle` implements a zero-dependency subset:

- Rust legacy `_ZN...E` names render as `crate::module::func`, dropping the
  hash-terminated `17h<16 hex>` suffix (RFC 2603 documents the shape).
- Rust v0 `_R` names for crate-path shapes: `C<ident>` crate roots and
  `N <ns> <path> <identifier>` nesting, with value/type namespaces hidden,
  closures rendered `{closure#index}`, and shims `{shim#index}`.
- Everything else, including C++ Itanium and the v0 `M`/`X`/`Y`/`I`/`B`
  path forms, returns the input unchanged. A wrong demangle is worse than an
  un-demangled name.

With demangling enabled (default; `--no-demangle` to skip) functions and
exports gain `demangled_name` and call graph nodes gain it for presentation
only. Node and edge identity stays index-based. Consumers that have the
`multi-demangle` package keep it authoritative; this subset serves the
zero-dependency CLI and reports.
