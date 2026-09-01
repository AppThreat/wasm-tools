# Vendored real-toolchain corpus

Small, real-world `.wasm` binaries used as regression fixtures against
opcode-table and toolchain-extraction drift. These are compiled artifacts, not
built from `.wat` sources; `tests/fixtures/build.py` does not touch them.

| File | Provenance | Toolchain |
| ---- | ---------- | --------- |
| erc20.wasm, erc721.wasm, erc1155.wasm | `wasmi-labs/wasmi` `crates/wasmi/benches/wasm/` (Soroban smart-contract examples) | rustc |
| bz2.wasm | `wasmi-labs/wasmi-benchmarks` `res/wasm/` (compiled bzip2) | clang 11, ships DWARF `.debug_*` sections and a `producers` section |

Sources are Apache-2.0/MIT licensed repositories; the bzip2 code inside bz2.wasm
is BSD-licensed. Fetched September 2026 while reviewing the Wasmi 2.0 release.
