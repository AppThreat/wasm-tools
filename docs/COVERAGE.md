# Spec coverage matrix

This matrix records what the current codebase decodes, based on `wasm_tools/parser.py`, `wasm_tools/opcodes.py`, `wasm_tools/visitor.py`, `wasm_tools/api.py`, and the test suite. It is a planning aid, not a certification statement.

Status terms: `Tested` means implemented and covered by automated tests. `Partial` means implemented in a limited way or traversed without full semantic decoding. `Known gap` is explicitly tracked missing behavior. `Not implemented` means no support and no evidence in tests.

## Module and section coverage

| Area                                 | Spec reference               | Status  | Notes                                                                                                                                  |
| ------------------------------------ | ---------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Module header and version            | `5.4-binary.modules.spectec` | Tested  | Magic and version validated; error cases covered in `tests/test_parser.py`.                                                            |
| Section framing and bounds           | `5.4-binary.modules.spectec` | Tested  | Section overrun checks; errors reported through `on_error`.                                                                            |
| Custom sections, generic             | `5.4-binary.modules.spectec` | Partial | Name is recorded; arbitrary payloads are skipped, not decoded.                                                                         |
| Custom `name` section                | `5.4-binary.modules.spectec` | Tested  | Subsections 1 (functions) and 2 (locals). Unicode names covered by `unicode_names.wat`.                                                |
| Custom `producers`/`target_features` | tool-conventions             | Tested  | Decoded into the toolchain block and printed in `-x` details mode.                                                                     |
| DWARF `.debug_*` sections            | DWARF in wasm convention     | Partial | Detected by name (`debug_info_present` signal); `.debug_str` payloads feed string extraction.                                          |
| Type section                         | `5.4-binary.modules.spectec` | Tested  | Including GC subtype and rec-type wrappers; rec-group members occupy individual type indices, composite kinds are reported via `kind`. |
| Import section                       | `5.4-binary.modules.spectec` | Tested  | All five kinds fully decoded.                                                                                                          |
| Function section                     | `5.4-binary.modules.spectec` | Tested  | Signature indices stored for prepass and JSON.                                                                                         |
| Table section                        | `5.4-binary.modules.spectec` | Tested  | Reference type and limits, including table64.                                                                                          |
| Memory section                       | `5.4-binary.modules.spectec` | Tested  | i32 and i64 limits, shared flag, custom page sizes.                                                                                    |
| Global section                       | `5.4-binary.modules.spectec` | Tested  | Type, mutability, constant initializer.                                                                                                |
| Export section                       | `5.4-binary.modules.spectec` | Tested  | All five kinds.                                                                                                                        |
| Start section                        | `5.4-binary.modules.spectec` | Tested  | Surfaced as `start_function`.                                                                                                          |
| Element section                      | `5.4-binary.modules.spectec` | Tested  | All 8 segment variants.                                                                                                                |
| Code section                         | `5.4-binary.modules.spectec` | Tested  | Local declarations, full instruction decode, body end tracking.                                                                        |
| Data section                         | `5.4-binary.modules.spectec` | Tested  | Active (mem 0), passive, and active (mem x) variants.                                                                                  |
| DataCount section                    | `5.4-binary.modules.spectec` | Tested  | Decoded and forwarded via `on_data_count`.                                                                                             |
| Tag section                          | `5.4-binary.modules.spectec` | Tested  | Tag entries with type index.                                                                                                           |

## Instruction coverage

| Area                                                       | Spec reference                    | Status | Notes                                                                                                                                                            |
| ---------------------------------------------------------- | --------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parametric basics (`unreachable`, `nop`, `drop`, `select`) | `5.3-binary.instructions.spectec` | Tested | Typed `select` via `SELECT_T`.                                                                                                                                   |
| Blocks, loops, ifs, ends                                   | `5.3-binary.instructions.spectec` | Tested | Block signatures and depth tracking.                                                                                                                             |
| Branching (`br`, `br_if`, `br_table`, `return`)            | `5.3-binary.instructions.spectec` | Tested | `br_table` target vectors decoded and printed.                                                                                                                   |
| Direct and indirect calls                                  | `5.3-binary.instructions.spectec` | Tested | `call` index and `call_indirect` type plus table operands.                                                                                                       |
| Return-call extensions                                     | `5.3-binary.instructions.spectec` | Tested | `return_call`, `return_call_indirect`, `call_ref`, `return_call_ref`.                                                                                            |
| Variable access                                            | `5.3-binary.instructions.spectec` | Tested | Local and global access immediates.                                                                                                                              |
| Loads and stores with memarg                               | `5.3-binary.instructions.spectec` | Tested | Includes memory64 large offsets.                                                                                                                                 |
| Numeric constants                                          | `5.3-binary.instructions.spectec` | Tested | All four widths, edge signed immediates in `adversarial_ops.wat`.                                                                                                |
| Scalar arithmetic and comparison                           | `5.3-binary.instructions.spectec` | Tested | Full i32/i64/f32/f64 sets plus sign-extension ops.                                                                                                               |
| Reference type ops                                         | `5.3-binary.instructions.spectec` | Tested | `0xD0` to `0xD6`, heaptype immediates.                                                                                                                           |
| Saturating truncation                                      | `5.3-binary.instructions.spectec` | Tested | All eight `0xFC 0-7`.                                                                                                                                            |
| Bulk memory                                                | `5.3-binary.instructions.spectec` | Tested | `memory.init`, `data.drop`, `memory.copy`, `memory.fill` with correct operand order.                                                                             |
| Table bulk ops                                             | `5.3-binary.instructions.spectec` | Tested | `0xFC 12-17`.                                                                                                                                                    |
| Exception handling                                         | `5.3-binary.instructions.spectec` | Tested | `throw`, `throw_ref`, `try_table` with full catch lists; legacy `try`/`catch`/`catch_all`/`rethrow`/`delegate` (pre-renumbering encoding, still accepted by V8). |
| GC ops (`0xFB` prefix)                                     | `5.3-binary.instructions.spectec` | Tested | All 31 sub-opcodes including `br_on_cast` flag decoding.                                                                                                         |
| SIMD (`0xFD` prefix)                                       | `5.3-binary.instructions.spectec` | Tested | Sub-opcodes 0 to 275, relaxed SIMD, f16x8, all immediate shapes.                                                                                                 |
| Atomics (`0xFE` prefix)                                    | `5.3-binary.instructions.spectec` | Tested | Full set; `atomic.fence` reserved byte.                                                                                                                          |
| Unknown opcode resilience                                  | `5.3-binary.instructions.spectec` | Tested | `unknown_<prefix>_<opcode>` fallback with telemetry.                                                                                                             |
| Wide arithmetic                                            | wide-arithmetic proposal          | Tested | `i64.add128`, `i64.sub128`, `i64.mul_wide_s/u`.                                                                                                                  |
| Half-precision scalar memory                               | half-precision proposal           | Tested | `f32.load_f16`, `f32.store_f16`.                                                                                                                                 |

## Interface and analysis coverage

| Area                             | Status          | Notes                                                                                                                |
| -------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------- |
| CLI disassembly mode (`-d`)      | Tested          | Exact substring assertions across all fixtures.                                                                      |
| CLI headers mode (`--headers`)   | Tested          | Section table output, including custom section names.                                                                |
| CLI details mode (`-x`)          | Tested          | All section content printers.                                                                                        |
| JSON library API                 | Tested          | Full report shape in `tests/test_json_api.py`.                                                                       |
| Non-throwing parse errors        | Tested          | Malformed input populates `errors`.                                                                                  |
| Strings extraction and screening | Tested          | ASCII and UTF-16LE with provenance; secret/IoC signals.                                                              |
| Call graph, xrefs, reachability  | Tested          | Labeled edges including approximations.                                                                              |
| Toolchain fingerprint            | Tested          | `producers` and `target_features` custom sections.                                                                   |
| Component Model binaries         | Tested          | Preamble detection, interface inventory, nested core modules.                                                        |
| Real-toolchain corpus regression | Tested          | Vendored clang/rustc binaries under `tests/fixtures/corpus/` with pinned decode and risk expectations.               |
| Full spec validation             | Not implemented | Deliberate scope choice; validation belongs to runtimes and validators.                                              |
| Text format (`.wat`) input       | Not implemented | Handled externally by WABT's `wat2wasm` for fixture builds; final-spec GC fixtures build with the Rust `wasm-tools`. |

## Scope boundaries

Three gaps are deliberate. Spec validation (type checking and structural constraints from spec chapters 2 and 3) is out of scope; this tool decodes and reports, it does not judge correctness. Text-format input is delegated to WABT. The bundled specification snapshot under `specification/wasm-latest/` serves as a development reference and is not shipped in the PyPI package.

Unknown opcodes are handled by fallback rather than rejection, so "decode everything" does not mean "understand everything": new proposals may decode as `unknown_*` until the table catches up. Check the release history when you see the telemetry described in [findings and signals](FINDINGS.md).
