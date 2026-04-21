# WebAssembly Dependency Detection and Package URL Construction

## Executive Summary

WebAssembly binaries **do refer to external dependencies and host capabilities**, but unlike traditional binaries with static linking or dynamic library references, WASM uses an **interface-based import system**. This document explores dependency detection mechanisms, package URL construction, and supply chain analysis opportunities.

---

## Part 1: How WASM Binaries Reference Dependencies

### 1.1 Import Section (Primary Mechanism)

Every WASM module contains an **import section** that declares functions, tables, memories, globals, and exception tags imported from external sources. This is the primary **explicit dependency declaration**.

**Binary Structure** (from `5.4-binary.modules.spectec`):

```
import := IMPORT module_name item_name externtype
```

**Example** (real output from `wasi_capabilities.wasm`):

```json
{
  "index": 0,
  "module": "wasi_snapshot_preview1",
  "name": "fd_write",
  "kind": "func",
  "type_index": 0
}
```

**Characteristics:**

- Each import declares a **(module name, item name, type signature)** triple.
- Module names are arbitrary strings; they are **convention-based, not authority-based**.
- No versioning information in the binary itself.
- No hash or cryptographic binding to the actual implementation.

**Common module namespaces observed in the wild:**

| Module Namespace         | Purpose                           | Example Names                                           |
| ------------------------ | --------------------------------- | ------------------------------------------------------- |
| `wasi_snapshot_preview1` | WASI system call interface        | `fd_write`, `path_open`, `sock_send`, `proc_exit`       |
| `wasi_unstable`          | Legacy WASI (pre-preview1)        | `fd_*`, `path_*`                                        |
| `wasi:*` (preview2-like) | Component-model WASI              | `wasi:filesystem/...`, `wasi:http/...`                  |
| `env`                    | Host environment                  | User-defined imports from embedders (Node.js, browsers) |
| `js` / `wbg`             | JavaScript interop (WASM-bindgen) | `__wbindgen_*`, `console_log`                           |
| `musli:*`                | Musli serialization framework     | Framework-specific imports                              |
| `libname`                | Application-specific              | Directly named libraries (rare)                         |

### 1.2 Custom Sections (Metadata and Toolchain Info)

Custom sections with **well-known names** provide metadata that can hint at dependency provenance and build chain:

**Known custom section names:**

| Name                | Content                                                             | Relevance                                              |
| ------------------- | ------------------------------------------------------------------- | ------------------------------------------------------ |
| `name`              | Function, local, and possibly module names (decoded by this parser) | Can hint at compiler and naming conventions            |
| `producers`         | List of toolchains used (e.g., `clang@15`, `wasm-bindgen@0.2.87`)   | Supply chain provenance                                |
| `target_features`   | Enabled proposal features (SIMD, threads, gc, bulk_memory)          | Feature flags and compatibility constraints            |
| `dylink.0`          | Shared library metadata for wasm32-emscripten                       | Indicates dynamic linking dependency model             |
| `component-type`    | Component-model metadata                                            | Indicates the binary is a component, not a core module |
| `code-section-name` | Custom code section naming (non-standard)                           | Toolchain fingerprinting                               |

**Example from the spec and real binaries:**

- **Emscripten** binaries carry `dylink.0` custom section with memory/table size hints.
- **Wasm-bindgen** (Rust+WASM) uses `wbg` imports and may carry toolchain metadata.
- **Components** carry `component-type` custom sections that describe their interface and dependencies on other components.

### 1.3 Global Initializers (Indirect Dependencies)

Global variables can have **constant init expressions**. While the core spec only allows `global.get` and const values, some toolchains embed references:

```wasm
(global i32 (global.get $imported_global))
```

This creates an **implicit dependency** on the imported global.

### 1.4 Data and Element Segments (Embedded Metadata)

- **Data segments** contain static memory initialization; they sometimes include **string literals that name dependencies** (especially in debug builds).
- **Element segments** initialize tables with function references; they implicitly depend on the table structure and function layout.

### 1.5 Component Model (Emerging)

The **WebAssembly Component Model** (W3C proposal, not yet in core spec) extends WASM with:

- Explicit component composition and interface definitions.
- Component instantiation with explicit dependency graphs.
- Nested components with versioned interfaces.

Components declared in custom sections or in component binaries carry **strong dependency declarations**.

---

## Part 2: Dependency Detection Strategies

### 2.1 Import-Based Detection (Highest Confidence)

**Strategy:** Parse all imports and normalize module/name pairs into capability identifiers.

**Advantages:**

- Explicit in the binary.
- Unambiguous for WASI and well-known frameworks.
- Can be extracted without parsing function bodies.

**Limitations:**

- No version information in the binary.
- Module names are conventions, not authorities.
- Cannot distinguish between "optional" and "required" imports.
- Toolchain-specific imports (`env.foo`) have no standard registry.

**Implementation in current codebase:**
The parser already extracts all imports. We extend this with:

1. Normalize module names (e.g., `wasi_snapshot_preview1` → `wasi` v0.2).
2. Group imports by (module, capability intent).
3. Flag unusual or unknown module names.
4. Emit JavaScript embedder signals in `analysis.detections.js_interface` for `js` / `wbg` namespaces, `wasm:*` builtin namespaces (for example `wasm:js-string`), and common glue symbol families.

### 2.2 Custom Section Analysis

**Strategy:** Parse and inspect well-known custom sections (`producers`, `target_features`, `dylink.0`, `component-type`).

**Advantages:**

- Provides toolchain/compiler information.
- Component metadata is explicit.
- Feature flags enable version compatibility checks.

**Limitations:**

- Not all toolchains emit metadata.
- Format varies between toolchains.
- Custom section parsing is toolchain-specific.

**Implementation opportunity:**
Extend `_BinaryReaderJsonCollector.build_report()` to decode common custom section formats and extract:

- Toolchain versions.
- Component type metadata.
- Dynamic linking requirements.

### 2.3 Heuristic Detection from Function Behavior

**Strategy:** Scan function bodies for patterns that hint at dependency usage.

**Examples:**

- Functions that call only imported functions → thin wrapper over external library.
- High ratios of `call` to local code → wrapper or trampoline.
- Indirect calls on imported table → dynamic dispatch framework.

**Limitations:**

- Low confidence without ground truth.
- Requires full disassembly; expensive.

### 2.4 Known Patterns Database

**Strategy:** Maintain a pattern database of common WASM frameworks and their import signatures.

**Examples:**

- WASI preview1 function set → POSIX-like system interface.
- Wasm-bindgen import set (`__wbindgen_*`, module=`wbg`) → Rust/WebAssembly toolchain.
- Emscripten (data segment size, `dylink.0`) → C/C++ compiled to WASM.

**Implementation:**
Create a `WASM_FRAMEWORKS` dict mapping (module, name patterns) to framework identifiers and versions.

---

## Part 3: Package URL (PURL) Construction

[Package URL spec](https://github.com/package-url/purl-spec) defines:

```
purl = scheme:type/namespace/name[@version][?qualifiers][#subpath]
```

### 3.1 WASM PURL Type

Propose `pkg:generic` with `type=wasm` qualifier as the WASM-specific PURL format:

```
pkg:generic/wasi@0.2.0?type=wasm&interface=wasi
pkg:generic/wasm-bindgen@0.2.87?type=wasm&framework=wasm-bindgen
pkg:generic/emscripten@3.1.27?type=wasm&framework=emscripten
pkg:generic/http-server@1.0.0?type=wasm&model=component
```

**Rationale:**

- `pkg:generic` is the official PURL type for packages not covered by other types.
- `type=wasm` qualifier explicitly marks this as a WebAssembly module.
- Additional qualifiers (`interface=wasi`, `framework=wbg`) provide semantic context for supply chain tools.
- Follows [Package URL spec](https://github.com/package-url/purl-spec) conventions.

### 3.2 PURL Derivation from Imports

| Detection Method   | PURL Example                                                       | Confidence                      |
| ------------------ | ------------------------------------------------------------------ | ------------------------------- |
| **WASI preview1**  | `pkg:generic/wasi@0.2.0?type=wasm&interface=wasi`                  | High (standardized)             |
| **WASI preview2**  | `pkg:generic/wasi@0.2.1?type=wasm&interface=wasi`                  | High                            |
| **Wasm-bindgen**   | `pkg:generic/wasm-bindgen@0.2.87?type=wasm&framework=wasm-bindgen` | Medium (from producer metadata) |
| **Emscripten**     | `pkg:generic/emscripten@3.1.27?type=wasm&framework=emscripten`     | Medium (custom section)         |
| **Component type** | `pkg:generic/component@1.0?type=wasm&model=component`              | Medium (component-model)        |
| **Unknown module** | `pkg:generic/unknown-module?type=wasm`                             | Low (heuristic)                 |

### 3.3 Versioning Strategy

**Challenge:** WASM binaries do not embed version information for imports.

**Solutions:**

1. **WASI versions** are standardized externally:
   - `wasi_snapshot_preview1` → WASI 0.2.0 (standardized)
   - `wasi_unstable` → WASI 0.1.0 (legacy)
   - `wasi:*` → WASI 0.2.1+ (preview2)

2. **Toolchain versions** (if available in custom sections):
   - Parse `producers` section: extract `clang@15.0.0`, `wasm-bindgen@0.2.87`.
   - Use these as qualifiers in PURL.

3. **Function signature fingerprinting**:
   - Hash the type signatures of all imports.
   - Compare against known frameworks' expected signatures.
   - Assign version based on best match.

4. **Fallback:**
   - Mark as `@unknown` if no metadata is present.
