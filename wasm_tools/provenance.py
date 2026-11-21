"""Toolchain and glue provenance from decoded report inputs.

Provenance answers one question for the analyst: what built this module and
what glue framework did it come through, at what confidence, on what
evidence. The detection table below reflects verified toolchain behavior:

- LLVM-based toolchains (clang, rustc) emit the producers custom section
  via WebAssemblyAsmPrinter and lld merges entries, so a producers hit is
  a high-confidence claim.
- Emscripten strips producers by default (EMIT_PRODUCERS_SECTION=false), and
  Go, TinyGo, and AssemblyScript never emit them; those toolchains are
  detected from imports, exports, custom sections, and data strings, and
  claims stay medium-confidence because import shapes are conventions, not
  authorities.
- No version is ever claimed without a producers or DWARF string that
  states one.

The block is additive analysis output (``analysis.provenance``); it never
changes findings or risk scores.
"""

from __future__ import annotations

import re
from typing import Any, Optional

# A DWARF producer string of a zig build: "zig 0.13.0" and the like.
_ZIG_PRODUCER_RE = re.compile(r"^zig \d+\.\d+")

_WASI_IMPORT_SUBSET_GO = {
    "clock_time_get",
    "environ_get",
    "environ_sizes_get",
    "fd_write",
    "proc_exit",
    "random_get",
}


def _entry(compiler: str, version: str, confidence: str, evidence: list[str]) -> dict[str, Any]:
    return {
        "name": compiler,
        "version": version,
        "confidence": confidence,
        "evidence": evidence,
    }


def build_provenance(
    toolchain: dict[str, Any],
    imports: list[dict[str, Any]],
    exports: list[dict[str, Any]],
    function_names: list[str],
    strings: list[str],
    debug_str: Optional[bytes],
    dylink: Optional[dict[str, Any]],
    has_name_section: bool,
) -> dict[str, Any]:
    """Assemble the ``analysis.provenance`` block from decoded inputs.

    ``strings`` are the extracted data-segment strings; ``debug_str`` is the
    raw .debug_str payload when present (DWARF producer strings live there);
    ``dylink`` is the decoded emscripten dynamic-linking metadata when
    present.
    """
    producers = toolchain.get("processed_by", [])
    processed_by = {
        str(entry.get("name", "")): str(entry.get("version", ""))
        for entry in producers
    }
    languages = {str(lang) for lang in toolchain.get("languages", [])}
    export_names = [str(exp.get("name", "")) for exp in exports]
    import_modules = [str(imp.get("module", "")) for imp in imports]
    import_names = [str(imp.get("name", "")) for imp in imports]
    module_strings = [str(s) for s in strings]

    compilers: list[dict[str, Any]] = []
    glue: list[dict[str, Any]] = []
    notes: list[str] = []

    def add_compiler(name: str, version: str, confidence: str, evidence: list[str]) -> None:
        compilers.append(_entry(name, version, confidence, evidence))

    def add_glue(name: str, version: str, confidence: str, evidence: list[str]) -> None:
        glue.append(_entry(name, version, confidence, evidence))

    # ── producers-backed claims (high confidence) ───────────────────────────
    if "rustc" in processed_by or "Rust" in languages:
        evidence = []
        if "rustc" in processed_by:
            evidence.append(f"producers.processed_by[rustc]={processed_by['rustc']}")
        if "Rust" in languages:
            evidence.append("producers.language[Rust]")
        add_compiler("rustc", processed_by.get("rustc", ""), "high", evidence)
    if "clang" in processed_by:
        add_compiler(
            "clang",
            processed_by["clang"],
            "high",
            [f"producers.processed_by[clang]={processed_by['clang']}"],
        )
    elif languages & {"C", "C++"}:
        add_compiler(
            "clang",
            "",
            "high",
            [f"producers.language[{sorted(languages & {'C', 'C++'})[0]}]"],
        )
    if "Javy" in processed_by:
        add_compiler(
            "Javy",
            processed_by["Javy"],
            "high",
            [f"producers.processed_by[Javy]={processed_by['Javy']}"],
        )
    if "Binaryen" in processed_by:
        add_glue(
            "Binaryen",
            processed_by["Binaryen"],
            "high",
            [f"producers.processed_by[Binaryen]={processed_by['Binaryen']}"],
        )

    # ── wasm-bindgen glue ────────────────────────────────────────────────────
    if "wasm-bindgen" in processed_by:
        add_glue(
            "wasm-bindgen",
            processed_by["wasm-bindgen"],
            "high",
            [f"producers.processed_by[wasm-bindgen]={processed_by['wasm-bindgen']}"],
        )
    else:
        wbg_exports = [n for n in export_names if n.startswith("__wbindgen")]
        wbg_imports = [m for m in import_modules if m in {"wbg", "js"}]
        if wbg_exports or wbg_imports:
            evidence = []
            if wbg_exports:
                evidence.append(f"{len(wbg_exports)} __wbindgen_* exports")
            if wbg_imports:
                evidence.append(
                    f"{len(wbg_imports)} imports from module {wbg_imports[0]}"
                )
            add_glue("wasm-bindgen", "", "medium", evidence)

    # ── import/section/string-shaped claims (medium confidence) ─────────────
    emscripten_imports = [
        n
        for n in import_names
        if "emscripten" in n or n.startswith("invoke_")
    ]
    if dylink is not None or emscripten_imports:
        evidence = []
        if dylink is not None:
            evidence.append(
                f"dylink custom section ({'legacy' if dylink.get('legacy') else 'dylink.0'})"
            )
        if emscripten_imports:
            evidence.append(f"{len(emscripten_imports)} emscripten-glue imports")
        add_compiler("emscripten", "", "high" if dylink is not None else "medium", evidence)
        if not processed_by:
            notes.append(
                "emscripten strips the producers section by default, so its absence is expected here"
            )

    wasi_imports = {
        str(imp.get("name", ""))
        for imp in imports
        if str(imp.get("module", "")) == "wasi_snapshot_preview1"
    }
    go_strings = any(s.startswith(("runtime.", "go:")) for s in module_strings)
    # The Go wasip1 import subset alone also fits any small C or Rust WASI
    # command that only writes and exits, so Go runtime strings are required
    # as well.
    if (
        not processed_by
        and not has_name_section
        and wasi_imports
        and wasi_imports.issubset(_WASI_IMPORT_SUBSET_GO)
        and go_strings
    ):
        evidence = [
            f"{len(wasi_imports)} wasi_snapshot_preview1 imports (Go wasip1 subset)",
            "Go runtime strings in data segments",
        ]
        add_compiler("go", "", "medium", evidence)
        tinygo_strings = any("tinygo" in s.lower() for s in module_strings)
        if tinygo_strings:
            add_compiler("tinygo", "", "medium", evidence + ["TinyGo runtime strings"])

    as_exports = [n for n in export_names if n in {"__new", "__pin", "__unpin", "__collect"}]
    if "env.abort" in {
        f"{imp.get('module', '')}.{imp.get('name', '')}" for imp in imports
    } and as_exports:
        add_compiler(
            "assemblyscript",
            "",
            "medium",
            ["env.abort import", "AssemblyScript GC runtime exports (__new/__pin/__unpin/__collect)"],
        )

    dotnet_strings = any(s.startswith("dotnet") for s in module_strings)
    if dylink is not None and dotnet_strings:
        add_compiler(".NET", "", "medium", ["dylink section", "dotnet strings in data segments"])

    # DWARF producer strings: .debug_str carries "clang version ...", and
    # zig builds leave "zig <version>" there too.
    # Only whole NUL-terminated strings count as producer strings, so a
    # source string that merely mentions "zig " does not.
    if debug_str:
        strings = debug_str[:65536].decode("utf-8", errors="replace").split("\x00")
        if any("clang version" in text.lower() for text in strings) and "clang" not in {
            c["name"] for c in compilers
        }:
            add_compiler("clang", "", "high", ["DWARF .debug_str 'clang version' string"])
        if any(_ZIG_PRODUCER_RE.match(text) for text in strings):
            add_compiler("zig", "", "high", ["DWARF .debug_str 'zig <version>' producer string"])

    # Name-section mangling shapes.
    kotlin_names = [n for n in function_names if "kotlin" in n.lower()]
    if kotlin_names:
        add_compiler("kotlin/wasm", "", "medium", ["kotlin.wasm.internal name-section mangling"])
    swift_names = [n for n in function_names if n.startswith("_$s")]
    if swift_names:
        add_compiler("swiftwasm", "", "medium", [f"{len(swift_names)} Swift _$s-mangled names"])

    # ── runtime target and platform resolution ──────────────────────────────
    has_wasi_p1 = any(m == "wasi_snapshot_preview1" for m in import_modules)
    has_wasi_p2 = any(m.startswith("wasi:") for m in import_modules)
    # Bare env imports are ubiquitous (abort hooks, allocator glue), so the
    # browser-js target requires the dedicated JS namespaces or an identified
    # glue framework rather than any env import.
    # Binaryen is an optimizer, not a JS glue layer, so it never implies a
    # browser target on its own.
    has_js_glue = bool(
        {m for m in import_modules if m in {"wbg", "js"}}
        or any(entry["name"] != "Binaryen" for entry in glue)
    )
    if has_wasi_p2:
        runtime_target = {"name": "wasi-preview2+", "confidence": "high"}
    elif has_wasi_p1:
        runtime_target = {"name": "wasi-preview1", "confidence": "high"}
    elif has_js_glue:
        runtime_target = {"name": "browser-js", "confidence": "medium"}
    else:
        runtime_target = {"name": "unknown", "confidence": "none"}

    fastly = [m for m in import_modules if m.startswith("fastly:")]
    if fastly:
        platform = {
            "name": "fastly-compute",
            "confidence": "high",
            "evidence": [f"imports {sorted(set(fastly))[0]}"],
        }
    elif runtime_target["name"] == "browser-js":
        platform = {"name": "browser", "confidence": "medium", "evidence": []}
    else:
        platform = {"name": "none", "confidence": "none", "evidence": []}

    stripped_producers = not processed_by and dylink is not None
    return {
        "compilers": compilers,
        "glue": glue,
        "runtime_target": runtime_target,
        "platform": platform,
        "stripped_producers": stripped_producers,
        "notes": notes,
    }
