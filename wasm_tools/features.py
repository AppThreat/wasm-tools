"""Static opcode and structural features for downstream detectors.

Every published WebAssembly malware and miner detector leans on features a
static parser can compute (MINOS's opcode sequences and CNN inputs, the
histogram feature vectors of later detectors, call-graph and ratio-shaped
features chosen for robustness against semantics-preserving perturbation).
The module walks the already-decoded function list and ships the data:
full per-mnemonic histograms, capped top n-grams over per-function mnemonic
sequences, prefix-family counts, and size-normalized derived ratios.

Determinism contract: identical input produces identical output; histograms
are sorted by count descending then mnemonic, n-grams by count descending
then gram text, and ratios are rounded to four decimals. Mnemonic names
follow the OPCODES table verbatim; consumers must tolerate unknown
mnemonic keys across minor releases.
"""

from __future__ import annotations

from typing import Any, Optional

from .opcodes import OPCODES

# n-gram window sizes and the cap on emitted grams (top by count, ties
# broken lexicographically so output is stable).
NGRAM_SIZES = (2, 3)
NGRAM_TOP = 50

# Mnemonic -> prefix family, derived from the opcode table so prefix counts
# are exact rather than name-shaped guesses.
_MNEMONIC_PREFIX: dict[str, str] = {
    name: {0: "core", 0xFC: "fc", 0xFB: "fb", 0xFD: "fd", 0xFE: "fe"}[prefix]
    for (prefix, _code), (name, _imm) in OPCODES.items()
}


def _function_sequences(functions: list[dict[str, Any]]) -> list[list[str]]:
    sequences = []
    for fn in functions:
        instructions = fn.get("instructions") or []
        sequences.append([str(ins.get("opcode", "")) for ins in instructions])
    return sequences


def build_features(
    functions: list[dict[str, Any]],
    imports: list[dict[str, Any]],
    exports: list[dict[str, Any]],
    sections: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the ``analysis.features`` block.

    Called with the pre-trim function list so budgets and instruction
    opt-outs never change the emitted statistics.
    """
    sequences = _function_sequences(functions)

    histogram: dict[str, int] = {}
    prefix_counts = {"core": 0, "fc": 0, "fb": 0, "fd": 0, "fe": 0}
    for sequence in sequences:
        for mnemonic in sequence:
            histogram[mnemonic] = histogram.get(mnemonic, 0) + 1
            prefix = _MNEMONIC_PREFIX.get(mnemonic)
            if prefix is not None:
                prefix_counts[prefix] += 1

    ngram_counter: dict[tuple[int, str], int] = {}
    for sequence in sequences:
        # n-grams stay inside function boundaries: crossing them injects
        # fake grams through the function-end sentinel.
        for n in NGRAM_SIZES:
            for start in range(0, max(0, len(sequence) - n + 1)):
                gram = "|".join(sequence[start : start + n])
                key = (n, gram)
                ngram_counter[key] = ngram_counter.get(key, 0) + 1
    ngram_top = [
        {"n": n, "gram": gram, "count": count}
        for (n, gram), count in sorted(
            ngram_counter.items(), key=lambda kv: (-kv[1], kv[0][1])
        )[:NGRAM_TOP]
    ]

    total = sum(histogram.values())
    mem_ops = sum(
        count
        for mnemonic, count in histogram.items()
        if mnemonic.startswith(
            (
                "i32.load", "i64.load", "f32.load", "f64.load", "v128.load",
                "i32.store", "i64.store", "f32.store", "f64.store", "v128.store",
                "memory.",
            )
        )
    )
    call_ops = sum(
        count for mnemonic, count in histogram.items() if mnemonic.startswith("call") or mnemonic.startswith("return_call")
    )
    branch_ops = sum(
        count for mnemonic, count in histogram.items() if mnemonic in {"br", "br_if", "br_table"}
    )
    f64_arith = sum(
        count
        for mnemonic, count in histogram.items()
        if mnemonic.startswith("f64.") and mnemonic not in {"f64.load", "f64.store"}
    )
    simd_ops = prefix_counts["fd"]
    functions_with_loops = sum(
        1 for fn in functions if (fn.get("features") or {}).get("has_loop")
    )
    indirect_calls = sum(
        count
        for mnemonic, count in histogram.items()
        if mnemonic in {"call_indirect", "return_call_indirect"}
    )
    section_sizes: dict[int, int] = {}
    for sec in sections:
        section_sizes.setdefault(int(sec.get("id", -1)), 0)
        section_sizes[int(sec.get("id", -1))] += int(sec.get("size", 0))
    total_section_bytes = sum(section_sizes.values()) or 1

    exported_func_count = sum(
        1 for exp in exports if str(exp.get("kind", "")) == "func"
    )

    def ratio(numerator: int) -> float:
        return round(numerator / total, 4) if total else 0.0

    derived = {
        "mem_op_ratio": ratio(mem_ops),
        "call_op_ratio": ratio(call_ops),
        "simd_ratio": ratio(simd_ops),
        "branch_density": ratio(branch_ops),
        "loop_function_ratio": round(
            functions_with_loops / len(functions), 4
        ) if functions else 0.0,
        "indirect_call_ratio": ratio(indirect_calls),
        "f64_arith_ratio": ratio(f64_arith),
        "avg_instructions_per_function": round(
            total / len(functions), 4
        ) if functions else 0.0,
        "code_section_share": round(
            section_sizes.get(10, 0) / total_section_bytes, 4
        ),
        "data_section_share": round(
            section_sizes.get(11, 0) / total_section_bytes, 4
        ),
        "function_count": len(functions),
        "exported_function_count": exported_func_count,
    }
    return {
        "opcode_histogram": dict(
            sorted(histogram.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
        "histogram_total": total,
        "distinct_opcodes": len(histogram),
        "prefix_counts": prefix_counts,
        "ngram_top": ngram_top,
        "derived": derived,
    }


# ─── WASM-MIN-009 cryptojacking heuristic ────────────────────────────────────
# Structural thresholds for the compute-bound, miner-shaped module profile:
# tight numeric kernels, no call graph, no branchy application logic. The
# ratios are the perturbation-robust half (Swamped, ASE 2025); string
# corroboration (the existing mining_indicator signal) is the only path to
# medium confidence. Numeric libraries can match the shape, so severity
# stays medium and the finding says so.
_MIN_RULE = {
    "f64_arith_ratio": 0.15,
    "simd_ratio": 0.30,
    "loop_function_ratio": 0.5,
    "call_op_ratio": 0.08,
    "branch_density": 0.20,
    "max_exported_functions": 5,
}


def evaluate_miner_heuristic(
    features: dict[str, Any],
    strings_detection: Optional[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Return WASM-MIN-009 evidence when the module matches the miner shape."""
    derived = features.get("derived", {})
    compute_bound = (
        derived.get("f64_arith_ratio", 0.0) >= _MIN_RULE["f64_arith_ratio"]
        or derived.get("simd_ratio", 0.0) >= _MIN_RULE["simd_ratio"]
    )
    tight_loop = derived.get("loop_function_ratio", 0.0) >= _MIN_RULE["loop_function_ratio"]
    call_free = derived.get("call_op_ratio", 0.0) <= _MIN_RULE["call_op_ratio"]
    linear = derived.get("branch_density", 1.0) <= _MIN_RULE["branch_density"]
    thin_surface = (
        derived.get("exported_function_count", 99)
        <= _MIN_RULE["max_exported_functions"]
    )
    if not (compute_bound and tight_loop and call_free and linear and thin_surface):
        return None
    mining_signals = set((strings_detection or {}).get("signals", []))
    has_string_support = "mining_indicator" in mining_signals
    evidence = {
        "f64_arith_ratio": derived.get("f64_arith_ratio"),
        "simd_ratio": derived.get("simd_ratio"),
        "loop_function_ratio": derived.get("loop_function_ratio"),
        "call_op_ratio": derived.get("call_op_ratio"),
        "branch_density": derived.get("branch_density"),
        "exported_function_count": derived.get("exported_function_count"),
        "mining_strings": has_string_support,
        "thresholds": dict(_MIN_RULE),
    }
    return evidence
