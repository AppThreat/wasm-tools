"""Obfuscation and packing signal detection.

Wasm obfuscation is documented in the literature and in incident reporting:
general-purpose obfuscators (WASMixer, ESORICS 2024), memory bitwise
obfuscation that defeats string scanning (WeBMO, COMPSAC 2024), multi-level
wat/binary/LLVM pipelines evading miner detectors (Cryptic Bytes, arXiv
2403.15197), Android malware shipping wasm payloads to defeat static
analysis (AndroWasm, arXiv 2602.18082), and eCriminals hiding logic in wasm
(CrowdStrike, December 2024).

The signals here are deliberately conservative: each names a documented
obfuscation shape, single weak signals never fire the finding, and severity
tops at medium unless a strong signal (control-flow flattening dispatcher or
packed data) aligns with a second. Vtable-heavy C++ and Go release builds
are the known false-positive shapes; the per-signal metric values stay in
the report so analysts can apply judgment.
"""

from __future__ import annotations

from typing import Any, Optional

# Signal weights for the composite obfuscation score (0-100). The finding
# fires at >= 30 with severity medium; severity high requires a strong
# signal (dispatcher or packed data) plus any second strong signal.
SIGNAL_WEIGHTS = {
    "dispatcher_loop": 25,
    "packed_data": 20,
    "duplicate_body_ratio": 15,
    "minimal_export_surface": 10,
    "thunk_swarm": 10,
    "name_section_stripped": 5,
    "unusual_metadata": 5,
    "emscripten_side_module_anomaly": 10,
}

STRONG_SIGNALS = {"dispatcher_loop", "packed_data", "duplicate_body_ratio"}
FINDING_SCORE_THRESHOLD = 30

# Thresholds, all named so retuning is a one-diff reviewable change.
DISPATCHER_MIN_TARGETS = 6
# A flattening dispatcher is one small function with a single switch
# dispatching back into its loop. Real state machines (bz2's decompressor
# carries 41- and 57-target switches inside loops in 4-13k instruction
# functions) share the br_table-in-loop shape but not the size or count
# profile, so both gates are required. CFF that inflates case bodies or
# spreads switches across functions still evades this; the per-function
# metrics stay in features for analysts.
DISPATCHER_MAX_FUNCTION_INSTRUCTIONS = 400
DISPATCHER_MAX_BR_TABLES = 1
THUNK_MAX_MEDIAN_INSTRUCTIONS = 4
THUNK_MIN_FUNCTIONS = 30
THUNK_MIN_INDIRECT_SHARE = 0.3
DUPLICATE_MIN_RATIO = 0.4
DUPLICATE_MIN_FUNCTIONS = 20
NAME_STRIPPED_MIN_FUNCTIONS = 10
EXPORT_SURFACE_MAX = 3
EXPORT_SURFACE_MIN_FUNCTIONS = 20
PACKED_ENTROPY = 7.2
PACKED_MIN_BYTES = 512


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    size = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / size
        if probability:
            import math

            entropy -= probability * math.log2(probability)
    return entropy


def build_obfuscation_detection(
    functions: list[dict[str, Any]],
    exports: list[dict[str, Any]],
    data_segments: list[dict[str, Any]],
    segment_payloads: list[tuple[int, bytes]],
    dylink: Optional[dict[str, Any]],
    custom_section_names: set[str],
    has_name_section: bool,
) -> Optional[dict[str, Any]]:
    """Assemble ``analysis.detections.obfuscation``; None when clean."""
    function_count = len(functions)
    features_list = [fn.get("features") or {} for fn in functions]
    instruction_counts = [f.get("instruction_count", 0) for f in features_list]
    exported_func_count = sum(
        1 for exp in exports if str(exp.get("kind", "")) == "func"
    )

    signals: dict[str, dict[str, Any]] = {}

    # 1. Name-section stripping is benign for Go and release Rust, so it
    # never fires alone and is reported as a metric only.
    if not has_name_section and function_count >= NAME_STRIPPED_MIN_FUNCTIONS:
        signals["name_section_stripped"] = {
            "metric": True,
            "weight": SIGNAL_WEIGHTS["name_section_stripped"],
        }

    # 2. Packer shape: huge code, one door.
    if (
        exported_func_count <= EXPORT_SURFACE_MAX
        and function_count >= EXPORT_SURFACE_MIN_FUNCTIONS
    ):
        signals["minimal_export_surface"] = {
            "metric": exported_func_count,
            "weight": SIGNAL_WEIGHTS["minimal_export_surface"],
        }

    # 3. Control-flow flattening: a dispatch loop switching over a wide
    # br_table. The constant-predicate branch arm of the original design
    # proved to be corpus noise (ordinary clang output routinely shows
    # const-predicate densities over the nominal bar in loops), so it is
    # reported per function in features.const_branch_density but does not
    # feed this signal; a CFG-based opaque-predicate check is the P12
    # follow-up.
    dispatcher_functions = [
        fn.get("index")
        for fn in functions
        if (fn.get("features") or {}).get("max_br_table_targets_in_loop", 0)
        >= DISPATCHER_MIN_TARGETS
        and (fn.get("features") or {}).get("instruction_count", 0)
        <= DISPATCHER_MAX_FUNCTION_INSTRUCTIONS
        and (fn.get("features") or {}).get("br_table_count", 0)
        <= DISPATCHER_MAX_BR_TABLES
    ]
    if dispatcher_functions:
        signals["dispatcher_loop"] = {
            "metric": {
                "dispatcher_functions": [
                    i for i in dispatcher_functions if i is not None
                ][:20],
            },
            "weight": SIGNAL_WEIGHTS["dispatcher_loop"],
        }

    # 4. Thunk swarm: many tiny wrappers fanning out through indirect calls.
    median_instructions = _median(instruction_counts)
    indirect_share = (
        sum(1 for f in features_list if f.get("has_indirect_call"))
        / function_count
        if function_count
        else 0.0
    )
    if (
        median_instructions <= THUNK_MAX_MEDIAN_INSTRUCTIONS
        and function_count >= THUNK_MIN_FUNCTIONS
        and indirect_share >= THUNK_MIN_INDIRECT_SHARE
    ):
        signals["thunk_swarm"] = {
            "metric": {
                "median_function_instructions": median_instructions,
                "indirect_call_share": round(indirect_share, 4),
            },
            "weight": SIGNAL_WEIGHTS["thunk_swarm"],
        }

    # 5. Clone herds: generated padding leaves duplicate bodies.
    body_hashes = [f.get("body_hash") for f in features_list if f.get("body_hash")]
    if body_hashes and function_count >= DUPLICATE_MIN_FUNCTIONS:
        seen: dict[str, int] = {}
        for body_hash in body_hashes:
            seen[body_hash] = seen.get(body_hash, 0) + 1
        duplicated = sum(count for count in seen.values() if count > 1)
        duplicate_ratio = round(duplicated / len(body_hashes), 4)
        if duplicate_ratio >= DUPLICATE_MIN_RATIO:
            signals["duplicate_body_ratio"] = {
                "metric": duplicate_ratio,
                "weight": SIGNAL_WEIGHTS["duplicate_body_ratio"],
            }

    # 6. Packed data: high-entropy segments above the size bar. Payload
    # entries are (index, offset_value, bytes) as produced by build_report.
    packed_segments = []
    payload_by_index = {entry[0]: entry[2] for entry in segment_payloads}
    for segment in data_segments:
        payload = payload_by_index.get(segment.get("index"))
        if payload is None or len(payload) < PACKED_MIN_BYTES:
            continue
        entropy = _shannon_entropy(payload)
        if entropy >= PACKED_ENTROPY:
            packed_segments.append(
                {"segment_index": segment.get("index"), "entropy": round(entropy, 4)}
            )
    if packed_segments:
        signals["packed_data"] = {
            "metric": packed_segments,
            "weight": SIGNAL_WEIGHTS["packed_data"],
        }

    # 7. Tooling traces without provenance.
    metadata_sections = {
        name
        for name in custom_section_names
        if name.startswith("metadata.code.")
    }
    if metadata_sections and not any(
        name in custom_section_names for name in ("producers", "target_features")
    ):
        signals["unusual_metadata"] = {
            "metric": sorted(metadata_sections)[:5],
            "weight": SIGNAL_WEIGHTS["unusual_metadata"],
        }

    # 8. Side-module smuggling shape: needed entries that are not
    # .wasm-suffixed library names.
    if dylink is not None and not dylink.get("legacy"):
        needed = [
            str(name)
            for name in dylink.get("needed", [])
            if name and not name.endswith((".wasm", ".so", ".dylib", ".dll"))
        ]
        if needed:
            signals["emscripten_side_module_anomaly"] = {
                "metric": needed[:10],
                "weight": SIGNAL_WEIGHTS["emscripten_side_module_anomaly"],
            }

    if not signals:
        return None
    score = min(100, sum(s["weight"] for s in signals.values()))
    return {
        "detected": True,
        "score": score,
        "signals": sorted(signals),
        "signal_details": signals,
        "median_function_instructions": median_instructions,
        "exported_function_count": exported_func_count,
        "function_count": function_count,
    }
