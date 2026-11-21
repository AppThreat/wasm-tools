"""Obfuscation and packing signal detection.

Wasm obfuscation is documented in the literature and in incident reporting:
general-purpose obfuscators (WASMixer, ESORICS 2024), memory bitwise
obfuscation that defeats string scanning (WeBMO, COMPSAC 2024), multi-level
wat/binary/LLVM pipelines evading miner detectors (Cryptic Bytes, arXiv
2403.15197), Android malware shipping wasm payloads to defeat static
analysis (AndroWasm, arXiv 2602.18082), and eCriminals hiding logic in wasm
(CrowdStrike, December 2024).

The finding rests on one structural signature, control-flow flattening
(see _flattening_profile), because the other shapes are common in ordinary
compiler output: release Rust and Go strip names, WASI commands export only
_start, compressed assets are high-entropy, generics leave clone herds, and
vtable-heavy C++ looks like a thunk swarm. Those signals are still measured
and reported in the detection block, and they add to the score once a
flattened function is present, but without one the score is held below the
finding threshold. Severity is high only when flattening covers several
functions, the pattern a flattening obfuscator leaves when it runs over a
whole module. A flattener that dispatches through memory instead of a
local, or that relies on a zero-initialised state local, evades the
signature; the per-function br_table and loop metrics stay in features for
analysts.
"""

from __future__ import annotations

from typing import Any, Optional

# Signal weights for the composite obfuscation score (0-100). The finding
# fires at >= 30 with severity medium, and only when dispatcher_loop (a
# flattened function) is present; severity high requires both strong
# signals, that is flattening in FLATTEN_WIDESPREAD_MIN_FUNCTIONS or more
# functions.
SIGNAL_WEIGHTS = {
    "dispatcher_loop": 30,
    "flattening_widespread": 20,
    "packed_data": 20,
    "duplicate_body_ratio": 15,
    "minimal_export_surface": 10,
    "thunk_swarm": 10,
    "name_section_stripped": 5,
    "unusual_metadata": 5,
    "emscripten_side_module_anomaly": 10,
}

STRONG_SIGNALS = {"dispatcher_loop", "flattening_widespread"}
FINDING_SCORE_THRESHOLD = 30
# Signals that can carry the score to the finding threshold. Everything
# else corroborates only.
FINDING_REQUIRED_SIGNALS = {"dispatcher_loop"}

# Thresholds, all named so retuning is a one-diff reviewable change.
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

# Control-flow flattening signature, applied per loop and the state local
# it dispatches on (see _flattening_profile). A profile matches only when
# the loop dispatches to at least FLATTEN_MIN_CASES distinct case blocks,
# constant writes to the state local reach at least that many of them and
# FLATTEN_MIN_CASE_COVERAGE of all cases, FLATTEN_MIN_RETURN_SHARE of those
# writes are followed by a straight branch back to the loop, nearly all
# writes inside the loop are constants, the state starts at a constant
# case value before the loop, and the loop spans most of the function.
FLATTEN_MIN_CASES = 6
FLATTEN_MIN_CASE_COVERAGE = 0.75
FLATTEN_MIN_RETURN_SHARE = 0.9
FLATTEN_MIN_CONSTANT_WRITE_SHARE = 0.9
FLATTEN_MIN_LOOP_SHARE = 0.7
# How far past a state write to look for the branch that ends its case.
FLATTEN_CASE_SCAN = 64
FLATTEN_WIDESPREAD_MIN_FUNCTIONS = 3
FLATTEN_REPORTED_FUNCTIONS = 20


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


_BLOCK_OPENERS = frozenset({"block", "loop", "if", "try", "try_table"})
_STATE_SETTERS = frozenset({"local.set", "local.tee"})
_COMPARE_OPS = frozenset({"i32.eq", "i32.ne"})
# Instructions that end a straight-line run: the first one after a state
# write decides whether that case block returns to the dispatcher.
_CONTROL_OPS = frozenset(
    {
        "br",
        "br_if",
        "br_table",
        "return",
        "return_call",
        "return_call_indirect",
        "return_call_ref",
        "unreachable",
        "throw",
        "throw_ref",
        "rethrow",
        "end",
        "else",
        "delegate",
    }
    | _BLOCK_OPENERS
)


def _first_imm(ins: dict[str, Any]) -> Optional[int]:
    imms = ins.get("immediates") or []
    if imms and isinstance(imms[0], int) and not isinstance(imms[0], bool):
        return imms[0]
    return None


def _written_constants(
    ops: list[str], instructions: list[dict[str, Any]], idx: int
) -> Optional[list[int]]:
    """Constants a local.set/tee at ``idx`` writes, or None when computed.

    Accepts ``i32.const K`` directly before the write and the two-way form
    a flattener leaves for a conditional successor:
    ``i32.const A; i32.const B; <short condition>; select``.
    """
    if idx < 1:
        return None
    if ops[idx - 1] == "i32.const":
        value = _first_imm(instructions[idx - 1])
        return [value] if value is not None else None
    if ops[idx - 1] == "select":
        for back in range(idx - 2, max(0, idx - 8), -1):
            if ops[back] == "i32.const" and back >= 1 and ops[back - 1] == "i32.const":
                first = _first_imm(instructions[back - 1])
                second = _first_imm(instructions[back])
                if first is None or second is None:
                    return None
                return [first, second]
    return None


def _flattening_profile(
    instructions: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Measure the strongest flattening-dispatcher candidate in a function.

    Control-flow flattening rewrites a function into one loop whose head
    dispatches on a state local; the state starts at a constant, every
    case block is a straight-line run that ends by writing the next
    state's constant and branching back to the loop. Two dispatch forms
    are recognised: a ``br_table`` on the state local (dense case numbers)
    and a tree of ``i32.eq``/``i32.ne`` tests of the state local against
    constants (the sparse random case values of OLLVM-style flattening).
    The returned profile carries the measurements the FLATTEN_* thresholds
    apply to; None means no loop dispatches on a local.
    """
    count = len(instructions)
    if count == 0:
        return None
    ops = [str(ins.get("opcode", "")) for ins in instructions]

    stack: list[tuple[str, int]] = []
    loop_end: dict[int, int] = {}
    branch_target: dict[int, int] = {}
    br_tables: list[tuple[int, int, list[int]]] = []  # (idx, loop, targets)
    writes: dict[int, list[tuple[int, Optional[list[int]]]]] = {}
    compares: dict[tuple[int, int], set[int]] = {}  # (loop, local) -> values

    def innermost_loop() -> int:
        for kind, start in reversed(stack):
            if kind == "loop":
                return start
        return -1

    def resolve(depth: Optional[int]) -> int:
        if depth is not None and 0 <= depth < len(stack):
            return stack[-1 - depth][1]
        return -1

    for idx, op in enumerate(ops):
        if op in _BLOCK_OPENERS:
            stack.append((op, idx))
        elif op in ("end", "delegate"):
            if stack:
                kind, start = stack.pop()
                if kind == "loop":
                    loop_end[start] = idx
        elif op in ("br", "br_if"):
            branch_target[idx] = resolve(_first_imm(instructions[idx]))
        elif op == "br_table":
            loop = innermost_loop()
            raw = instructions[idx].get("immediates") or []
            resolved = [resolve(t) if isinstance(t, int) else -1 for t in raw]
            if loop >= 0 and resolved:
                br_tables.append((idx, loop, resolved))
        elif op in _STATE_SETTERS:
            local = _first_imm(instructions[idx])
            if local is not None:
                writes.setdefault(local, []).append(
                    (idx, _written_constants(ops, instructions, idx))
                )
        elif op in _COMPARE_OPS and idx >= 2:
            pair = (ops[idx - 2], ops[idx - 1])
            if pair == ("local.get", "i32.const"):
                local = _first_imm(instructions[idx - 2])
                value = _first_imm(instructions[idx - 1])
            elif pair == ("i32.const", "local.get"):
                local = _first_imm(instructions[idx - 1])
                value = _first_imm(instructions[idx - 2])
            else:
                continue
            loop = innermost_loop()
            if loop >= 0 and local is not None and value is not None:
                compares.setdefault((loop, local), set()).add(value)

    def returns_to(idx: int, loop: int, limit: int) -> bool:
        for j in range(idx + 1, min(limit, idx + FLATTEN_CASE_SCAN) + 1):
            if ops[j] in _CONTROL_OPS:
                return ops[j] == "br" and branch_target.get(j) == loop
        return False

    def measure(
        loop: int, local: int, case_of: dict[int, int], cases: int, form: str
    ) -> Optional[dict[str, Any]]:
        end = loop_end.get(loop, count - 1)
        local_writes = writes.get(local, [])
        inside = [(i, vals) for i, vals in local_writes if loop < i < end]
        if not inside:
            return None
        before = [(i, vals) for i, vals in local_writes if i < loop]
        initial = before[-1][1] if before else None
        initial_is_case = bool(initial) and all(v in case_of for v in initial)
        constant_writes = [(i, vals) for i, vals in inside if vals]
        covered = {
            case_of[v] for _, vals in constant_writes for v in vals if v in case_of
        }
        returning = sum(
            1 for i, _ in constant_writes if returns_to(i, loop, end)
        )
        return {
            "form": form,
            "loop_offset": instructions[loop].get("offset"),
            "state_local": local,
            "cases": cases,
            "covered_cases": len(covered),
            "case_coverage": round(len(covered) / cases, 4) if cases else 0.0,
            "constant_write_share": round(len(constant_writes) / len(inside), 4),
            "return_share": round(returning / len(constant_writes), 4)
            if constant_writes
            else 0.0,
            "constant_initial_state": initial_is_case,
            "loop_share": round((end - loop + 1) / count, 4),
        }

    profiles: list[dict[str, Any]] = []
    for idx, loop, resolved in br_tables:
        base = 0
        if idx >= 1 and ops[idx - 1] == "local.get":
            local = _first_imm(instructions[idx - 1])
        elif (
            idx >= 3
            and ops[idx - 3] == "local.get"
            and ops[idx - 2] == "i32.const"
            and ops[idx - 1] in ("i32.sub", "i32.add")
        ):
            local = _first_imm(instructions[idx - 3])
            delta = _first_imm(instructions[idx - 2]) or 0
            base = delta if ops[idx - 1] == "i32.sub" else -delta
        else:
            continue
        if local is None:
            continue
        # State value v selects entry v - base; entries that leave through
        # the default slot or straight back to the loop are not cases.
        case_of = {
            base + pos: target
            for pos, target in enumerate(resolved[:-1])
            if target >= 0 and target != loop
        }
        cases = len(set(case_of.values()))
        if cases < FLATTEN_MIN_CASES:
            continue
        profile = measure(loop, local, case_of, cases, "br_table")
        if profile:
            profiles.append(profile)

    for (loop, local), values in compares.items():
        if len(values) < FLATTEN_MIN_CASES:
            continue
        profile = measure(loop, local, {v: v for v in values}, len(values), "compare_tree")
        if profile:
            profiles.append(profile)

    if not profiles:
        return None
    return max(
        profiles,
        key=lambda p: (_profile_matches(p), p["covered_cases"], p["return_share"]),
    )


def _profile_matches(profile: dict[str, Any]) -> bool:
    """Apply the flattening thresholds to one measured profile."""
    return (
        profile["covered_cases"] >= FLATTEN_MIN_CASES
        and profile["case_coverage"] >= FLATTEN_MIN_CASE_COVERAGE
        and profile["return_share"] >= FLATTEN_MIN_RETURN_SHARE
        and profile["constant_write_share"] >= FLATTEN_MIN_CONSTANT_WRITE_SHARE
        and profile["constant_initial_state"]
        and profile["loop_share"] >= FLATTEN_MIN_LOOP_SHARE
    )


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

    # 3. Control-flow flattening: a loop dispatching on a state local that
    # starts at a constant, where nearly every case writes the next state's
    # constant and branches straight back (see _flattening_profile). Only
    # functions with a loop are measured.
    flattened: list[dict[str, Any]] = []
    for fn in functions:
        if not (fn.get("features") or {}).get("has_loop"):
            continue
        profile = _flattening_profile(fn.get("instructions") or [])
        if profile is not None and _profile_matches(profile):
            flattened.append({"function_index": fn.get("index"), **profile})
    if flattened:
        signals["dispatcher_loop"] = {
            "metric": {
                "dispatcher_functions": [
                    entry["function_index"]
                    for entry in flattened
                    if entry["function_index"] is not None
                ][:FLATTEN_REPORTED_FUNCTIONS],
                "flattened_function_count": len(flattened),
                "profiles": flattened[:FLATTEN_REPORTED_FUNCTIONS],
            },
            "weight": SIGNAL_WEIGHTS["dispatcher_loop"],
        }
    if len(flattened) >= FLATTEN_WIDESPREAD_MIN_FUNCTIONS:
        signals["flattening_widespread"] = {
            "metric": len(flattened),
            "weight": SIGNAL_WEIGHTS["flattening_widespread"],
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
    # Without a flattened function the remaining signals describe ordinary
    # compiler output as often as obfuscation, so they never reach the bar.
    score_capped = False
    if not FINDING_REQUIRED_SIGNALS & set(signals) and score >= FINDING_SCORE_THRESHOLD:
        score = FINDING_SCORE_THRESHOLD - 1
        score_capped = True
    return {
        "detected": True,
        "score": score,
        "score_capped": score_capped,
        "signals": sorted(signals),
        "signal_details": signals,
        "median_function_instructions": median_instructions,
        "exported_function_count": exported_func_count,
        "function_count": function_count,
    }
