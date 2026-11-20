"""Stack-aware basic-block CFG recovery per function.

Wasm's structured control flow makes block recovery tractable: boundaries
fall out of the instruction stream plus label depths, with ``br_table`` the
only multi-target wildcard. This module reconstructs a per-function CFG from
the already-decoded instruction list: leader offsets, block extents,
successor edges from branch resolution, loop headers, and unreachable
blocks.

Leaders are the first instruction, every construct opener (``block``,
``loop``, ``if``, ``try_table``, legacy ``try``) and the instruction after
it, every construct separator or closer (``else``, ``catch``,
``catch_all``, a construct-closing ``end``, ``delegate``) and the
instruction after it, and the instruction after every branch or exit
(``br``, ``br_if``, ``br_table``, the ``br_on_*`` family, ``return``,
``unreachable``, ``return_call*``, ``throw``, ``throw_ref``, ``rethrow``).
Openers, separators and closers therefore always sit in single-instruction
blocks; an opener block carries ``labels: [<opener mnemonic>]``.

Branch semantics follow the spec's label rules. A label of depth ``N``
names the ``N``-th enclosing construct. A branch to a ``loop`` label goes
to the loop opener (the loop start); a branch to any other label
(``block``, ``if``, ``try_table``, ``try``) goes to the instruction after
the construct's matching ``end``. A branch to the function's own label
leaves the function and has no successor. Successors per block terminator:

* ``br``: the target only. ``br_table``: every listed target and the
  default, no fallthrough.
* ``br_if``, ``br_on_null``, ``br_on_non_null``, ``br_on_cast``,
  ``br_on_cast_fail``: the target plus the fallthrough.
* ``return``, ``unreachable``, ``return_call*``, ``throw``, ``throw_ref``,
  ``rethrow``: none.
* ``if`` opener: the then arm and the else arm (the instruction after
  ``else``), or the instruction after the matching ``end`` when there is
  no ``else``.
* ``else``, ``catch``, ``catch_all``: these close the preceding arm, so
  they go past the construct's ``end``; the next arm is entered from the
  opener, never by falling through.
* ``try_table`` opener: the body plus every catch clause's label target
  (catch labels are resolved outside the ``try_table`` itself).
* legacy ``try`` opener: the body plus the start of every ``catch`` and
  ``catch_all`` arm. When the ``try`` ends in ``delegate N``, the opener
  also gets edges to the handlers of the construct that label ``N`` names:
  the arms of a legacy ``try``, the catch targets of a ``try_table``, or,
  for a ``block``/``loop``/``if`` label, those of the nearest enclosing
  handler construct (none when the exception leaves the function).
* anything else (including ``end`` and ``delegate``): the fallthrough.

Exceptional flow is modeled at the handler construct: any instruction in
a protected body may throw, so the edges to the handlers leave from the
opener block rather than from individual throwing instructions.

Loop headers are ``loop`` opener blocks with an incoming edge from a block
at the same or a later offset (a back edge). Unreachable blocks are those
not reachable from block 0 over successor edges.

Correctness envelope: the CFG is exact for spec-conforming code with intact
immediates. For functions whose decode was incomplete (``decode_incomplete``)
or whose branch immediates were dropped by an older collection, the CFG is
best-effort and carries ``incomplete: true``; branches to constructs that
never close have no edge. The recovery is structural only: the parser
deliberately does not validate, so structurally dead code after
unconditional exits is emitted, marked unreachable, never dropped.

The builder runs in O(n log n) time for n instructions (one walk, one sort
of the leaders, no per-block rescans), so deeply nested or very long bodies
from untrusted input stay cheap.

Report contract (stable within a major version): block ids are dense and
ordered by start offset; successors are sorted; every instruction belongs to
exactly one block.
"""

from __future__ import annotations

from typing import Any

_BLOCK_OPENERS = {"block", "loop", "if", "try_table", "try"}
_ARM_SEPARATORS = {"else", "catch", "catch_all"}
_TERMINAL_EXITS = {
    "return",
    "unreachable",
    "return_call",
    "return_call_indirect",
    "return_call_ref",
    "throw",
    "throw_ref",
    "rethrow",
}
# Conditional branches and the position of their label immediate.
_CONDITIONAL_BRANCHES = {
    "br_if": 0,
    "br_on_null": 0,
    "br_on_non_null": 0,
    "br_on_cast": 1,
    "br_on_cast_fail": 1,
}
_MAX_SUCCESSOR_FANOUT = 64


def _instruction_offset(ins: dict[str, Any], fallback: int) -> int:
    offset = ins.get("offset")
    return int(offset) if isinstance(offset, int) else fallback


class _Construct:
    """One structured control construct seen during the walk."""

    __slots__ = (
        "arms",
        "catch_labels",
        "close",
        "delegate_to",
        "op",
        "opener",
        "parent",
    )

    def __init__(
        self, op: str, opener: int, parent: _Construct | None
    ) -> None:
        self.op = op
        self.opener = opener
        # Index of the matching end/delegate, None while open or if missing.
        self.close: int | None = None
        # Indices of else/catch/catch_all separators, in order.
        self.arms: list[int] = []
        # try_table catch clauses, resolved to the constructs they name
        # (None for the function label).
        self.catch_labels: list[_Construct | None] = []
        # Legacy try closed by delegate: the construct the label names
        # (None for the function label); a 1-tuple marks "delegate seen".
        self.delegate_to: tuple[_Construct | None] | None = None
        self.parent = parent


def _label(
    stack: list[_Construct], depth: Any
) -> tuple[bool, _Construct | None]:
    """Resolve a label depth against the stack.

    Returns ``(valid, construct)``; ``construct`` is None for the function
    label (depth == stack size). Invalid depths return ``(False, None)``.
    """
    if not isinstance(depth, int) or depth < 0 or depth > len(stack):
        return False, None
    if depth == len(stack):
        return True, None
    return True, stack[-1 - depth]


def build_function_cfg(instructions: list[dict[str, Any]]) -> dict[str, Any]:
    """Recover the basic-block CFG for one function's instruction list."""
    if not instructions:
        return {
            "block_count": 0,
            "edge_count": 0,
            "blocks": [],
            "loop_headers": [],
            "unreachable_blocks": [],
            "incomplete": False,
        }

    count = len(instructions)
    incomplete = any(
        bool(ins.get("decode_incomplete")) for ins in instructions
    )
    offsets = [
        _instruction_offset(ins, index)
        for index, ins in enumerate(instructions)
    ]
    ops = [str(ins.get("opcode", "")) for ins in instructions]

    # Pass 1: walk with the construct stack. Record each instruction's
    # construct (openers, separators, closers) and each branch's target
    # constructs; targets resolve to indices once every construct closes.
    stack: list[_Construct] = []
    construct_at: dict[int, _Construct] = {}
    branch_labels: dict[int, list[_Construct | None]] = {}
    leaders: set[int] = {0}

    def mark_after(index: int) -> None:
        if index + 1 < count:
            leaders.add(index + 1)

    for index, ins in enumerate(instructions):
        op = ops[index]
        if op in _BLOCK_OPENERS:
            construct = _Construct(op, index, stack[-1] if stack else None)
            if op == "try_table":
                for clause in ins.get("catches") or []:
                    if not isinstance(clause, (list, tuple)) or not clause:
                        continue
                    # Catch labels are resolved outside the try_table.
                    valid, target = _label(stack, clause[-1])
                    if valid:
                        construct.catch_labels.append(target)
            construct_at[index] = construct
            stack.append(construct)
            leaders.add(index)
            mark_after(index)
        elif op == "end" or op == "delegate":
            # The final end (empty stack) closes the function body, not a
            # construct: it is not a leader.
            if not stack:
                continue
            construct = stack.pop()
            construct.close = index
            construct_at[index] = construct
            if op == "delegate":
                immediates = ins.get("immediates") or []
                valid, target = _label(
                    stack, immediates[0] if immediates else None
                )
                construct.delegate_to = (target,) if valid else None
            leaders.add(index)
            mark_after(index)
        elif op in _ARM_SEPARATORS:
            if stack:
                stack[-1].arms.append(index)
                construct_at[index] = stack[-1]
            leaders.add(index)
            mark_after(index)
        elif op == "br" or op == "br_table" or op in _CONDITIONAL_BRANCHES:
            immediates = ins.get("immediates") or []
            if op in _CONDITIONAL_BRANCHES:
                position = _CONDITIONAL_BRANCHES[op]
                depths = immediates[position : position + 1]
            elif op == "br":
                depths = immediates[:1]
            else:
                depths = immediates
            targets: list[_Construct | None] = []
            for depth in depths:
                valid, target = _label(stack, depth)
                if valid:
                    targets.append(target)
            branch_labels[index] = targets
            mark_after(index)
        elif op in _TERMINAL_EXITS:
            mark_after(index)

    def label_target(construct: _Construct | None) -> int | None:
        # Where a branch to this construct's label lands.
        if construct is None:
            return None
        if construct.op == "loop":
            return construct.opener
        if construct.close is not None and construct.close + 1 < count:
            return construct.close + 1
        return None

    def handler_targets(construct: _Construct | None) -> list[int]:
        # Where an exception delegated to this construct's label goes.
        seen: set[int] = set()
        while construct is not None and id(construct) not in seen:
            seen.add(id(construct))
            if construct.op == "try_table":
                return [
                    target
                    for target in map(label_target, construct.catch_labels)
                    if target is not None
                ]
            if construct.op == "try":
                if construct.delegate_to is not None:
                    construct = construct.delegate_to[0]
                    continue
                return [
                    arm + 1
                    for arm in construct.arms
                    if ops[arm] != "else" and arm + 1 < count
                ]
            construct = construct.parent
        return []

    # Resolve successor indices per terminating instruction.
    successors_at: dict[int, set[int]] = {}
    for index, labels in branch_labels.items():
        targets = {t for t in map(label_target, labels) if t is not None}
        if (
            ops[index] != "br"
            and ops[index] != "br_table"
            and index + 1 < count
        ):
            targets.add(index + 1)
        successors_at[index] = targets
    for index, construct in construct_at.items():
        op = ops[index]
        if op in _BLOCK_OPENERS:
            targets = {index + 1} if index + 1 < count else set()
            if op == "if":
                if construct.arms:
                    if construct.arms[0] + 1 < count:
                        targets.add(construct.arms[0] + 1)
                else:
                    past_end = label_target(construct)
                    if past_end is not None:
                        targets.add(past_end)
            elif op == "try_table":
                targets.update(handler_targets(construct))
            elif op == "try":
                targets.update(
                    arm + 1 for arm in construct.arms if arm + 1 < count
                )
                if construct.delegate_to is not None:
                    targets.update(handler_targets(construct.delegate_to[0]))
            successors_at[index] = targets
        elif op in _ARM_SEPARATORS:
            # The arm before the separator is done: go past the end.
            close = construct.close
            successors_at[index] = (
                {close + 1}
                if close is not None and close + 1 < count
                else set()
            )
        # end/delegate fall through, handled with plain instructions below.
    for targets in successors_at.values():
        leaders.update(targets)

    # Blocks run leader to next leader in instruction order.
    ordered = sorted(leaders)
    block_of_index = {
        leader: block_id for block_id, leader in enumerate(ordered)
    }
    blocks: list[dict[str, Any]] = []
    successor_count = 0
    loop_opener_blocks: set[int] = set()
    full_successors: list[list[int]] = []
    for block_id, start_index in enumerate(ordered):
        next_index = (
            ordered[block_id + 1] if block_id + 1 < len(ordered) else count
        )
        last_index = next_index - 1
        start_op = ops[start_index]
        labels = [start_op] if start_op in _BLOCK_OPENERS else []
        if start_op == "loop":
            loop_opener_blocks.add(block_id)
        last_op = ops[last_index]
        if last_index in successors_at:
            successor_indices = successors_at[last_index]
        elif last_op in _TERMINAL_EXITS:
            successor_indices = set()
        else:
            successor_indices = {next_index} if next_index < count else set()
        successors = sorted(
            block_of_index[target] for target in successor_indices
        )
        full_successors.append(successors)
        block: dict[str, Any] = {
            "id": block_id,
            "start": offsets[start_index],
            "end": offsets[next_index]
            if next_index < count
            else offsets[-1] + 1,
            "instructions": next_index - start_index,
            "labels": labels,
            "successors": successors,
        }
        if len(successors) > _MAX_SUCCESSOR_FANOUT:
            block["successors"] = successors[:_MAX_SUCCESSOR_FANOUT]
            block["successors_truncated"] = True
        successor_count += len(block["successors"])
        blocks.append(block)

    # Loop headers: loop-opener blocks entered by a back edge. Use the full
    # successor sets so fan-out truncation never hides a header.
    loop_headers: set[int] = {
        target
        for block_id, successors in enumerate(full_successors)
        for target in successors
        if target in loop_opener_blocks and target <= block_id
    }

    # Unreachable blocks: not reachable from block 0 over successors (the
    # untruncated sets, so the fan-out cap never invents dead code).
    reachable: set[int] = set()
    frontier = [0]
    while frontier:
        current = frontier.pop()
        if current in reachable:
            continue
        reachable.add(current)
        frontier.extend(full_successors[current])
    unreachable = [
        block["id"] for block in blocks if block["id"] not in reachable
    ]

    return {
        "block_count": len(blocks),
        "edge_count": successor_count,
        "blocks": blocks,
        "loop_headers": sorted(loop_headers),
        "unreachable_blocks": unreachable,
        "incomplete": incomplete,
    }
