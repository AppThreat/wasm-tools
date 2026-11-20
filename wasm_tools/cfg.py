"""Stack-aware basic-block CFG recovery per function.

Wasm's structured control flow makes block recovery tractable: boundaries
fall out of the instruction stream plus label depths, with ``br_table`` the
only multi-target wildcard. This module reconstructs a per-function CFG from
the already-decoded instruction list: leader offsets, block extents,
successor edges from branch resolution, loop headers, and unreachable
blocks.

Correctness envelope: the CFG is exact for spec-conforming code with intact
immediates. For functions whose decode was incomplete (``decode_incomplete``)
or whose branch immediates were dropped by an older collection, the CFG is
best-effort and carries ``incomplete: true``. The recovery is structural
only: the parser deliberately does not validate, so structurally dead code
after unconditional exits is emitted, marked unreachable, never dropped.

Report contract (stable within a major version): block ids are dense and
ordered by start offset; successors are sorted; every instruction belongs to
exactly one block.
"""

from __future__ import annotations

from typing import Any, Optional

_BLOCK_OPENERS = {"block", "loop", "if", "try_table", "try"}
_TERMINAL_EXITS = {
    "return",
    "unreachable",
    "return_call",
    "return_call_indirect",
    "return_call_ref",
}
_MAX_SUCCESSOR_FANOUT = 64


def _instruction_offset(ins: dict[str, Any], fallback: int) -> int:
    offset = ins.get("offset")
    return int(offset) if isinstance(offset, int) else fallback


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

    incomplete = any(
        bool(ins.get("decode_incomplete")) for ins in instructions
    )

    # Pass 1: walk with the block stack, snapshot branch targets, and collect
    # structural boundary offsets.
    stack: list[tuple[str, int]] = []
    openers: set[int] = set()
    else_offsets: set[int] = set()
    end_offsets: set[int] = set()
    branch_targets: dict[int, set[int]] = {}
    offsets: list[int] = []
    for index, ins in enumerate(instructions):
        offset = _instruction_offset(ins, index)
        offsets.append(offset)
        op = str(ins.get("opcode", ""))
        if op in _BLOCK_OPENERS:
            openers.add(offset)
            stack.append((op, offset))
        elif op == "end":
            # The final end (empty stack) closes the function body, not a
            # construct: it is not a leader.
            if stack:
                stack.pop()
                end_offsets.add(offset)
        elif op == "else":
            else_offsets.add(offset)
        elif op in {"br", "br_if", "br_table"}:
            immediates = ins.get("immediates") or []
            targets: set[int] = set()
            for depth in immediates:
                if isinstance(depth, int) and 0 <= depth < len(stack):
                    targets.add(stack[-1 - depth][1])
            branch_targets[index] = targets

    # Leaders: function start, every opener, the instruction after an opener
    # or an else, after every construct-closing end, after every
    # unconditional exit, and every branch target.
    leaders: set[int] = {offsets[0]}
    for index, ins in enumerate(instructions):
        op = str(ins.get("opcode", ""))
        offset = offsets[index]
        if op in _BLOCK_OPENERS:
            openers.add(offset)
            leaders.add(offset)
            if index + 1 < len(instructions):
                leaders.add(offsets[index + 1])
        elif op == "end" and offset in end_offsets:
            leaders.add(offset)
            if index + 1 < len(instructions):
                leaders.add(offsets[index + 1])
        elif op == "else":
            leaders.add(offset)
            if index + 1 < len(instructions):
                leaders.add(offsets[index + 1])
        elif op in _TERMINAL_EXITS or op == "br":
            if index + 1 < len(instructions):
                leaders.add(offsets[index + 1])
        targets = branch_targets.get(index)
        if targets:
            leaders.update(targets)

    ordered_leaders = sorted(leaders)
    block_of_offset: dict[int, int] = {
        offset: block_id for block_id, offset in enumerate(ordered_leaders)
    }

    def block_id_for(offset: int) -> Optional[int]:
        # The block containing ``offset`` is the last leader <= offset.
        candidate = None
        for block_id, leader in enumerate(ordered_leaders):
            if leader <= offset:
                candidate = block_id
            else:
                break
        return candidate

    # Block extents and successors.
    blocks: list[dict[str, Any]] = []
    for block_id, start in enumerate(ordered_leaders):
        end = (
            ordered_leaders[block_id + 1]
            if block_id + 1 < len(ordered_leaders)
            else offsets[-1] + 1
        )
        members = [
            index
            for index, offset in enumerate(offsets)
            if start <= offset < end
        ]
        opener_op = None
        if start in openers:
            for index in members:
                if offsets[index] == start:
                    opener_op = str(instructions[index].get("opcode", ""))
                    break
        blocks.append(
            {
                "id": block_id,
                "start": start,
                "end": end,
                "instructions": len(members),
                "labels": [opener_op] if opener_op else [],
                "successors": [],
            }
        )

    successor_count = 0
    for block_id, block in enumerate(blocks):
        members = [
            index
            for index, offset in enumerate(offsets)
            if block["start"] <= offset < block["end"]
        ]
        if not members:
            continue
        last_index = members[-1]
        op = str(instructions[last_index].get("opcode", ""))
        successors: set[int] = set()
        if op == "br":
            successors = {
                block_id_for(target)
                for target in branch_targets.get(last_index, set())
            }
        elif op == "br_table":
            successors = {
                block_id_for(target)
                for target in branch_targets.get(last_index, set())
            }
        elif op == "br_if":
            successors = {
                block_id_for(target)
                for target in branch_targets.get(last_index, set())
            }
            if last_index + 1 < len(instructions):
                successors.add(block_id_for(offsets[last_index + 1]))
        elif op in _TERMINAL_EXITS:
            successors = set()
        else:
            # Fallthrough, including ends and elses.
            if block_id + 1 < len(blocks):
                successors = {block_id + 1}
        successors.discard(None)
        successors = {
            int(target) for target in successors if target is not None
        }
        if len(successors) > _MAX_SUCCESSOR_FANOUT:
            successors = set(sorted(successors)[:_MAX_SUCCESSOR_FANOUT])
            block["successors_truncated"] = True
        block["successors"] = sorted(successors)
        successor_count += len(block["successors"])

    # Loop headers: loop-opener blocks that are branch targets from within
    # (a back edge in offset order).
    loop_headers: set[int] = set()
    loop_opener_blocks = {
        block["id"] for block in blocks if block.get("labels") == ["loop"]
    }
    for index, ins in enumerate(instructions):
        targets = branch_targets.get(index)
        if not targets:
            continue
        for target in targets:
            target_block = block_id_for(target)
            if (
                target_block in loop_opener_blocks
                and offsets[index] >= target
            ):
                loop_headers.add(int(target_block))

    # Unreachable blocks: not reachable from block 0 over successors.
    reachable: set[int] = set()
    frontier = [0] if blocks else []
    while frontier:
        current = frontier.pop()
        if current in reachable:
            continue
        reachable.add(current)
        frontier.extend(blocks[current]["successors"])
    unreachable = sorted(
        block["id"] for block in blocks if block["id"] not in reachable
    )

    return {
        "block_count": len(blocks),
        "edge_count": successor_count,
        "blocks": blocks,
        "loop_headers": sorted(loop_headers),
        "unreachable_blocks": unreachable,
        "incomplete": incomplete,
    }
