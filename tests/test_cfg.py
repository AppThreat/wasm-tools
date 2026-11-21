"""Edge-level tests for the basic-block CFG builder.

Instruction lists use the collector's shape (``offset``, ``opcode``,
``immediates`` and, for ``try_table``, ``catches``). Offsets equal the
instruction index, so each expected edge reads as "the block starting at
instruction i goes to the blocks starting at instructions j, k". Every
expectation below was derived by hand from the spec's label rules: a branch
to a ``loop`` label lands on the loop opener, a branch to any other label
lands on the instruction after the construct's ``end``.
"""

import time

from wasm_tools.api import parse_wasm_bytes
from wasm_tools.cfg import build_function_cfg


def _ins(*ops):
    out = []
    for index, op in enumerate(ops):
        if isinstance(op, str):
            op = (op,)
        entry = {"offset": index, "opcode": op[0], "immediates": list(op[1:])}
        out.append(entry)
    return out


def _edges(cfg):
    """Map each block's start offset to its successors' start offsets."""
    starts = {block["id"]: block["start"] for block in cfg["blocks"]}
    return {
        block["start"]: [starts[s] for s in block["successors"]]
        for block in cfg["blocks"]
    }


def _unreachable_starts(cfg):
    starts = {block["id"]: block["start"] for block in cfg["blocks"]}
    return [starts[b] for b in cfg["unreachable_blocks"]]


def _check_coverage(cfg, count):
    assert sum(b["instructions"] for b in cfg["blocks"]) == count
    assert [b["id"] for b in cfg["blocks"]] == list(range(cfg["block_count"]))
    assert cfg["edge_count"] == sum(
        len(b["successors"]) for b in cfg["blocks"]
    )


def test_br_out_of_block_goes_past_end_not_to_loop():
    # 0 block / 1 loop / 2 br 1 / 3 end / 4 end / 5 i32.const 7 / 6 end
    # br 1 names the outer block: it lands on 5, past the block's end. It is
    # not a back edge, the loop is not a header, and 5 is reachable.
    ins = _ins(
        "block", "loop", ("br", 1), "end", "end", ("i32.const", 7), "end"
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[2] == [5]
    assert edges[0] == [1]
    assert edges[1] == [2]
    assert cfg["loop_headers"] == []
    # Only the two ends (3 and 4) are dead.
    assert _unreachable_starts(cfg) == [3, 4]


def test_br_if_to_loop_is_back_edge():
    # 0 loop / 1 local.get / 2 br_if 0 / 3 nop / 4 end / 5 end
    # The conditional back edge goes to the loop start (0); the fallthrough
    # continues in the loop body.
    ins = _ins("loop", ("local.get", 0), ("br_if", 0), "nop", "end", "end")
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[1] == [0, 3]
    assert edges[3] == [4]
    assert cfg["loop_headers"] == [0]
    assert cfg["unreachable_blocks"] == []


def test_br_if_mid_block_ends_the_block():
    # 0 block / 1 local.get / 2 br_if 0 / 3 nop / 4 end / 5 nop / 6 end
    # br_if ends the block {1,2}: taken edge to 5, fallthrough to 3.
    ins = _ins(
        "block", ("local.get", 0), ("br_if", 0), "nop", "end", "nop", "end"
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[1] == [3, 5]
    assert edges[3] == [4]
    assert edges[4] == [5]
    assert cfg["unreachable_blocks"] == []


def test_br_table_targets_and_default_no_fallthrough():
    # 0 block A / 1 block B / 2 loop C / 3 local.get / 4 br_table 0 1 2
    # 5 end(C) / 6 end(B) / 7 nop / 8 end(A) / 9 nop / 10 end
    # Depth 0 = loop C (start 2), 1 = block B (past end: 7), default 2 =
    # block A (past end: 9). No fallthrough to 5.
    ins = _ins(
        "block",
        "block",
        "loop",
        ("local.get", 0),
        ("br_table", 0, 1, 2),
        "end",
        "end",
        "nop",
        "end",
        "nop",
        "end",
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[3] == [2, 7, 9]
    assert cfg["loop_headers"] == [2]
    assert 5 in _unreachable_starts(cfg)


def test_if_else_arms():
    # 0 local.get / 1 if / 2 i32.const 1 / 3 else / 4 i32.const 2 / 5 end
    # 6 drop / 7 end
    # The if goes to the then arm (2) and the else arm (4); the then arm
    # reaches the else separator, which jumps past the end (6), never into
    # the else arm.
    ins = _ins(
        ("local.get", 0),
        ("if", -1),
        ("i32.const", 1),
        "else",
        ("i32.const", 2),
        "end",
        "drop",
        "end",
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[0] == [1]
    assert edges[1] == [2, 4]
    assert edges[2] == [3]
    assert edges[3] == [6]
    assert edges[4] == [5]
    assert edges[5] == [6]
    assert cfg["unreachable_blocks"] == []


def test_if_without_else_skips_to_past_end():
    # 0 local.get / 1 if / 2 nop / 3 end / 4 nop / 5 end
    ins = _ins(("local.get", 0), ("if", -64), "nop", "end", "nop", "end")
    cfg = build_function_cfg(ins)
    edges = _edges(cfg)
    assert edges[1] == [2, 4]
    assert edges[2] == [3]
    assert edges[3] == [4]


def test_nested_labels_depth_greater_than_zero():
    # 0 loop L / 1 block B / 2 if / 3 local.get / 4 br_if 2 / 5 br 1
    # 6 end(if) / 7 end(B) / 8 nop / 9 end(L) / 10 end
    # br_if 2 names loop L (start 0, a back edge); br 1 names block B
    # (past end: 8).
    ins = _ins(
        "loop",
        "block",
        ("if", -64),
        ("local.get", 0),
        ("br_if", 2),
        ("br", 1),
        "end",
        "end",
        "nop",
        "end",
        "end",
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[3] == [0, 5]
    assert edges[5] == [8]
    assert edges[2] == [3, 7]
    assert cfg["loop_headers"] == [0]


def test_branch_to_function_label_leaves_the_function():
    # 0 block / 1 local.get / 2 br_if 1 / 3 br 1 / 4 end / 5 nop / 6 end
    # Depth 1 names the function itself: br_if keeps only its fallthrough
    # (3) and br has no successor, so the rest is dead.
    ins = _ins(
        "block", ("local.get", 0), ("br_if", 1), ("br", 1), "end", "nop", "end"
    )
    cfg = build_function_cfg(ins)
    edges = _edges(cfg)
    assert edges[1] == [3]
    assert edges[3] == []
    assert _unreachable_starts(cfg) == [4, 5]


def test_return_and_unreachable_have_no_successors():
    # 0 local.get / 1 if / 2 return / 3 end / 4 unreachable / 5 nop / 6 end
    ins = _ins(
        ("local.get", 0),
        ("if", -64),
        "return",
        "end",
        "unreachable",
        "nop",
        "end",
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[2] == []
    assert edges[3] == [4]
    assert edges[4] == []
    assert _unreachable_starts(cfg) == [3, 5]


def test_throw_and_return_call_terminate():
    # 0 i32.const / 1 throw 0 / 2 nop / 3 return_call 0 / 4 end
    ins = _ins(
        ("i32.const", 1), ("throw", 0), "nop", ("return_call", 0), "end"
    )
    cfg = build_function_cfg(ins)
    edges = _edges(cfg)
    assert edges[0] == []
    assert edges[2] == []
    assert _unreachable_starts(cfg) == [2, 4]


def test_br_on_null_and_br_on_cast_are_conditional():
    # 0 block / 1 local.get / 2 br_on_null 0 / 3 br_on_cast 3 0 any i31
    # 4 drop / 5 end / 6 nop / 7 end
    ins = _ins(
        "block",
        ("local.get", 0),
        ("br_on_null", 0),
        ("br_on_cast", 3, 0, "any", "i31"),
        "drop",
        "end",
        "nop",
        "end",
    )
    cfg = build_function_cfg(ins)
    edges = _edges(cfg)
    assert edges[1] == [3, 6]
    assert edges[3] == [4, 6]


def test_try_table_catches_branch_to_their_labels():
    # 0 block $b / 1 block $c / 2 try_table (catch 0 $c=0) (catch_all $b=1)
    # 3 i32.const / 4 throw 0 / 5 end(try_table) / 6 br 1 / 7 end($c)
    # 8 nop / 9 end($b) / 10 nop / 11 end
    # Catch labels are resolved outside the try_table: depth 0 is $c (past
    # end: 8), depth 1 is $b (past end: 10).
    ins = _ins(
        "block",
        "block",
        ("try_table", -64, 0, 0, 0, 2, 1),
        ("i32.const", 1),
        ("throw", 0),
        "end",
        ("br", 1),
        "end",
        "nop",
        "end",
        "nop",
        "end",
    )
    ins[2]["catches"] = [[0, 0, 0], [2, 1]]
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[2] == [3, 8, 10]
    assert edges[3] == []
    assert 8 not in _unreachable_starts(cfg)


def test_legacy_try_catch_arms_and_delegate():
    # 0 try A / 1 try B / 2 call 0 / 3 delegate 0 / 4 nop / 5 catch 0
    # 6 drop / 7 catch_all / 8 nop / 9 end(A) / 10 end
    # A's opener goes to its body and both handler arms (6, 8). B is closed
    # by delegate 0, which names A: B's opener also reaches A's handlers.
    # The body and each arm end past A's end (10).
    ins = _ins(
        ("try", -64),
        ("try", -64),
        ("call", 0),
        ("delegate", 0),
        "nop",
        ("catch", 0),
        "drop",
        "catch_all",
        "nop",
        "end",
        "end",
    )
    cfg = build_function_cfg(ins)
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    assert edges[0] == [1, 6, 8]
    assert edges[1] == [2, 6, 8]
    assert edges[3] == [4]
    assert edges[5] == [10]
    assert edges[7] == [10]
    assert cfg["unreachable_blocks"] == []


def test_parsed_module_block_loop_br():
    # (func (result i32) block loop br 1 end end i32.const 7) as bytes.
    code = bytes.fromhex("024003400c010b0b41070b")
    body = b"\x00" + code
    module = (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1, 5, 1, 0x60, 0, 1, 0x7F])
        + bytes([3, 2, 1, 0])
        + bytes([10, len(body) + 2, 1, len(body)])
        + body
    )
    report = parse_wasm_bytes(module, "b.wasm", include_cfg=True)
    assert not report["errors"]
    fn = report["functions"][0]
    cfg = fn["cfg"]
    ops = [i["opcode"] for i in fn["instructions"]]
    assert ops == ["block", "loop", "br", "end", "end", "i32.const", "end"]
    offsets = [i["offset"] for i in fn["instructions"]]
    edges = _edges(cfg)
    assert edges[offsets[2]] == [offsets[5]]
    assert cfg["loop_headers"] == []
    starts = {b["id"]: b["start"] for b in cfg["blocks"]}
    assert offsets[5] not in [starts[b] for b in cfg["unreachable_blocks"]]


def _deep(n):
    return _ins(
        *(["block"] * n + ["nop", ("br", n - 1)] + ["end"] * n + ["end"])
    )


def test_deeply_nested_blocks_build_fast():
    # 8000 nested blocks with a branch out of all of them. The old builder
    # rescanned every instruction per block (about 12 s here).
    depth = 8000
    ins = _deep(depth)
    started = time.perf_counter()
    cfg = build_function_cfg(ins)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"CFG build took {elapsed:.2f}s"
    _check_coverage(cfg, len(ins))
    edges = _edges(cfg)
    # The block {nop, br} starts at index depth; the branch leaves the
    # outermost block and lands on the function's final end.
    assert edges[depth] == [2 * depth + 2]
