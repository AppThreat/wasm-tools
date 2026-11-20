# tests/fixtures/build.py
import glob
import os
import subprocess

# Per-fixture extra flags for wat2wasm.
_EXTRA_FLAGS: dict = {
    "simd_basic.wat": ["--enable-simd"],
    "exceptions_basic.wat": ["--enable-exceptions"],
    "threads_basic.wat": ["--enable-threads"],
    "call_refs.wat": ["--enable-function-references", "--enable-gc"],
    "js_deopt_surface.wat": ["--enable-function-references", "--enable-gc"],
    "load64.wat": ["--enable-memory64"],
    "memory64_shared.wat": ["--enable-memory64", "--enable-threads"],
    "table_init64.wat": ["--enable-memory64"],
    "float_memory64.wat": ["--enable-memory64"],
    "bulk64.wat": ["--enable-memory64"],
    "memory_trap64.wat": ["--enable-memory64"],
    "table_fill64.wat": ["--enable-memory64"],
    "table_set64.wat": ["--enable-memory64"],
    "table_size64.wat": ["--enable-memory64"],
    # The thunk-swarm obfuscation fixture needs a name section so the
    # name_section_stripped signal does not stack onto it.
    "thunk_swarm.wat": ["--debug-names"],
}

# Final-spec GC text (rec groups, struct/array instructions, abstract heap
# types such as anyref) is beyond WABT's wat2wasm text front-end, even with
# --enable-gc. These fixtures build with the Rust wasm-tools instead:
#   brew install wasm-tools   (or cargo install wasm-tools)
_WASM_TOOLS_FIXTURES = {
    "gc_rec_group.wat",
    "gc_ops.wat",
}


def _u32_leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _u32_leb(len(payload)) + payload


def build_f16x8_binary() -> bytes:
    """Emit f16x8_binary.wasm directly as bytes.

    The half-precision proposal (WebAssembly/half-precision,
    proposals/half-precision/Overview.md, "Binary format") assigns
    0xFC 0x30/0x31 to f32.load_f16/f32.store_f16 and, under the 0xFD
    prefix, 0x120-0x122 to the lane operations, 0x130-0x13c to the unary
    and comparison forms, 0x13d-0x144 to binary arithmetic, 0x145-0x14d to
    the conversions and 0x14e/0x14f to f16x8.madd/f16x8.nmadd. Neither
    wat2wasm nor the Rust wasm-tools (1.263) accepts f16 mnemonics or
    opcodes yet, so the fixture is assembled here and no external validator
    can check it. Each instruction is given the operand count and types the
    proposal's typing rules state (unary [v128] -> [v128], binary and
    comparison [v128 v128] -> [v128], FMA [v128 v128 v128] -> [v128]) so the
    function is well-typed by hand. The module is one function taking three
    v128 params and returning one v128, and it uses every f16 opcode once.
    """
    # (opcode, operand count): every v128-only f16x8 instruction.
    v128_ops = [
        (0x130, 1),  # f16x8.abs
        (0x131, 1),  # f16x8.neg
        (0x132, 1),  # f16x8.sqrt
        (0x133, 1),  # f16x8.ceil
        (0x134, 1),  # f16x8.floor
        (0x135, 1),  # f16x8.trunc
        (0x136, 1),  # f16x8.nearest
        (0x137, 2),  # f16x8.eq
        (0x138, 2),  # f16x8.ne
        (0x139, 2),  # f16x8.lt
        (0x13A, 2),  # f16x8.gt
        (0x13B, 2),  # f16x8.le
        (0x13C, 2),  # f16x8.ge
        (0x13D, 2),  # f16x8.add
        (0x13E, 2),  # f16x8.sub
        (0x13F, 2),  # f16x8.mul
        (0x140, 2),  # f16x8.div
        (0x141, 2),  # f16x8.min
        (0x142, 2),  # f16x8.max
        (0x143, 2),  # f16x8.pmin
        (0x144, 2),  # f16x8.pmax
        (0x145, 1),  # i16x8.trunc_sat_f16x8_s
        (0x146, 1),  # i16x8.trunc_sat_f16x8_u
        (0x147, 1),  # f16x8.convert_i16x8_s
        (0x148, 1),  # f16x8.convert_i16x8_u
        (0x149, 1),  # f16x8.demote_f32x4_zero
        (0x14A, 1),  # f16x8.demote_f64x2_zero
        (0x14B, 1),  # f32x4.promote_low_f16x8
        (0x14C, 1),  # i16x8.trunc_f16x8_s
        (0x14D, 1),  # i16x8.trunc_f16x8_u
        (0x14E, 3),  # f16x8.madd
        (0x14F, 3),  # f16x8.nmadd
    ]

    def local_get(index: int) -> bytes:
        return b"\x20" + _u32_leb(index)

    def simd(opcode: int) -> bytes:
        return b"\xFD" + _u32_leb(opcode)

    # memarg for a 2-byte access: alignment exponent 1, then the offset.
    def memarg_f16(offset: int) -> bytes:
        return _u32_leb(1) + _u32_leb(offset)

    i32_const_0 = b"\x41\x00"
    drop = b"\x1A"

    body = bytearray()
    body.append(0x00)  # no locals
    for opcode, arity in v128_ops:
        for operand in range(arity):
            body += local_get(operand)
        body += simd(opcode) + drop
    # f32.load_f16 then f16x8.splat: [i32] -> [f32] -> [v128]
    body += i32_const_0 + b"\xFC" + _u32_leb(0x30) + memarg_f16(0)
    body += simd(0x120) + drop
    # f16x8.extract_lane 7 feeding f32.store_f16: [i32 f32] -> []
    body += i32_const_0 + local_get(0) + simd(0x121) + b"\x07"
    body += b"\xFC" + _u32_leb(0x31) + memarg_f16(2)
    # f16x8.replace_lane 3: [v128 f32] -> [v128]
    body += local_get(0) + i32_const_0 + b"\xFC" + _u32_leb(0x30) + memarg_f16(4)
    body += simd(0x122) + b"\x03" + drop
    # f16x8.add of the first two params is the return value.
    body += local_get(0) + local_get(1) + simd(0x13D)
    body.append(0x0B)  # end

    types = _section(
        1,
        _u32_leb(1) + b"\x60" + _u32_leb(3) + b"\x7b\x7b\x7b" + _u32_leb(1) + b"\x7b",
    )
    functions = _section(3, _u32_leb(1) + _u32_leb(0))
    memories = _section(5, _u32_leb(1) + b"\x00\x01")
    exports = _section(
        7, _u32_leb(1) + _u32_leb(4) + b"pick" + b"\x00" + _u32_leb(0)
    )
    code = _section(10, _u32_leb(1) + _u32_leb(len(body)) + bytes(body))
    return b"\x00asm\x01\x00\x00\x00" + types + functions + memories + exports + code


_MANUAL_FIXTURES = {
    "f16x8_binary.wasm": build_f16x8_binary,
}


def _build_command(wat: str, wasm: str) -> list:
    name = os.path.basename(wat)
    if name in _WASM_TOOLS_FIXTURES:
        return ["wasm-tools", "parse", wat, "-o", wasm]
    return ["wat2wasm"] + _EXTRA_FLAGS.get(name, []) + [wat, "-o", wasm]


def build_fixtures():
    # F16x8 text is not accepted by either assembler, so that fixture is
    # assembled from bytes directly (see build_f16x8_binary).
    for name, builder in sorted(_MANUAL_FIXTURES.items()):
        wasm = os.path.join(os.path.dirname(__file__), name)
        print(f"Assembling {name} (byte-level builder)")
        with open(wasm, "wb") as out:
            out.write(builder())
    wat_files = glob.glob(os.path.join(os.path.dirname(__file__), "*.wat"))
    for wat in sorted(wat_files):
        wasm = wat.replace(".wat", ".wasm")
        name = os.path.basename(wat)
        cmd = _build_command(wat, wasm)
        print(f"Compiling {name} -> {os.path.basename(wasm)}  ({cmd[0]})")
        try:
            subprocess.run(cmd, check=True)
        except FileNotFoundError:
            if cmd[0] == "wasm-tools":
                print(
                    "Error: 'wasm-tools' not found. Install the Rust wasm-tools"
                    " (brew install wasm-tools) to rebuild GC fixtures."
                )
            else:
                print(
                    "Error: 'wat2wasm' not found. Please install WABT"
                    " (https://github.com/WebAssembly/wabt)."
                )
            return
        except subprocess.CalledProcessError as e:
            print(f"  WARNING: {name} failed ({e}), skipping.")


if __name__ == "__main__":
    build_fixtures()
