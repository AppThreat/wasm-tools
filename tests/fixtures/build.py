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

    The half-precision proposal (WebAssembly/half-precision, opcode table in
    proposals/half-precision/Overview.md) assigns 0x13d-0x144 to f16x8.add
    through f16x8.pmax and 0x145-0x14f to the conversion and FMA forms, all
    under the 0xFD prefix with no immediates. Neither wat2wasm nor the Rust
    wasm-tools text front-end accepts f16x8 mnemonics yet, so the fixture is
    assembled here rather than from text. The module is one function taking
    three v128 params and returning one v128, exercising every new opcode.
    """
    opcodes = [
        0x13D,  # f16x8.add
        0x13E,  # f16x8.sub
        0x13F,  # f16x8.mul
        0x140,  # f16x8.div
        0x141,  # f16x8.min
        0x142,  # f16x8.max
        0x143,  # f16x8.pmin
        0x144,  # f16x8.pmax
        0x145,  # i16x8.trunc_sat_f16x8_s
        0x146,  # i16x8.trunc_sat_f16x8_u
        0x147,  # f16x8.convert_i16x8_s
        0x148,  # f16x8.convert_i16x8_u
        0x149,  # f16x8.demote_f32x4_zero
        0x14A,  # f16x8.demote_f64x2_zero
        0x14B,  # f32x4.promote_low_f16x8
        0x14C,  # i16x8.trunc_f16x8_s
        0x14D,  # i16x8.trunc_f16x8_u
        0x14E,  # f16x8.madd
        0x14F,  # f16x8.nmadd
    ]
    body = bytearray()
    body.append(0x00)  # no locals
    for i, op in enumerate(opcodes):
        body.append(0x20)  # local.get
        body += _u32_leb(i % 3)
        body.append(0x20)  # local.get
        body += _u32_leb((i + 1) % 3)
        if op in (0x14E, 0x14F):  # f16x8.madd / f16x8.nmadd take three operands
            body.append(0x20)  # local.get
            body += _u32_leb((i + 2) % 3)
        body.append(0xFD)
        body += _u32_leb(op)
        body.append(0x1A)  # drop
    body.append(0x20)  # local.get
    body += _u32_leb(0)
    body.append(0x20)  # local.get
    body += _u32_leb(1)
    body.append(0xFD)
    body += _u32_leb(0x13D)  # f16x8.add becomes the return value
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
