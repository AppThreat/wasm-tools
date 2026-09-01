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
}

# Final-spec GC text (rec groups, struct/array instructions, abstract heap
# types such as anyref) is beyond WABT's wat2wasm text front-end, even with
# --enable-gc. These fixtures build with the Rust wasm-tools instead:
#   brew install wasm-tools   (or cargo install wasm-tools)
_WASM_TOOLS_FIXTURES = {
    "gc_rec_group.wat",
    "gc_ops.wat",
}


def _build_command(wat: str, wasm: str) -> list:
    name = os.path.basename(wat)
    if name in _WASM_TOOLS_FIXTURES:
        return ["wasm-tools", "parse", wat, "-o", wasm]
    return ["wat2wasm"] + _EXTRA_FLAGS.get(name, []) + [wat, "-o", wasm]


def build_fixtures():
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
