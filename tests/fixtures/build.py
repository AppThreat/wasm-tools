# tests/fixtures/build.py
import glob
import os
import subprocess

# Per-fixture extra flags for wat2wasm.
_EXTRA_FLAGS: dict = {
    "simd_basic.wat": ["--enable-simd"],
    "exceptions_basic.wat": ["--enable-exceptions"],
    "threads_basic.wat": ["--enable-threads"],
    "gc_basic.wat": ["--enable-gc"],
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


def build_fixtures():
    wat_files = glob.glob(os.path.join(os.path.dirname(__file__), "*.wat"))
    for wat in sorted(wat_files):
        wasm = wat.replace(".wat", ".wasm")
        name = os.path.basename(wat)
        flags = _EXTRA_FLAGS.get(name, [])
        cmd = ["wat2wasm"] + flags + [wat, "-o", wasm]
        print(f"Compiling {name} -> {os.path.basename(wasm)}  flags={flags}")
        try:
            subprocess.run(cmd, check=True)
        except FileNotFoundError:
            print(
                "Error: 'wat2wasm' not found. Please install WABT (https://github.com/WebAssembly/wabt)."
            )
            return
        except subprocess.CalledProcessError as e:
            print(f"  WARNING: {name} failed ({e}), skipping.")


if __name__ == "__main__":
    build_fixtures()
