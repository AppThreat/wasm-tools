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
