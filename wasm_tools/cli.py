import argparse
import sys

from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from .parser import BinaryReader
from .visitor import (
    BinaryReaderObjdumpDetails,
    BinaryReaderObjdumpDisassemble,
    BinaryReaderObjdumpHeaders,
    BinaryReaderObjdumpPrepass,
)


def main() -> None:
    """Parse CLI args and run the two-pass wasm objdump pipeline."""
    parser = argparse.ArgumentParser(
        description="A WebAssembly objdump tool for inspecting .wasm binaries.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("file", help="WebAssembly binary file (.wasm)")
    parser.add_argument("--headers", action="store_true", help="Print section headers")
    parser.add_argument(
        "-x", "--details", action="store_true", help="Print section details"
    )
    parser.add_argument(
        "-d", "--disassemble", action="store_true", help="Disassemble function bodies"
    )

    args = parser.parse_args()

    options = ObjdumpOptions()
    options.filename = args.file

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    state = ObjdumpState()

    # Pass 1: Prepass – collect names, types, section metadata into state.
    options.mode = ObjdumpMode.PREPASS
    prepass_reader = BinaryReaderObjdumpPrepass(data, options, state)
    BinaryReader(data, prepass_reader).read_module()

    # Pass 2: Selected output mode.
    if args.headers:
        options.mode = ObjdumpMode.HEADERS
        print("\nSections:\n")
        print(f"  {'id':>3} {'name':<16} {'size':>6}  {'offset'}")
        print(f"  {'-'*3} {'-'*16} {'-'*6}  {'-'*8}")
        headers_reader = BinaryReaderObjdumpHeaders(data, options, state)
        BinaryReader(data, headers_reader).read_module()
    elif args.disassemble:
        options.mode = ObjdumpMode.DISASSEMBLE
        dis_reader = BinaryReaderObjdumpDisassemble(data, options, state)
        BinaryReader(data, dis_reader).read_module()
    elif args.details:
        options.mode = ObjdumpMode.DETAILS
        details_reader = BinaryReaderObjdumpDetails(data, options, state)
        BinaryReader(data, details_reader).read_module()
    else:
        # Default: show details
        options.mode = ObjdumpMode.DETAILS
        details_reader = BinaryReaderObjdumpDetails(data, options, state)
        BinaryReader(data, details_reader).read_module()


if __name__ == "__main__":
    main()
