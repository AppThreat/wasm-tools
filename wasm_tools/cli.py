import argparse
import json
import sys

from .api import parse_wasm_bytes
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
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Write a minified JSON report to PATH",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a minified JSON report to stdout",
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="With --json and/or --json-out, emit only the analysis object",
    )

    args = parser.parse_args()

    if args.analysis_only and not (args.json or args.json_out):
        parser.error("--analysis-only requires --json and/or --json-out")

    options = ObjdumpOptions()
    options.filename = args.file

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    state = ObjdumpState()

    if args.json or args.json_out:
        report = parse_wasm_bytes(data, filename=args.file)
        output = report["analysis"] if args.analysis_only else report
        payload = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
        if args.json:
            print(payload)
        try:
            if args.json_out:
                with open(args.json_out, "w", encoding="utf-8") as out_file:
                    out_file.write(payload)
        except Exception as e:
            print(f"Error writing {args.json_out}: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Pass 1: Prepass – collect names, types, section metadata into state.
    options.mode = ObjdumpMode.PREPASS
    prepass_reader = BinaryReaderObjdumpPrepass(data, options, state)
    BinaryReader(data, prepass_reader).read_module()

    # Pass 2: Selected output mode.
    if args.headers:
        options.mode = ObjdumpMode.HEADERS
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
