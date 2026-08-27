import argparse
import json
import sys

from .api import parse_wasm_bytes
from .component import detect_component
from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState
from .parser import BinaryReader
from .visitor import (
    BinaryReaderObjdumpDetails,
    BinaryReaderObjdumpDisassemble,
    BinaryReaderObjdumpHeaders,
    BinaryReaderObjdumpPrepass,
)

_MAX_CALL_TREE_DEPTH = 4


def _print_strings_from_report(report: dict) -> None:
    """Print extracted strings with segment and linear-memory provenance.

    Length filtering already happened during extraction (strings_min_len is
    threaded to it), so every entry here is printable as-is.
    """
    print("\nStrings:\n")
    for entry in report.get("strings", []):
        mem = entry.get("memory_offset")
        mem_str = f"0x{mem:08x}" if isinstance(mem, int) else "-"
        core_mod = entry.get("core_module")
        core_str = f" core[{core_mod}]" if isinstance(core_mod, int) else ""
        value = str(entry.get("value", ""))
        print(
            f" segment[{entry.get('segment_index')}]{core_str} "
            f"mem[{mem_str}] +0x{int(entry.get('byte_offset', 0)):x} "
            f"len={entry.get('length')} {entry.get('encoding')} \"{value}\""
        )
    truncated = bool(report.get("strings_truncated", False))
    suffix = " (list truncated)" if truncated else ""
    print(f"\n{len(report.get('strings', []))} strings shown{suffix}\n")


def _print_call_tree(report: dict, selector: str) -> int:
    """Print an outgoing call tree for a function chosen by name or index."""
    graph = report.get("call_graph") or {}
    nodes = {int(n.get("index", -1)): n for n in graph.get("nodes", [])}
    edges_by_src: dict[int, list] = {}
    for edge in graph.get("edges", []):
        edges_by_src.setdefault(int(edge.get("from", -1)), []).append(edge)

    target = None
    if selector.isdigit():
        idx = int(selector)
        if idx in nodes:
            target = idx
    if target is None:
        for node in nodes.values():
            if str(node.get("name", "")) == selector:
                target = int(node["index"])
                break
    if target is None:
        print(f"error: no function matches '{selector}'", file=sys.stderr)
        return 1

    def label(idx: int) -> str:
        node = nodes.get(idx)
        if node is None:
            return f"func[{idx}]"
        name = str(node.get("name", ""))
        suffix = f" <{name}>" if name else ""
        tags = []
        if node.get("imported"):
            tags.append("import")
        if node.get("exported"):
            tags.append("export")
        tag_str = f" [{','.join(tags)}]" if tags else ""
        return f"func[{idx}]{suffix}{tag_str}"

    print(f"\nCall tree for {label(target)}:\n")
    # Markers are deterministic regardless of traversal order: a node on the
    # current path is "(recursion)", a node already expanded elsewhere is
    # "(seen)", and deeper subtrees past the cap are "...".
    expanded = {target}

    def walk(idx: int, depth: int, path: set) -> None:
        indent = "  " * (depth + 1)
        for edge in edges_by_src.get(idx, []):
            dst = int(edge.get("to", -1))
            offset = edge.get("offset")
            offset_str = f" @0x{offset:x}" if isinstance(offset, int) else ""
            edge_str = f"({edge.get('kind')}{offset_str})"
            if dst in path:
                marker = " (recursion)"
            elif dst in expanded:
                marker = " (seen)"
            elif depth >= _MAX_CALL_TREE_DEPTH:
                marker = " ..."
            else:
                marker = ""
            print(f"{indent}-> {label(dst)} {edge_str}{marker}")
            if not marker:
                expanded.add(dst)
                path.add(dst)
                walk(dst, depth + 1, path)
                path.discard(dst)

    walk(target, 0, {target})
    print()
    return 0


def _print_component_text(report: dict, mode: str) -> None:
    """Text output modes for component-model binaries."""
    component = report.get("component", {})
    if mode == "headers":
        print("\nComponent sections:\n")
        print(f"  {'id':>3} {'name':<16} {'size':>6}  {'offset'}")
        print(f"  {'-' * 3} {'-' * 16} {'-' * 6}  {'-' * 8}")
        for sec in report.get("sections", []):
            print(
                f"  {sec.get('id', 0):3d} {str(sec.get('name', '?')):<16} "
                f"{int(sec.get('size', 0)):6d}  {int(sec.get('offset', 0)):08x}"
            )
        return

    print("\nComponent Details:\n")
    print(
        f" component version: {component.get('component_version')} "
        f"layer: {component.get('layer_version')}"
    )
    print(f" core modules: {component.get('core_module_count', 0)}")
    if component.get("interfaces"):
        print(" interfaces:")
        for iface in component["interfaces"]:
            print(f"  - {iface}")
    if component.get("imports"):
        print(" imports:")
        for imp in component["imports"]:
            type_str = (
                f" type={imp['type_index']}" if "type_index" in imp else ""
            )
            print(f"  - {imp.get('kind', '?')}{type_str} <\"{imp.get('name', '')}\">")
    if component.get("exports"):
        print(" exports:")
        for exp in component["exports"]:
            print(
                f"  - {exp.get('kind', '?')}[{exp.get('index', '?')}] "
                f"-> \"{exp.get('name', '')}\""
            )
    canon = component.get("canonical_options", {})
    if canon.get("options"):
        opts = ", ".join(sorted(set(canon["options"])))
        print(
            f" canon: lift={canon.get('lift_count', 0)} "
            f"lower={canon.get('lower_count', 0)} options: {opts}"
        )
    for module_index, module in enumerate(component.get("core_modules", [])):
        print(
            f"\n core module[{module_index}]: version={module.get('module_version')} "
            f"functions={module.get('function_count', 0)} "
            f"imports={len(module.get('imports', []))} "
            f"exports={len(module.get('exports', []))}"
        )
    if mode == "disassemble":
        for module_index, module in enumerate(component.get("core_modules", [])):
            print(f"\nCode Disassembly (core module[{module_index}]):\n")
            for fn in module.get("functions", []):
                name = str(fn.get("name", ""))
                name_str = f" <{name}>" if name else ""
                print(f"func[{fn.get('index')}]{name_str}:")
                for ins in fn.get("instructions", []):
                    imm = " ".join(str(v) for v in ins.get("immediates", []))
                    offset = ins.get("offset")
                    offset_str = f"{offset:06x}" if isinstance(offset, int) else "      "
                    print(f" {offset_str}: | {ins.get('opcode', '?')} {imm}".rstrip())
                print()


def main() -> None:
    """Parse CLI args and run the wasm objdump pipeline."""
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
        "--strings",
        action="store_true",
        help="Extract printable strings from data segments with provenance",
    )
    parser.add_argument(
        "--strings-min-len",
        type=int,
        default=5,
        metavar="N",
        help="Minimum string length for --strings/--json (default: 5)",
    )
    parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Skip string extraction in --json reports",
    )
    parser.add_argument(
        "--no-call-graph",
        action="store_true",
        help="Skip call graph construction in --json reports",
    )
    parser.add_argument(
        "--calls",
        metavar="FUNC",
        help="Print an outgoing call tree for a function (name or index)",
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
    if args.no_call_graph and args.calls:
        parser.error("--calls requires the call graph; do not combine with --no-call-graph")

    options = ObjdumpOptions()
    options.filename = args.file

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    is_component = detect_component(data) is not None
    # The min-length must reach extraction (not just output filtering) or
    # values below the extraction default could never surface.
    report_kwargs = {
        "strings_min_len": args.strings_min_len,
        "include_strings": not args.no_strings,
        "include_call_graph": not args.no_call_graph,
    }

    if args.json or args.json_out:
        report = parse_wasm_bytes(data, filename=args.file, **report_kwargs)
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

    if args.strings or args.calls or is_component:
        report = parse_wasm_bytes(data, filename=args.file, **report_kwargs)

    if args.strings:
        _print_strings_from_report(report)
        return

    if args.calls:
        rc = _print_call_tree(report, args.calls)
        if rc:
            sys.exit(rc)
        return

    if is_component:
        if args.headers:
            _print_component_text(report, "headers")
        elif args.disassemble:
            _print_component_text(report, "disassemble")
        else:
            _print_component_text(report, "details")
        return

    # Pass 1: Prepass – collect names, types, section metadata into state.
    state = ObjdumpState()
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
