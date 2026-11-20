import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .api import parse_wasm_bytes
from .component import detect_component
from .models import ObjdumpMode, ObjdumpOptions, ObjdumpState, SECTION_NAMES
from .parser import BinaryReader
from .visitor import (
    BinaryReaderObjdumpDetails,
    BinaryReaderObjdumpDisassemble,
    BinaryReaderObjdumpHeaders,
    BinaryReaderObjdumpPrepass,
    BinaryReaderObjdumpRaw,
    SectionFilter,
)

_MAX_CALL_TREE_DEPTH = 4


def _print_strings_from_report(report: dict) -> None:
    """Print extracted strings with segment and linear-memory provenance.

    Length filtering already happened during extraction (strings_min_len is
    threaded to it), so every entry here is printable as-is.
    """
    print("\nStrings:\n")
    for entry in report.get("strings", []):
        core_mod = entry.get("core_module")
        core_str = f" core[{core_mod}]" if isinstance(core_mod, int) else ""
        value = str(entry.get("value", ""))
        source = entry.get("source")
        if source:
            # Custom-section strings (e.g. .debug_str) have no linear-memory
            # provenance; the section label is the provenance.
            print(
                f" {source}{core_str} "
                f"+0x{int(entry.get('byte_offset', 0)):x} "
                f"len={entry.get('length')} {entry.get('encoding')} \"{value}\""
            )
            continue
        mem = entry.get("memory_offset")
        mem_str = f"0x{mem:08x}" if isinstance(mem, int) else "-"
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


def _resolve_section(value: str) -> tuple[set[int], set[str]]:
    """Resolve a --section selector to (canonical ids, custom names).

    Raises ValueError for a numeric id outside the known 0-13 range.
    """
    if value.isdigit():
        section_id = int(value)
        if 0 <= section_id <= 13:
            return {section_id}, set()
        raise ValueError(
            f"section id {section_id} is not a known wasm section id (0-13)"
        )
    name_to_id = {name.lower(): sid for sid, name in SECTION_NAMES.items()}
    if value.lower() in name_to_id:
        return {name_to_id[value.lower()]}, set()
    # Not a canonical name: treat it as a custom section name match.
    return set(), {value}


def _collect_input_files(args: argparse.Namespace) -> list[str]:
    files = list(args.file)
    if args.recursive:
        root = Path(args.recursive)
        if not root.is_dir():
            # Errors here are usage-shaped; main() reports and exits 2.
            raise NotADirectoryError(args.recursive)
        files.extend(sorted(str(p) for p in root.rglob("*.wasm")))
    return files


def _run_text_mode(path: str, args: argparse.Namespace, options: ObjdumpOptions) -> None:
    """Run a text output mode for one input file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(1)

    is_component = detect_component(data) is not None
    report_kwargs = {
        "strings_min_len": args.strings_min_len,
        "include_strings": not args.no_strings,
        "include_call_graph": not args.no_call_graph,
        "max_instructions_per_function": args.max_instructions_per_function,
        "instruction_budget": args.instruction_budget,
        "include_instructions": not args.no_instructions,
        "include_demangled": not args.no_demangle,
        "include_features": not args.no_features,
        "include_cfg": args.cfg,
    }

    if args.strings or args.calls or is_component or args.print_wat or args.wat_out:
        report = parse_wasm_bytes(data, filename=path, **report_kwargs)

    if args.print_wat or args.wat_out:
        from .wat import emit_wat

        wat_text = emit_wat(report, source=data)
        if args.print_wat:
            print(wat_text, end="")
        if args.wat_out:
            try:
                with open(args.wat_out, "w", encoding="utf-8") as out_file:
                    out_file.write(wat_text)
            except Exception as e:
                print(f"Error writing {args.wat_out}: {e}", file=sys.stderr)
                sys.exit(1)
        if not (args.strings or args.calls):
            return

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
        elif args.raw:
            _print_component_raw(report, path)
        elif args.disassemble:
            _print_component_text(report, "disassemble")
        else:
            _print_component_text(report, "details")
        return

    # Pass 1: Prepass - collect names, types, section metadata into state.
    state = ObjdumpState()
    options.mode = ObjdumpMode.PREPASS
    options.filename = path
    prepass_reader = BinaryReaderObjdumpPrepass(data, options, state)
    BinaryReader(data, prepass_reader).read_module()

    # Pass 2: Selected output mode.
    if args.headers:
        options.mode = ObjdumpMode.HEADERS
        headers_reader = BinaryReaderObjdumpHeaders(data, options, state)
        BinaryReader(data, headers_reader).read_module()
    elif args.raw:
        options.mode = ObjdumpMode.RAW_DATA
        _run_raw_mode(data, args, options, state)
    elif args.disassemble:
        options.mode = ObjdumpMode.DISASSEMBLE
        dis_reader = BinaryReaderObjdumpDisassemble(data, options, state)
        if args.section:
            wanted_ids, wanted_custom = _resolve_section(args.section)
            dis_reader = SectionFilter(dis_reader, wanted_ids, wanted_custom)
        BinaryReader(data, dis_reader).read_module()
    elif args.details:
        options.mode = ObjdumpMode.DETAILS
        details_reader = BinaryReaderObjdumpDetails(data, options, state)
        if args.section:
            wanted_ids, wanted_custom = _resolve_section(args.section)
            details_reader = SectionFilter(details_reader, wanted_ids, wanted_custom)
        BinaryReader(data, details_reader).read_module()
    else:
        # Default: show details
        options.mode = ObjdumpMode.DETAILS
        details_reader = BinaryReaderObjdumpDetails(data, options, state)
        if args.section:
            wanted_ids, wanted_custom = _resolve_section(args.section)
            details_reader = SectionFilter(details_reader, wanted_ids, wanted_custom)
        BinaryReader(data, details_reader).read_module()


def _run_raw_mode(
    data: bytes, args: argparse.Namespace, options: ObjdumpOptions, state: ObjdumpState
) -> None:
    """Hexdump mode: --section picks the section; without it, the first
    non-empty data-bearing section is dumped and announced."""
    if not args.section:
        args.section = _default_raw_section(data)
        if args.section is None:
            print("\nNo non-empty section found to dump.\n")
            return
        print(f"(no --section given; dumping the {args.section} section)")
    wanted_ids, wanted_custom = _resolve_section(args.section)
    raw_reader = SectionFilter(
        BinaryReaderObjdumpRaw(data, options, state), wanted_ids, wanted_custom
    )
    BinaryReader(data, raw_reader).read_module()


def _default_raw_section(data: bytes) -> str | None:
    """First non-empty section: data, then any canonical, then any custom."""
    report = parse_wasm_bytes(data, include_strings=False, include_call_graph=False)
    sections = report.get("sections", [])
    by_id = {}
    for sec in sections:
        by_id.setdefault(sec.get("id"), sec)
    data_sec = by_id.get(11)  # 11 = Data in the canonical section order
    if data_sec and data_sec.get("size", 0) > 0:
        return "data"
    for sec in sections:
        if sec.get("size", 0) > 0:
            if sec.get("id") == 0:
                return f'"{sec.get("name", "")}"'
            return str(SECTION_NAMES.get(sec.get("id"), "")).lower()
    return None


def _print_component_raw(report: dict, path: str) -> None:
    """Hexdump the component's nested core modules' section tables is not
    wired through the two-pass pipeline; fall back to details."""
    print("(--raw for components dumps each nested core module's sections)\n")
    _print_component_text(report, "details")


def main() -> None:
    """Parse CLI args and run the wasm objdump pipeline."""
    parser = argparse.ArgumentParser(
        description="A WebAssembly objdump tool for inspecting .wasm binaries.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "file",
        nargs="*",
        help="WebAssembly binary file (.wasm); repeat for multiple files",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        metavar="DIR",
        help="Also parse every .wasm file under DIR",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--headers", action="store_true", help="Print section headers")
    parser.add_argument(
        "-x", "--details", action="store_true", help="Print section details"
    )
    parser.add_argument(
        "-d", "--disassemble", action="store_true", help="Disassemble function bodies"
    )
    parser.add_argument(
        "-s",
        "--raw",
        action="store_true",
        help="Hexdump section payloads (objdump -s style)",
    )
    parser.add_argument(
        "--section",
        metavar="NAME",
        help="Limit -x/-d/--raw output to one section (numeric id 0-13, "
        "canonical name like code or data, or a custom section name)",
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
        "--cfg",
        action="store_true",
        help="Attach per-function basic-block CFGs to --json reports",
    )
    parser.add_argument(
        "--print-wat",
        action="store_true",
        help="Print WAT text for the module (flat style)",
    )
    parser.add_argument(
        "--wat-out",
        metavar="PATH",
        help="Write WAT text to PATH",
    )
    parser.add_argument(
        "--carve",
        action="store_true",
        help="Scan the input for embedded wasm blobs (any file type) and "
        "report their spans and quick summaries",
    )
    parser.add_argument(
        "--carve-full",
        action="store_true",
        help="With --carve, emit the full report for every blob",
    )
    parser.add_argument(
        "--carve-decode",
        action="store_true",
        help="With --carve, also decode long base64 runs and rescan them",
    )
    parser.add_argument(
        "--extract",
        metavar="DIR",
        help="With --carve, write each bounded blob to DIR/blob-<offset>.wasm",
    )
    parser.add_argument(
        "--no-features",
        action="store_true",
        help="Skip the analysis.features opcode statistics block in --json reports",
    )
    parser.add_argument(
        "--no-demangle",
        action="store_true",
        help="Skip Rust/C++ demangling of name-section symbols",
    )
    parser.add_argument(
        "--no-instructions",
        action="store_true",
        help="Omit per-function instruction streams in --json reports "
        "(analysis and counts still describe the full decode)",
    )
    parser.add_argument(
        "--max-instructions-per-function",
        type=int,
        default=None,
        metavar="N",
        help="Cap each function's emitted instruction stream at N entries",
    )
    parser.add_argument(
        "--instruction-budget",
        type=int,
        default=None,
        metavar="N",
        help="Share a total instruction budget of N across functions "
        "(max-min fair; per core module for components)",
    )
    parser.add_argument(
        "--calls",
        metavar="FUNC",
        help="Print an outgoing call tree for a function (name or index)",
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Write a minified JSON report to PATH (JSON Lines for multiple inputs)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a minified JSON report to stdout (JSON Lines for multiple inputs)",
    )
    parser.add_argument(
        "--analysis-only",
        action="store_true",
        help="With --json and/or --json-out, emit only the analysis object",
    )

    args = parser.parse_args()

    if args.version:
        print(f"wasm-tools {__version__}")
        return

    if args.analysis_only and not (args.json or args.json_out):
        parser.error("--analysis-only requires --json and/or --json-out")
    if args.no_call_graph and args.calls:
        parser.error("--calls requires the call graph; do not combine with --no-call-graph")
    if args.instruction_budget is not None and args.instruction_budget < 0:
        parser.error("--instruction-budget must be non-negative")
    if (
        args.max_instructions_per_function is not None
        and args.max_instructions_per_function < 0
    ):
        parser.error("--max-instructions-per-function must be non-negative")
    if args.section:
        try:
            _resolve_section(args.section)
        except ValueError as exc:
            parser.error(str(exc))
    if args.recursive:
        root = Path(args.recursive)
        if not root.is_dir():
            parser.error(f"--recursive path is not a directory: {args.recursive}")

    try:
        files = _collect_input_files(args)
    except NotADirectoryError as exc:
        parser.error(f"--recursive path is not a directory: {exc}")
    if not files:
        parser.error("no input files")

    options = ObjdumpOptions()

    # JSON modes: one report per input; multiple inputs produce JSON Lines
    # on stdout (or a JSON array written to --json-out).
    if args.json or args.json_out:
        outputs: list[str] = []
        for path in files:
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception as e:
                print(f"Error reading {path}: {e}", file=sys.stderr)
                sys.exit(1)
            report = parse_wasm_bytes(data, filename=path, **{
                "strings_min_len": args.strings_min_len,
                "include_strings": not args.no_strings,
                "include_call_graph": not args.no_call_graph,
                "max_instructions_per_function": args.max_instructions_per_function,
                "instruction_budget": args.instruction_budget,
                "include_instructions": not args.no_instructions,
                "include_demangled": not args.no_demangle,
                "include_features": not args.no_features,
                "include_cfg": args.cfg,
            })
            output = report["analysis"] if args.analysis_only else report
            outputs.append(json.dumps(output, ensure_ascii=False, separators=(",", ":")))
        if len(outputs) == 1:
            payload = outputs[0]
        elif args.json_out and not args.json:
            payload = json.dumps([json.loads(line) for line in outputs], ensure_ascii=False, separators=(",", ":"))
        else:
            payload = "\n".join(outputs)
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

    if args.carve:
        for index, path in enumerate(files):
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except Exception as e:
                print(f"Error reading {path}: {e}", file=sys.stderr)
                sys.exit(1)
            from .carve import carve_wasm_bytes

            carve_report = carve_wasm_bytes(
                data, decode_base64=args.carve_decode
            )
            if args.carve_full:
                from .api import parse_wasm_bytes as _parse

                for record in carve_report["blobs"]:
                    size = record.get("size")
                    if size is None:
                        record["report"] = None
                        continue
                    blob_bytes = data[
                        record["offset"] : record["offset"] + size
                    ]
                    record["report"] = _parse(
                        blob_bytes,
                        filename=f"{path}@{record['offset']}",
                        include_strings=False,
                        include_call_graph=False,
                    )
            carve_report["file"] = path
            if args.extract:
                extract_dir = Path(args.extract)
                extract_dir.mkdir(parents=True, exist_ok=True)
                for record in carve_report["blobs"]:
                    size = record.get("size")
                    if size is None:
                        continue
                    blob_bytes = data[
                        record["offset"] : record["offset"] + size
                    ]
                    out_path = extract_dir / f"blob-{record['offset']:08x}.wasm"
                    out_path.write_bytes(blob_bytes)
                    record["extracted_to"] = str(out_path)
            print(json.dumps(carve_report, ensure_ascii=False, separators=(",", ":")))
        return

    multi = len(files) > 1
    for index, path in enumerate(files):
        if multi:
            if index:
                print()
            print(f"== {path} ==")
        _run_text_mode(path, args, options)


if __name__ == "__main__":
    main()
